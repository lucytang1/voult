use std::{
    fs,
    io,
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuId, MenuItem},
};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    window::WindowId,
};

const START_ITEM_ID: &str = "start_item";
const STATUS_ITEM_ID: &str = "status_item";
const QUIT_ITEM_ID: &str = "quit_item";

/// Address the server is expected to listen on. The launcher only needs to
/// know "is something listening" — a raw TCP connect is enough for that and
/// keeps the launcher decoupled from the API itself.
const SERVER_ADDR: &str = "127.0.0.1:8080";
/// How often the menu/process state is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// How often the TCP health probe runs (throttled separately from the poll).
const HEALTH_PROBE_INTERVAL: Duration = Duration::from_millis(2000);
/// Connect timeout for the health probe; must be short so a dead port doesn't
/// stall the UI event loop.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Lifecycle of the server as shown in the tray. `child` ownership lives on
/// `Launcher` (not in this enum) because we need to keep the handle around for
/// stopping regardless of which state we're displaying.
#[derive(Debug, Clone, PartialEq)]
enum ServerState {
    /// Nothing running and nothing listening on the port.
    Stopped,
    /// We spawned the process but it hasn't bound the port yet (cargo may
    /// still be compiling, or the server hasn't finished binding).
    Starting,
    /// Our child process is alive AND something is listening on the port.
    Running { pid: u32 },
    /// Our child exited with a non-zero code or a signal. Persists until the
    /// user starts the server again. No notifications are sent — the tray line
    /// is the sole signal.
    Crashed { reason: String },
    /// Something is listening on the port that we did not spawn (e.g. the user
    /// ran `cargo run` manually). Start is disabled in this state.
    RunningElsewhere { pid: Option<u32> },
}

enum UserEvent {
    MenuEvent(MenuEvent),
}

struct Launcher {
    tray_icon: Option<TrayIcon>,
    start_stop_item: Option<MenuItem>,
    status_item: Option<MenuItem>,
    start_stop_id: Option<MenuId>,
    state: ServerState,
    /// Handle to the process we spawned (`cargo run`). Kept separate from
    /// `state` so Stop always works while we own the child.
    child: Option<Child>,
    next_poll: Instant,
    last_health_probe: Instant,
    /// Whether we have already auto-opened the browser this launcher session.
    /// Reset on stop so next start re-opens.
    has_auto_opened: bool,
}

impl Launcher {
    fn new() -> Self {
        Self {
            tray_icon: None,
            start_stop_item: None,
            status_item: None,
            start_stop_id: None,
            state: ServerState::Stopped,
            child: None,
            next_poll: Instant::now(),
            last_health_probe: Instant::now(),
            has_auto_opened: false,
        }
    }

    // ---------------------------------------------------------------- state

    fn is_port_open(&self) -> bool {
        TcpStream::connect_timeout(
            &SERVER_ADDR.parse().expect("SERVER_ADDR is a valid socket addr"),
            HEALTH_PROBE_TIMEOUT,
        )
        .is_ok()
    }

    /// Best-effort lookup of whichever PID is holding the server port, used to
    /// label "Running elsewhere". macOS-only via lsof; failure just means no
    /// pid is displayed.
    fn foreign_pid() -> Option<u32> {
        let output = Command::new("lsof")
            .args(["-ti", "tcp:8080"])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let first = String::from_utf8_lossy(&output.stdout);
        first.lines().next()?.trim().parse().ok()
    }

    /// Human-readable description of an exit status for the crash line.
    fn describe_exit(status: ExitStatus) -> String {
        if let Some(code) = status.code() {
            format!("exit {code}")
        } else if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
            format!("killed by signal {signal}")
        } else {
            format!("{status}")
        }
    }

    /// Reconcile our view of the world with reality:
    /// 1. If we own a child, check whether it exited (crash detection).
    /// 2. Throttled health probe decides Starting vs Running, and detects a
    ///    foreign server when we own nothing.
    fn refresh_state(&mut self) {
        // --- process probe -------------------------------------------------
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child = None;
                    if status.success() {
                        // Clean exit (e.g. server shut down gracefully on its
                        // own) — not a crash, but re-probe the port in case a
                        // foreign instance took over.
                        self.state = ServerState::Stopped;
                    } else {
                        let reason = Self::describe_exit(status);
                        eprintln!("Server terminated unexpectedly ({reason})");
                        self.state = ServerState::Crashed { reason };
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("Could not inspect server process: {error}");
                    self.child = None;
                    self.state = ServerState::Stopped;
                }
            }
        }

        // --- health probe (throttled) --------------------------------------
        let probe_due = self.last_health_probe.elapsed() >= HEALTH_PROBE_INTERVAL;
        if !probe_due {
            return;
        }
        self.last_health_probe = Instant::now();
        let port_open = self.is_port_open();

        let mut transitioned_to_running = false;
        match (&self.state, port_open) {
            // Process alive, port now bound → genuinely serving.
            (ServerState::Starting, true) => {
                let pid = self.child.as_ref().map(|c| c.id());
                self.state = ServerState::Running {
                    pid: pid.unwrap_or(0),
                };
                transitioned_to_running = true;
            }
            // Port closed again after being open (server restarting?) — drop
            // back to Starting while our child is still alive.
            (ServerState::Running { .. }, false) => {
                if self.child.is_some() {
                    self.state = ServerState::Starting;
                } else {
                    self.state = ServerState::Stopped;
                }
            }
            // Nothing of ours, but the port is busy → someone else's server.
            (_, true) if self.child.is_none() => {
                let pid = Self::foreign_pid();
                info_log(&format!(
                    "Detected server on {SERVER_ADDR} not started by launcher{}",
                    pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
                ));
                self.state = ServerState::RunningElsewhere { pid };
            }
            _ => {}
        }

        // Auto-open browser once when server becomes reachable
        if transitioned_to_running && !self.has_auto_opened {
            self.has_auto_opened = true;
            Self::open_browser();
        }
    }

    /// Best-effort open of http://localhost:8080 in the default browser.
    fn open_browser() {
        let url = "http://localhost:8080";
        info_log(&format!("Opening browser at {url}"));
        // `open` crate handles macOS `open` correctly; fallback to Command.
        if open::that(url).is_err() {
            let _ = Command::new("open").arg(url).stdin(Stdio::null()).spawn();
        }
    }

    /// Resolve the server binary path for both bundled (.app) and dev (`cargo run`) modes.
    fn resolve_server_binary() -> Option<PathBuf> {
        // 1. Bundled: sibling in Contents/MacOS (Voult launcher next to voult-server)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join("voult-server");
                if sibling.exists() {
                    return Some(sibling);
                }
                let resources_alt = dir.join("../Resources/voult-server");
                if resources_alt.exists() {
                    return Some(resources_alt);
                }
                // When running via `cargo run` in dev, exe is target/debug/launcher,
                // check for target/debug/pass-manager or apps/server/target
                let dev_bin = dir.join("pass-manager");
                if dev_bin.exists() {
                    return Some(dev_bin);
                }
            }
        }
        // 2. Dev fallback: will use `cargo run`
        None
    }

    fn server_directory() -> io::Result<PathBuf> {
        let launcher_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        launcher_directory
            .parent()
            .map(|root| root.join("apps/server"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "repository root not found"))
    }

    fn log_file_path() -> Option<PathBuf> {
        // ~/Library/Logs/Voult/server.log
        let home = std::env::var("HOME").ok()?;
        let dir = PathBuf::from(home).join("Library/Logs/Voult");
        let _ = fs::create_dir_all(&dir);
        Some(dir.join("server.log"))
    }

    fn start_server(&mut self) {
        if matches!(self.state, ServerState::RunningElsewhere { .. }) || self.child.is_some() {
            return;
        }

        // Prefer direct binary if bundled; fallback to `cargo run` for dev.
        if let Some(bin) = Self::resolve_server_binary() {
            info_log(&format!("Starting bundled server at {}", bin.display()));
            // Prepare log file
            let log_path = Self::log_file_path();
            let (stdout, stderr) = if let Some(ref p) = log_path {
                match fs::OpenOptions::new().create(true).append(true).open(p) {
                    Ok(f) => {
                        let s1 = f.try_clone().ok();
                        let s2 = f.try_clone().ok();
                        let to_stdio = |opt: Option<fs::File>| {
                            opt.map(|file| Stdio::from(file)).unwrap_or_else(Stdio::null)
                        };
                        // We need two handles; if clone fails, inherit for visibility
                        if s1.is_some() && s2.is_some() {
                            (to_stdio(s1), to_stdio(s2))
                        } else {
                            (Stdio::inherit(), Stdio::inherit())
                        }
                    }
                    Err(e) => {
                        eprintln!("Could not open log file {}: {e}", p.display());
                        (Stdio::inherit(), Stdio::inherit())
                    }
                }
            } else {
                (Stdio::inherit(), Stdio::inherit())
            };

            let result = Command::new(&bin)
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn();

            match result {
                Ok(server) => {
                    info_log(&format!("Started server process (pid {})", server.id()));
                    self.child = Some(server);
                    self.state = ServerState::Starting;
                    self.last_health_probe =
                        Instant::now() - HEALTH_PROBE_INTERVAL + Duration::from_millis(250);
                }
                Err(error) => {
                    eprintln!("Could not start server binary {}: {error}", bin.display());
                    self.state = ServerState::Crashed {
                        reason: format!("failed to spawn: {error}"),
                    };
                }
            }
            return;
        }

        // Dev fallback: cargo run
        let server_directory = match Self::server_directory() {
            Ok(directory) => directory,
            Err(error) => {
                eprintln!("Could not locate server directory: {error}");
                return;
            }
        };

        // Server output is inherited so it appears in the terminal the
        // launcher was started from, same as before.
        let result = Command::new("cargo")
            .args(["run", "--bin", "pass-manager"])
            .current_dir(server_directory)
            .stdin(Stdio::null())
            .spawn();

        match result {
            Ok(server) => {
                info_log(&format!(
                    "Started server process (pid {})",
                    server.id()
                ));
                self.child = Some(server);
                self.state = ServerState::Starting;
                // Probe promptly rather than waiting a full interval so the
                // transition out of Starting feels responsive once compiled.
                self.last_health_probe =
                    Instant::now() - HEALTH_PROBE_INTERVAL + Duration::from_millis(250);
            }
            Err(error) => {
                eprintln!("Could not start server: {error}");
                self.state = ServerState::Crashed {
                    reason: format!("failed to spawn: {error}"),
                };
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(mut server) = self.child.take() {
            if let Err(error) = server.kill() {
                eprintln!("Could not stop server: {error}");
            }
            let _ = server.wait();
        }
        self.state = ServerState::Stopped;
        self.has_auto_opened = false;
        self.update_menu();
    }

    // ----------------------------------------------------------------- menu

    fn update_menu(&mut self) {
        // Start/Stop toggle text + availability driven entirely by state.
        if let Some(item) = &self.start_stop_item {
            match &self.state {
                ServerState::Starting | ServerState::Running { .. } => {
                    item.set_text("Stop Server");
                    item.set_enabled(true);
                }
                ServerState::Stopped | ServerState::Crashed { .. } => {
                    item.set_text("Start Server");
                    item.set_enabled(true);
                }
                ServerState::RunningElsewhere { .. } => {
                    item.set_text("Server Already Running");
                    item.set_enabled(false);
                }
            }
        }

        if let Some(item) = &self.status_item {
            item.set_text(match &self.state {
                ServerState::Stopped => "Status: Not running".to_string(),
                ServerState::Starting => "Status: Starting…".to_string(),
                ServerState::Running { pid } => {
                    format!("Status: Running · pid {pid} · {SERVER_ADDR}")
                }
                ServerState::Crashed { reason } => format!("Status: Crashed ({reason})"),
                ServerState::RunningElsewhere { pid } => match pid {
                    Some(pid) => format!("Status: Running elsewhere · pid {pid}"),
                    None => "Status: Running elsewhere".to_string(),
                },
            });
        }
    }

    fn build_tray(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let start_stop_item = MenuItem::with_id(START_ITEM_ID, "Start Server", true, None);
        let status_item =
            MenuItem::with_id(STATUS_ITEM_ID, "Status: Not running", false, None);
        let quit_item = MenuItem::with_id(QUIT_ITEM_ID, "Quit", true, None);
        let menu = Menu::with_items(&[&start_stop_item, &status_item, &quit_item])?;

        self.start_stop_id = Some(start_stop_item.id().clone());
        self.start_stop_item = Some(start_stop_item);
        self.status_item = Some(status_item);
        self.tray_icon = Some(
            TrayIconBuilder::new()
                .with_title("Voult")
                .with_tooltip("Voult server")
                .with_menu(Box::new(menu))
                .build()?,
        );
        self.update_menu();
        Ok(())
    }
}

fn info_log(message: &str) {
    println!("[launcher] {message}");
}

impl ApplicationHandler<UserEvent> for Launcher {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.tray_icon.is_some() {
            return;
        }

        if let Err(error) = self.build_tray() {
            eprintln!("Could not create Voult menu bar item: {error}");
            event_loop.exit();
            return;
        }

        // Auto-start the server on launch so double-clicking the app
        // immediately makes http://localhost:8080 usable. If something is
        // already listening on :8080 we detect it via the health probe and
        // show "Running elsewhere" instead.
        if self.child.is_none() && !self.is_port_open() {
            self.start_server();
        } else if self.is_port_open() {
            // Refresh immediately so "Running elsewhere" shows without 2s delay
            self.last_health_probe = Instant::now() - HEALTH_PROBE_INTERVAL;
            self.refresh_state();
            self.update_menu();
            // If we detected a foreign server, still auto-open browser
            if matches!(self.state, ServerState::RunningElsewhere { .. }) && !self.has_auto_opened {
                self.has_auto_opened = true;
                Self::open_browser();
            }
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(event) => match event.id().as_ref() {
                QUIT_ITEM_ID => {
                    _event_loop.exit();
                }
                START_ITEM_ID => match &self.state {
                    ServerState::Starting | ServerState::Running { .. } => self.stop_server(),
                    ServerState::Stopped | ServerState::Crashed { .. } => {
                        // Starting again clears any previous crash line.
                        self.start_server();
                    }
                    ServerState::RunningElsewhere { .. } => {}
                },
                _ => {}
            },
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        let now = Instant::now();
        if now >= self.next_poll {
            self.refresh_state();
            self.update_menu();
            self.next_poll = now + POLL_INTERVAL;
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(self.next_poll));
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.stop_server();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();

    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    let mut launcher = Launcher::new();
    event_loop.run_app(&mut launcher)?;
    Ok(())
}
