use std::{
    fs, io,
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuId, MenuItem},
};

// Linux drives the launcher from a GTK main loop (see `main` at the bottom):
// tray-icon's Linux backend is libappindicator, which owns GTK widgets, and
// GTK objects must only be touched from the thread running `gtk::main()`.
// winit is used on macOS (and would be on Windows) because there the tray is a
// native menu-bar item and winit's own event loop is sufficient.
#[cfg(not(target_os = "linux"))]
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    window::WindowId,
};

const START_ITEM_ID: &str = "start_item";
const STATUS_ITEM_ID: &str = "status_item";
const QUIT_ITEM_ID: &str = "quit_item";

mod config;
use config::Environment;

/// Hardcoded contexts for the launcher's root-level logging.
const LAUNCHER_LOG: logger::LauncherLogger =
    logger::Logger::create(logger::LauncherContext::Launcher);
const PROCESS_LOG: logger::LauncherLogger =
    logger::Logger::create(logger::LauncherContext::Process);
const TRAY_LOG: logger::LauncherLogger = logger::Logger::create(logger::LauncherContext::Tray);

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

#[cfg(not(target_os = "linux"))]
enum UserEvent {
    MenuEvent(MenuEvent),
}

/// Extract the first `pid=NNN` value from `ss -p` output.
#[cfg(target_os = "linux")]
fn parse_pid_field(text: &str) -> Option<u32> {
    let start = text.find("pid=")? + "pid=".len();
    let digits: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
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
    /// Next winit poll deadline. The Linux build uses a GLib timeout instead,
    /// so this is only read on macOS.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
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
            &SERVER_ADDR
                .parse()
                .expect("SERVER_ADDR is a valid socket addr"),
            HEALTH_PROBE_TIMEOUT,
        )
        .is_ok()
    }

    /// Best-effort lookup of whichever PID is holding the server port, used to
    /// label "Running elsewhere". Failure just means no pid is displayed.
    #[cfg(target_os = "macos")]
    fn foreign_pid() -> Option<u32> {
        let output = Command::new("lsof")
            .args(["-ti", "tcp:8080"])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let first = String::from_utf8_lossy(&output.stdout);
        first.lines().next()?.trim().parse().ok()
    }

    /// Linux equivalent. `ss` (iproute2) is present on essentially every
    /// distro and, unlike lsof, does not need a separate install. Both tools
    /// can only see other users' PIDs as root, but the only process that
    /// matters here is the user's own leftover server.
    #[cfg(target_os = "linux")]
    fn foreign_pid() -> Option<u32> {
        // `ss -ltnpH 'sport = :8080'` prints e.g.
        //   LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("voult-server",pid=1234,fd=8))
        if let Ok(output) = Command::new("ss")
            .args(["-ltnpH", "sport = :8080"])
            .stdin(Stdio::null())
            .output()
        {
            if let Some(pid) = parse_pid_field(&String::from_utf8_lossy(&output.stdout)) {
                return Some(pid);
            }
        }

        // Fallback for minimal images without iproute2.
        let output = Command::new("lsof")
            .args(["-ti", "tcp:8080", "-sTCP:LISTEN"])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn foreign_pid() -> Option<u32> {
        None
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
                        PROCESS_LOG.error(
                            format_args!("Server terminated unexpectedly ({reason})"),
                            logger::Metadata::new(),
                        );
                        self.state = ServerState::Crashed { reason };
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    PROCESS_LOG.error(
                        format_args!("Could not inspect server process: {error}"),
                        logger::Metadata::new(),
                    );
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
                PROCESS_LOG.log(
                    format_args!(
                        "Detected server on {SERVER_ADDR} not started by launcher{}",
                        pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
                    ),
                    logger::Metadata::new(),
                );
                self.state = ServerState::RunningElsewhere { pid };
            }
            _ => {}
        }

        // Auto-open browser once when server becomes reachable (prod only).
        if transitioned_to_running && !self.has_auto_opened {
            self.has_auto_opened = true;
            if Environment::from_env().is_dev() {
                LAUNCHER_LOG.log(
                    "Dev mode (VOULT_ENV=development): auto-open disabled",
                    logger::Metadata::new(),
                );
            } else {
                Self::open_browser();
            }
        }
    }

    /// Best-effort open of http://localhost:8080 in the default browser.
    fn open_browser() {
        let url = "http://localhost:8080";
        LAUNCHER_LOG.log(
            format_args!("Opening browser at {url}"),
            logger::Metadata::new(),
        );
        #[cfg(target_os = "linux")]
        {
            // xdg-open can block until the browser detaches, and this runs on
            // the GTK main loop — a hung launcher there would freeze the tray.
            let _ = open::that_in_background(url);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // `open` crate dispatches to `open` (macOS) / the platform helper;
            // the explicit Command is only for environments where the crate's
            // helper process is unavailable.
            if open::that(url).is_err() {
                let _ = Command::new("open").arg(url).stdin(Stdio::null()).spawn();
            }
        }
    }

    /// Resolve the server binary path for bundled layouts and dev (`cargo run`).
    fn resolve_server_binary() -> Option<PathBuf> {
        // 1. Bundled: sibling of the launcher. On macOS that is
        // Contents/MacOS/voult-server; on Linux the installer puts both
        // binaries in ~/.local/lib/voult/ (or /opt/voult/bin).
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

    /// Where to append the spawned server's stdout/stderr.
    ///
    /// macOS keeps the existing `~/Library/Logs/Voult/server.log`. Linux
    /// follows the XDG base-directory spec: `$XDG_STATE_HOME/voult/server.log`
    /// (default `~/.local/state/voult/`), which is the conventional home for
    /// logs — `~/.local/share` would put them next to the database.
    fn log_file_path() -> Option<PathBuf> {
        let home = std::env::var_os("HOME").map(PathBuf::from)?;

        #[cfg(target_os = "macos")]
        let dir = home.join("Library/Logs/Voult");

        #[cfg(target_os = "linux")]
        let dir = {
            let state_home = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".local/state"));
            state_home.join("voult")
        };

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let dir = home.join(".voult").join("logs");

        let _ = fs::create_dir_all(&dir);
        Some(dir.join("server.log"))
    }

    fn start_server(&mut self) {
        if matches!(self.state, ServerState::RunningElsewhere { .. }) || self.child.is_some() {
            return;
        }

        // Prefer direct binary if bundled; fallback to `cargo run` for dev.
        if let Some(bin) = Self::resolve_server_binary() {
            PROCESS_LOG.log(
                format_args!("Starting bundled server at {}", bin.display()),
                logger::Metadata::new(),
            );
            // Prepare log file
            let log_path = Self::log_file_path();
            let (stdout, stderr) = if let Some(ref p) = log_path {
                match fs::OpenOptions::new().create(true).append(true).open(p) {
                    Ok(f) => {
                        let s1 = f.try_clone().ok();
                        let s2 = f.try_clone().ok();
                        let to_stdio = |opt: Option<fs::File>| {
                            opt.map(|file| Stdio::from(file))
                                .unwrap_or_else(Stdio::null)
                        };
                        // We need two handles; if clone fails, inherit for visibility
                        if s1.is_some() && s2.is_some() {
                            (to_stdio(s1), to_stdio(s2))
                        } else {
                            (Stdio::inherit(), Stdio::inherit())
                        }
                    }
                    Err(e) => {
                        LAUNCHER_LOG.warn(
                            format_args!("Could not open log file {}: {e}", p.display()),
                            logger::metadata! { "path" => p.display().to_string() },
                        );
                        (Stdio::inherit(), Stdio::inherit())
                    }
                }
            } else {
                (Stdio::inherit(), Stdio::inherit())
            };

            let mut cmd = Command::new(&bin);
            cmd.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
            // In dev, run the server with CWD = apps/server so a relative
            // DATABASE_URL resolves to apps/server/voult.db even when launcher
            // CWD != server.
            if Environment::from_env().is_dev() {
                if let Ok(dir) = Self::server_directory() {
                    if dir.exists() {
                        cmd.current_dir(dir);
                    }
                }
            }
            let result = cmd.spawn();

            match result {
                Ok(server) => {
                    PROCESS_LOG.log(
                        format_args!("Started server process (pid {})", server.id()),
                        logger::metadata! { "pid" => server.id() },
                    );
                    self.child = Some(server);
                    self.state = ServerState::Starting;
                    self.last_health_probe =
                        Instant::now() - HEALTH_PROBE_INTERVAL + Duration::from_millis(250);
                }
                Err(error) => {
                    PROCESS_LOG.error(
                        format_args!("Could not start server binary {}: {error}", bin.display()),
                        logger::metadata! { "path" => bin.display().to_string() },
                    );
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
                PROCESS_LOG.error(
                    format_args!("Could not locate server directory: {error}"),
                    logger::Metadata::new(),
                );
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
                PROCESS_LOG.log(
                    format_args!("Started server process (pid {})", server.id()),
                    logger::metadata! { "pid" => server.id() },
                );
                self.child = Some(server);
                self.state = ServerState::Starting;
                // Probe promptly rather than waiting a full interval so the
                // transition out of Starting feels responsive once compiled.
                self.last_health_probe =
                    Instant::now() - HEALTH_PROBE_INTERVAL + Duration::from_millis(250);
            }
            Err(error) => {
                PROCESS_LOG.error(
                    format_args!("Could not start server: {error}"),
                    logger::Metadata::new(),
                );
                self.state = ServerState::Crashed {
                    reason: format!("failed to spawn: {error}"),
                };
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(mut server) = self.child.take() {
            if let Err(error) = server.kill() {
                PROCESS_LOG.warn(
                    format_args!("Could not stop server: {error}"),
                    logger::metadata! { "pid" => server.id() },
                );
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
                    set_text_if_changed(item, "Stop Server");
                    set_enabled_if_changed(item, true);
                }
                ServerState::Stopped | ServerState::Crashed { .. } => {
                    set_text_if_changed(item, "Start Server");
                    set_enabled_if_changed(item, true);
                }
                ServerState::RunningElsewhere { .. } => {
                    set_text_if_changed(item, "Server Already Running");
                    set_enabled_if_changed(item, false);
                }
            }
        }

        if let Some(item) = &self.status_item {
            match &self.state {
                ServerState::Stopped => set_text_if_changed(item, "Status: Not running"),
                ServerState::Starting => set_text_if_changed(item, "Status: Starting…"),
                ServerState::Running { pid } => set_text_if_changed(
                    item,
                    &format!("Status: Running · pid {pid} · {SERVER_ADDR}"),
                ),
                ServerState::Crashed { reason } => {
                    set_text_if_changed(item, &format!("Status: Crashed ({reason})"))
                }
                ServerState::RunningElsewhere { pid } => match pid {
                    Some(pid) => {
                        set_text_if_changed(item, &format!("Status: Running elsewhere · pid {pid}"))
                    }
                    None => set_text_if_changed(item, "Status: Running elsewhere"),
                },
            }
        }
    }

    fn build_tray(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let start_stop_item = MenuItem::with_id(START_ITEM_ID, "Start Server", true, None);
        let status_item = MenuItem::with_id(STATUS_ITEM_ID, "Status: Not running", false, None);
        let quit_item = MenuItem::with_id(QUIT_ITEM_ID, "Quit", true, None);
        let menu = Menu::with_items(&[&start_stop_item, &status_item, &quit_item])?;

        self.start_stop_id = Some(start_stop_item.id().clone());
        self.start_stop_item = Some(start_stop_item);
        self.status_item = Some(status_item);

        // Menu-bar icon from the bundled asset. Embedded at compile time via
        // `include_bytes!` so it works both in dev (`cargo run`) and in the
        // bundled Voult.app (no runtime asset path to resolve).
        // `with_icon_as_template(true)` lets macOS tint the solid-black glyph
        // for light/dark menu bars, like a standard template image.
        let mut builder = TrayIconBuilder::new()
            .with_tooltip("Voult server")
            .with_menu(Box::new(menu));
        match Self::load_tray_icon() {
            Some(icon) => {
                builder = builder.with_icon(icon).with_icon_as_template(true);
            }
            None => {
                // Fallback to the old text label if the icon can't be decoded.
                builder = builder.with_title("Voult");
            }
        }

        self.tray_icon = Some(builder.build()?);
        self.update_menu();
        Ok(())
    }

    /// Decode `assets/voult.png` into a tray `Icon`.
    fn load_tray_icon() -> Option<Icon> {
        const ICON_BYTES: &[u8] = include_bytes!("../assets/voult.png");
        let image = image::load_from_memory(ICON_BYTES)
            .inspect_err(|error| {
                TRAY_LOG.warn(
                    format_args!("Could not decode tray icon: {error}"),
                    logger::Metadata::new(),
                );
            })
            .ok()?
            .into_rgba8();
        let (width, height) = image.dimensions();
        Icon::from_rgba(image.into_raw(), width, height)
            .inspect_err(|error| {
                TRAY_LOG.warn(
                    format_args!("Could not create tray icon: {error}"),
                    logger::Metadata::new(),
                );
            })
            .ok()
    }
}

impl Launcher {
    /// Build the tray and apply the launch policy (auto-start / auto-open).
    ///
    /// Returns `false` when the tray could not be created. The caller must then
    /// exit: without a tray there is no way to reach Start/Stop/Quit, and the
    /// macOS build has always treated that as fatal.
    fn initialize(&mut self) -> bool {
        if self.tray_icon.is_some() {
            return true;
        }

        if let Err(error) = self.build_tray() {
            TRAY_LOG.error(
                format_args!("Could not create Voult menu bar item: {error}"),
                logger::Metadata::new(),
            );
            #[cfg(target_os = "linux")]
            TRAY_LOG.error(
                "No system tray available. Install libayatana-appindicator3 and enable a \
                 StatusNotifier host (GNOME needs the AppIndicator extension), or run \
                 voult-server directly.",
                logger::Metadata::new(),
            );
            return false;
        }

        // Auto-start the server on launch so launching the app immediately
        // makes http://localhost:8080 usable.
        // Dev skips auto-start so launcher/server can be tested independently.
        if Environment::from_env().is_dev() {
            LAUNCHER_LOG.log(
                "Dev mode (VOULT_ENV=development): auto-start disabled — use \"Start Server\" in the tray menu",
                logger::Metadata::new(),
            );
            if self.is_port_open() {
                // Still reflect current port state immediately without the
                // 2s probe delay, but don't auto-open the browser in dev.
                self.last_health_probe = Instant::now() - HEALTH_PROBE_INTERVAL;
                self.refresh_state();
                self.update_menu();
            }
            return true;
        }

        if self.child.is_none() && !self.is_port_open() {
            self.start_server();
        } else if self.is_port_open() {
            // Refresh immediately so "Running elsewhere" shows without 2s delay
            self.last_health_probe = Instant::now() - HEALTH_PROBE_INTERVAL;
            self.refresh_state();
            self.update_menu();
            // If we detected a foreign server, still auto-open browser (prod only)
            if matches!(self.state, ServerState::RunningElsewhere { .. }) && !self.has_auto_opened {
                self.has_auto_opened = true;
                Self::open_browser();
            }
        }
        true
    }

    /// Handle a menu item activation. Returns `true` when the launcher should
    /// quit.
    fn handle_menu(&mut self, id: &str) -> bool {
        match id {
            QUIT_ITEM_ID => true,
            START_ITEM_ID => {
                match &self.state {
                    ServerState::Starting | ServerState::Running { .. } => self.stop_server(),
                    ServerState::Stopped | ServerState::Crashed { .. } => {
                        // Starting again clears any previous crash line.
                        self.start_server();
                    }
                    ServerState::RunningElsewhere { .. } => {}
                }
                false
            }
            _ => false,
        }
    }

    /// Run one polling tick: queued menu events, process/port reconciliation,
    /// and menu text refresh. Returns `true` when a Quit was requested.
    ///
    /// Menu events are drained explicitly (instead of relying on a tray event
    /// handler) so the same code path works on the Linux GTK thread, where the
    /// menu objects live. macOS gets its events through the winit proxy and
    /// calls `refresh_state`/`update_menu` from `about_to_wait` instead.
    #[cfg(target_os = "linux")]
    fn poll(&mut self) -> bool {
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if self.handle_menu(event.id().as_ref()) {
                return true;
            }
        }

        self.refresh_state();
        self.update_menu();
        false
    }
}

/// Avoid touching GTK menu widgets when nothing changed. `update_menu` runs on
/// every poll tick, and on Linux every `set_text`/`set_enabled` is a call into
/// GTK; rewriting identical labels makes appindicator redraw for no reason.
fn set_text_if_changed(item: &MenuItem, text: &str) {
    if item.text() != text {
        item.set_text(text);
    }
}

fn set_enabled_if_changed(item: &MenuItem, enabled: bool) {
    if item.is_enabled() != enabled {
        item.set_enabled(enabled);
    }
}

#[cfg(not(target_os = "linux"))]
impl ApplicationHandler<UserEvent> for Launcher {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if !self.initialize() {
            event_loop.exit();
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(event) => {
                if self.handle_menu(event.id().as_ref()) {
                    event_loop.exit();
                }
            }
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

fn log_startup() -> logger::LevelFilter {
    config::load_dotenv();
    let log_filter = logger::init();
    LAUNCHER_LOG.log(
        format_args!("launcher starting (VOULT_LOG_LEVEL={log_filter})"),
        logger::Metadata::new(),
    );
    if Environment::from_env().is_dev() {
        LAUNCHER_LOG.log(
            "VOULT_ENV=development detected (dev mode)",
            logger::Metadata::new(),
        );
    }
    log_filter
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_startup();

    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();

    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    let mut launcher = Launcher::new();
    event_loop.run_app(&mut launcher)?;
    Ok(())
}

/// Linux entry point.
///
/// tray-icon's Linux backend is libappindicator, which creates GTK widgets for
/// both the indicator and its menu. GTK is explicitly not thread-safe, and its
/// objects (`MenuItem`, `TrayIcon`) are `!Send`, so every tray/menu call must
/// happen on the thread that runs the GTK main loop. Instead of juggling a
/// second thread, Linux runs the entire launcher — tray, polling, and server
/// supervision — inside `gtk::main()`, and uses a GLib timeout as the tick.
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{cell::RefCell, rc::Rc};

    log_startup();

    // Fails with a clear error when no display/GTK is available (headless SSH,
    // no XDG_SESSION_TYPE, missing libgtk-3). Running the server directly is
    // the supported headless path.
    if let Err(error) = gtk::init() {
        LAUNCHER_LOG.error(
            format_args!(
                "Could not initialize GTK: {error}. A graphical session and libgtk-3 are \
                 required for the tray launcher; run voult-server directly instead."
            ),
            logger::Metadata::new(),
        );
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GTK initialization failed: {error}"),
        )));
    }

    let launcher = Rc::new(RefCell::new(Launcher::new()));
    if !launcher.borrow_mut().initialize() {
        return Ok(());
    }

    let tick = Rc::clone(&launcher);
    gtk::glib::timeout_add_local(POLL_INTERVAL, move || {
        if tick.borrow_mut().poll() {
            gtk::main_quit();
            gtk::glib::ControlFlow::Break
        } else {
            gtk::glib::ControlFlow::Continue
        }
    });

    gtk::main();

    // Never leave an orphaned server process behind: closing the tray is the
    // launcher's shutdown signal, exactly like Quit on macOS.
    launcher.borrow_mut().stop_server();
    Ok(())
}
