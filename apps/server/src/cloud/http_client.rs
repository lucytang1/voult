//! Shared outbound client for provider calls. A bounded timeout prevents a
//! stalled cloud API from pinning detached mirror/OAuth tasks indefinitely.
use std::sync::LazyLock;
use std::time::Duration;

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("shared cloud HTTP client configuration is valid")
});

pub fn client() -> &'static reqwest::Client {
    &CLIENT
}
