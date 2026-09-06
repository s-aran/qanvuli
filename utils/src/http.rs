//! Shared finite deadlines for feed and archive downloads.
use std::{sync::LazyLock, time::Duration};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
}

pub fn client() -> reqwest::Client {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        client_builder()
            .build()
            .expect("failed to initialize HTTP client")
    });
    CLIENT.clone()
}

pub fn blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .expect("failed to initialize HTTP client")
}
