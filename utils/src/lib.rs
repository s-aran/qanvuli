macro_rules! eprintln {
    ($($arg:tt)*) => {
        crate::logging::stderr(format_args!($($arg)*))
    };
}

pub mod datetime_deserialize;
pub mod github;
pub mod http;
pub mod loader;
pub mod logging;

use std::sync::Once;

static TLS_PROVIDER_INIT: Once = Once::new();

pub fn init_tls_provider() {
    TLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
