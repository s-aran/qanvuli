pub mod datetime_deserialize;
pub mod github;
pub mod loader;

use std::sync::Once;

static TLS_PROVIDER_INIT: Once = Once::new();

pub fn init_tls_provider() {
    TLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
