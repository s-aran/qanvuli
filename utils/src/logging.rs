use log::{LevelFilter, Log, Metadata, Record};
use std::fmt;
use std::io::Write;
use std::sync::Once;

const STDOUT_TARGET: &str = "qanvuli::stdout";
const STDERR_TARGET: &str = "qanvuli::stderr";

struct QanvuliLogger;

impl Log for QanvuliLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if record.target() == STDOUT_TARGET {
            let _ = writeln!(std::io::stdout().lock(), "{}", record.args());
        } else {
            let _ = writeln!(std::io::stderr().lock(), "{}", record.args());
        }
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
}

static LOGGER: QanvuliLogger = QanvuliLogger;
static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(LevelFilter::Info);
        }
    });
}

pub fn stdout(args: fmt::Arguments<'_>) {
    init();
    log::info!(target: STDOUT_TARGET, "{args}");
}

pub fn stderr(args: fmt::Arguments<'_>) {
    init();
    log::info!(target: STDERR_TARGET, "{args}");
}
