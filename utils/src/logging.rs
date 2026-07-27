use log::{LevelFilter, Log, Metadata, Record};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once, OnceLock};

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
        if SILENCE_DEPTH.load(Ordering::Relaxed) > 0 {
            return;
        }
        if let Ok(mut output) = file_output().lock()
            && let Some(output) = output.as_mut()
        {
            if output.file.is_none() {
                output.file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&output.path)
                    .ok();
            }
            if let Some(file) = output.file.as_mut() {
                let _ = writeln!(file, "{}", record.args());
            }
            return;
        }
        if record.target() == STDOUT_TARGET {
            let _ = writeln!(std::io::stdout().lock(), "{}", record.args());
        } else {
            let _ = writeln!(std::io::stderr().lock(), "{}", record.args());
        }
    }

    fn flush(&self) {
        if let Ok(mut output) = file_output().lock()
            && let Some(output) = output.as_mut()
            && let Some(file) = output.file.as_mut()
        {
            let _ = file.flush();
            return;
        }
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
}

static LOGGER: QanvuliLogger = QanvuliLogger;
static INIT: Once = Once::new();
static SILENCE_DEPTH: AtomicUsize = AtomicUsize::new(0);
struct FileOutput {
    path: PathBuf,
    file: Option<File>,
}

static FILE_OUTPUT: OnceLock<Mutex<Option<FileOutput>>> = OnceLock::new();

fn file_output() -> &'static Mutex<Option<FileOutput>> {
    FILE_OUTPUT.get_or_init(|| Mutex::new(None))
}

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

/// Suppresses logger output until the returned guard is dropped.
pub fn suppress() -> SilenceGuard {
    SILENCE_DEPTH.fetch_add(1, Ordering::Relaxed);
    SilenceGuard
}

pub struct SilenceGuard;

impl Drop for SilenceGuard {
    fn drop(&mut self) {
        SILENCE_DEPTH.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Redirects logs to `path` until the returned guard is dropped.
pub fn redirect_to_file(path: &Path) -> io::Result<LogFileGuard> {
    init();
    let mut output = file_output()
        .lock()
        .map_err(|_| io::Error::other("qanvuli logger output lock poisoned"))?;
    *output = Some(FileOutput {
        path: path.to_owned(),
        file: None,
    });
    Ok(LogFileGuard)
}

pub struct LogFileGuard;

impl Drop for LogFileGuard {
    fn drop(&mut self) {
        if let Ok(mut output) = file_output().lock() {
            *output = None;
        }
    }
}
