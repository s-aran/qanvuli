use qanvuli_app_commands::common::{IngestProgress, IngestProgressCallback};
#[cfg(unix)]
use std::{fs::File, os::fd::AsRawFd};
use std::{future::Future, sync::Arc, thread};
use tokio::sync::mpsc;

pub(crate) fn maintenance_progress_channel() -> (
    IngestProgressCallback,
    mpsc::UnboundedReceiver<IngestProgress>,
) {
    let (progress_tx, progress_rx) = mpsc::unbounded_channel();
    let progress = Arc::new(move |progress| {
        let _ = progress_tx.send(progress);
    });
    (progress, progress_rx)
}

pub(crate) fn spawn_maintenance_task<F>(future: F) -> mpsc::UnboundedReceiver<Result<(), String>>
where
    F: Future<Output = Result<(), String>> + Send + 'static,
{
    let (result_tx, result_rx) = mpsc::unbounded_channel();
    thread::spawn(move || {
        let _stderr = StderrSilencer::new();
        let result = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(future),
            Err(err) => Err(format!("failed to build maintenance runtime: {err}")),
        };
        let _ = result_tx.send(result);
    });
    result_rx
}

struct StderrSilencer {
    #[cfg(unix)]
    saved: Option<i32>,
}

impl StderrSilencer {
    #[cfg(unix)]
    fn new() -> Self {
        let Ok(dev_null) = File::options().write(true).open("/dev/null") else {
            return Self { saved: None };
        };
        let saved = unsafe { dup(STDERR_FD) };
        if saved < 0 {
            return Self { saved: None };
        }
        if unsafe { dup2(dev_null.as_raw_fd(), STDERR_FD) } < 0 {
            unsafe {
                close(saved);
            }
            return Self { saved: None };
        }
        Self { saved: Some(saved) }
    }

    #[cfg(not(unix))]
    fn new() -> Self {
        Self {}
    }
}

#[cfg(unix)]
impl Drop for StderrSilencer {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            unsafe {
                let _ = dup2(saved, STDERR_FD);
                close(saved);
            }
        }
    }
}

#[cfg(unix)]
const STDERR_FD: i32 = 2;

#[cfg(unix)]
unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
}
