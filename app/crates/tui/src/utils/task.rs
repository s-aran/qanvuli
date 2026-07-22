use qanvuli_app_commands::common::{IngestProgress, IngestProgressCallback};
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
