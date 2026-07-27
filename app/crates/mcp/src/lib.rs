mod args;
mod common;
mod db;
mod response;
mod server;

/// Starts the MCP server over stdio using the provided database URL.
pub fn run(db_url: String) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(server::serve(db_url))
}
