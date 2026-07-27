pub(crate) mod tools;

use crate::db::DbProvider;
use rmcp::{ServiceExt, transport::stdio};

#[derive(Clone)]
pub(crate) struct CveSearchServer {
    pub(crate) db: DbProvider,
}

impl CveSearchServer {
    pub(crate) fn new(db_url: String) -> Self {
        Self {
            db: DbProvider::new(db_url),
        }
    }
}

pub(crate) async fn serve(db_url: String) -> Result<(), String> {
    let service = CveSearchServer::new(db_url)
        .serve(stdio())
        .await
        .map_err(|err| format!("failed to serve MCP over stdio: {err}"))?;
    service
        .waiting()
        .await
        .map_err(|err| format!("MCP server failed: {err}"))?;
    Ok(())
}
