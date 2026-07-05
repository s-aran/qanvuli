//! Cross-source vulnerability identifier graph DTOs.

use sea_orm::FromQueryResult;
use serde::Serialize;

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct SourceSyncState {
    pub source: String,
    pub last_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub last_cursor: Option<String>,
    pub content_hash: Option<String>,
    pub schema_version: Option<String>,
    pub record_count: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentifierResolution {
    pub queried_id: String,
    pub normalized_id: String,
    pub identifier_type: String,
    pub related_cve_ids: Vec<String>,
    pub related_osv_ids: Vec<String>,
    pub related_aliases: Vec<String>,
    pub edges: Vec<IdentifierEdgeEvidence>,
    pub source_sync: Vec<SourceSyncState>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct IdentifierEdgeEvidence {
    pub from_identifier: String,
    pub to_identifier: String,
    pub relation_type: String,
    pub source: String,
    pub confidence: String,
    pub evidence_json: String,
    pub created_at: String,
}
