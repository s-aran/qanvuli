//! Vulnerability database API.

pub mod database {
    pub(crate) mod maintenance;
    pub(crate) mod package_eval;
    pub(crate) mod queries;
    pub mod replacement;
    pub(crate) mod schema;
    pub(crate) mod search;
    pub mod sqlx_database;
    pub(crate) mod timestamps;
    pub(crate) mod writer;
}

pub mod capec;
mod common;
mod cve_types;
mod epss;
mod identifiers;
mod kev;
mod osv;

pub use capec::*;
pub use common::detect_identifier_type;
pub use cve_types::*;
pub use database::package_eval::{
    OsvRange as SqlxOsvRange, ParsedPackagePurl, VersionMatch as SqlxVersionMatch,
    ecosystem_identity_key, evaluate_version as evaluate_sqlx_osv_version,
    is_concrete_package_version, normalize_package_name, package_identity_purl, parse_package_purl,
    versions_equivalent,
};
pub use database::sqlx_database::{
    OsvImportStats, SqlxAffected, SqlxCveDetail, SqlxCveReference, SqlxCveSearch, SqlxCveSummary,
    SqlxCveSummaryWithDetail, SqlxCvss, SqlxCvssSearch, SqlxCwe, SqlxDatabase, SqlxDatabaseStatus,
    SqlxEpss, SqlxEpssRisk, SqlxIdentifierEdge, SqlxIdentifierResolution, SqlxKev, SqlxKevEntry,
    SqlxOsvSummary, SqlxPackageFinding, SqlxSourceSyncState,
};
/// Shared database handle used by application crates.
pub type CveDatabase = SqlxDatabase;
pub use epss::*;
pub use identifiers::*;
pub use kev::*;
pub use osv::*;
