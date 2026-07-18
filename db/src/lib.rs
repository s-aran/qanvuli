//! Database API facade.
//!
//! The implementation is being migrated from the former monolithic module into
//! `database/` components. Public exports remain here so callers do not depend on
//! the internal layout.

pub mod database {
    pub(crate) mod compat;
    pub(crate) mod maintenance;
    pub(crate) mod package_eval;
    pub mod replacement;
    pub(crate) mod schema;
    pub(crate) mod search;
    pub mod sqlx_database;
    pub(crate) mod timestamps;
    pub(crate) mod writer;
}

mod common;
mod cve_types;
mod epss;
mod identifiers;
mod kev;
mod osv;

pub use common::detect_identifier_type;
pub use cve_types::*;
pub use database::package_eval::{
    OsvRange as SqlxOsvRange, VersionMatch as SqlxVersionMatch,
    evaluate_version as evaluate_sqlx_osv_version,
};
pub use database::sqlx_database::{
    SqlxAffected, SqlxCveDetail, SqlxCveReference, SqlxCveSearch, SqlxCveSummary,
    SqlxCveSummaryWithDetail, SqlxCvss, SqlxCvssSearch, SqlxCwe, SqlxDatabase, SqlxDatabaseStatus,
    SqlxEpss, SqlxEpssRisk, SqlxIdentifierEdge, SqlxIdentifierResolution, SqlxKev, SqlxKevEntry,
    SqlxOsvSummary, SqlxPackageFinding, SqlxSourceSyncState,
};
/// Backward-compatible public database handle. The implementation is SQLx-only.
pub type CveDatabase = SqlxDatabase;
pub use epss::*;
pub use identifiers::*;
pub use kev::*;
pub use osv::*;
