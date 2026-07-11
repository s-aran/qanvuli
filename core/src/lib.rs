//! Stable public API for querying and maintaining qanvuli vulnerability data.
//!
//! Lower-level workspace crates are implementation details. This crate exposes
//! only the types and operations required by API consumers.

/// Database connection, query, and synchronization API.
pub mod database {
    pub use qanvuli_db::{
        CveActiveModels, CveAdvancedQueryMode, CveAdvancedSearch, CveAffectedDetail, CveCvssDetail,
        CveCweDetail, CveDatabase, CveDetail, CveReference, CveStateScope, CveSummary,
        CveSummarySortOrder, CveSummaryWithDetail, CveZipFileRecord, CweEntry, EnrichedCveSummary,
        EnrichedFinding, ImportSummary, OsvRawRecord, ReadJsonFileRecord, cve_state_label,
        detect_identifier_type,
    };
}

/// Download and archive-ingestion API for vulnerability data feeds.
pub mod ingest {
    pub use qanvuli_collector::providers::{
        cve::CveRelease,
        cwe::CweCatalogFile,
        epss::download_epss_current_csv,
        kev::download_kev_json,
        osv::{OSV_ALL_ZIP, OsvGcsSource, OsvModifiedId, parse_modified_id_csv},
    };
    pub use qanvuli_utils::{
        github::GitHubReleaseFile,
        loader::{FileStorageTrait, JsonEntry, ZipStorage},
    };
}

/// Vulnerability data models returned by the public API.
pub mod model {
    pub use qanvuli_models::{RawCveStatusRecord, cwe::WeaknessCatalog};
    pub use qanvuli_models::{
        cwe::read_cwe_catalog_zip,
        osv::{OSV_DATABASE_SOURCE_PREFIXES, is_known_osv_database_prefix},
    };
}

/// Process-wide runtime initialization required by network clients.
pub mod runtime {
    pub use qanvuli_utils::init_tls_provider;
}
