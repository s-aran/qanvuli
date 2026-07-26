//! Public API for qanvuli vulnerability data.

/// Database connection, query, and synchronization API.
pub mod database {
    pub use qanvuli_db::database::replacement::{
        DatabaseReplacement, RecoveryAction, ReplacementError, candidate_database_path,
        recover_interrupted_replacement, remove_sqlite_database_files,
    };
    pub use qanvuli_db::{
        AffectedStatus, CapecCategory, CapecCategoryDetail, CapecDetail, CapecEntry, CapecHistory,
        CapecNote, CapecReference, CapecSearchFilters, CapecTaxonomyMapping, CapecView,
        CapecViewDetail, CveAdvancedQueryMode, CveAdvancedSearch, CveAffectedDetail,
        CveAffectedVersionDetail, CveCvssDetail, CveCweDetail, CveDatabase, CveDetail,
        CveReference, CveRiskSummary, CveStateScope, CveSummary, CveSummarySortOrder,
        CveSummaryWithDetail, CweEntry, EnrichedCveSummary, EnrichedFinding, Evidence,
        FindingEnrichment, ImportSummary, OsvImportStats, OsvRawRecord, OsvSummary, PackageQuery,
        PrioritySignals, SqlxAffected, SqlxCveDetail, SqlxCveReference, SqlxCveSearch,
        SqlxCveSummary, SqlxCveSummaryWithDetail, SqlxCvss, SqlxCvssSearch, SqlxCwe, SqlxDatabase,
        SqlxDatabaseStatus, SqlxEpss, SqlxEpssRisk, SqlxIdentifierEdge, SqlxIdentifierResolution,
        SqlxKev, SqlxKevEntry, SqlxOsvRange, SqlxOsvSummary, SqlxPackageFinding,
        SqlxSourceSyncState, SqlxVersionMatch, cve_state_label, detect_identifier_type,
        evaluate_sqlx_osv_version,
    };
}

/// Download and archive-ingestion API for vulnerability data feeds.
pub mod ingest {
    pub use qanvuli_collector::providers::{
        capec::CapecCatalogFile,
        cve::CveRelease,
        cwe::CweCatalogFile,
        epss::download_epss_current_csv,
        kev::download_kev_json,
        osv::{OSV_ALL_ZIP, OsvDownloadError, OsvGcsSource, OsvModifiedId, parse_modified_id_csv},
    };
    pub use qanvuli_utils::{
        github::GitHubReleaseFile,
        loader::{JsonEntry, JsonStorage, ZipStorage},
    };
}

/// Vulnerability data models returned by the public API.
pub mod model {
    pub use qanvuli_models::{
        RawCveStatusRecord, capec::AttackPatternCatalog, cwe::WeaknessCatalog,
    };
    pub use qanvuli_models::{
        capec::read_capec_catalog_xml,
        cwe::read_cwe_catalog_zip,
        osv::{OSV_DATABASE_SOURCE_PREFIXES, is_known_osv_database_prefix},
    };
}

/// Process-wide runtime initialization required by network clients.
pub mod runtime {
    pub use qanvuli_utils::init_tls_provider;
}
