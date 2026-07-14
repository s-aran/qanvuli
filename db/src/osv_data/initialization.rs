//! SQLite storage setup for bulk OSV imports.

use super::super::*;

pub(crate) const OSV_BULK_LOAD_DROPPED_INDEXES: &[&str] = &[
    "idx_source_raw_records_source_hash",
    "idx_osv_aliases_alias",
    "idx_osv_cve_search_cve_id",
    "idx_osv_affected_packages_lookup",
    "idx_osv_ranges_package",
    "idx_osv_range_events_range",
    "idx_identifier_edges_to",
    "idx_identifier_edges_from",
];

pub(crate) const OSV_BULK_LOAD_FINAL_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_source_raw_records_source_hash ON source_raw_records (source, content_hash)",
    "CREATE INDEX IF NOT EXISTS idx_osv_aliases_alias ON osv_aliases (alias_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_cve_search_cve_id ON osv_cve_search (cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_lookup ON osv_affected_packages (ecosystem, package_name)",
    "CREATE INDEX IF NOT EXISTS idx_osv_ranges_package ON osv_ranges (affected_package_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_range_events_range ON osv_range_events (range_id, event_order)",
    "CREATE INDEX IF NOT EXISTS idx_identifier_edges_to ON vulnerability_identifier_edges (to_identifier)",
    "CREATE INDEX IF NOT EXISTS idx_identifier_edges_from ON vulnerability_identifier_edges (from_identifier)",
];

pub(crate) async fn prepare_bulk_osv_import_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
    db.execute_unprepared("PRAGMA journal_mode = MEMORY")
        .await?;
    db.execute_unprepared("PRAGMA synchronous = OFF").await?;
    db.execute_unprepared("PRAGMA temp_store = MEMORY").await?;
    db.execute_unprepared("PRAGMA cache_size = -400000").await?;
    db.execute_unprepared("PRAGMA locking_mode = EXCLUSIVE")
        .await?;
    for index_name in OSV_BULK_LOAD_DROPPED_INDEXES {
        db.execute_unprepared(&format!("DROP INDEX IF EXISTS {index_name}"))
            .await?;
    }
    Ok(())
}

pub(crate) async fn finish_bulk_osv_import_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    for sql in OSV_BULK_LOAD_FINAL_INDEXES {
        db.execute_unprepared(sql).await?;
    }
    rebuild_osv_text_search(db).await?;
    restore_sqlite_bulk_pragmas(db).await
}

pub(crate) async fn finish_bulk_osv_import_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    rebuild_osv_text_search(db).await?;
    restore_sqlite_bulk_pragmas(db).await
}
