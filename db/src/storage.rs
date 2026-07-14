//! Shared SQLite storage maintenance operations.

use super::*;

pub(crate) async fn restore_sqlite_bulk_pragmas<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    db.execute_unprepared("PRAGMA foreign_keys = ON").await?;
    db.execute_unprepared("PRAGMA journal_mode = WAL").await?;
    db.execute_unprepared("PRAGMA synchronous = NORMAL").await?;
    db.execute_unprepared("PRAGMA locking_mode = NORMAL")
        .await?;
    db.execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE)")
        .await?;
    Ok(())
}

pub(crate) async fn compact_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    db.execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE)")
        .await?;
    db.execute_unprepared("VACUUM").await?;
    Ok(())
}
