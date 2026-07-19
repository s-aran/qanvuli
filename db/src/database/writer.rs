//! Single-owner SQLite write connection.
//!
//! This is the foundation for the SQLx migration. Mutating operations are added here
//! instead of relying on a pooled connection whose connection-scoped PRAGMAs may differ.

use super::maintenance::{
    check_required_schema, check_search_integrity, check_sqlite_integrity, finish_cve_bulk_load,
    finish_osv_bulk_load, prepare_cve_bulk_load, prepare_osv_bulk_load, rebuild_cve_search,
    rebuild_osv_search, rebuild_search,
};
use super::schema;
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub(crate) struct SqliteWriter {
    connection: Arc<Mutex<SqliteConnection>>,
}

impl SqliteWriter {
    pub(crate) async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        // Bulk ingestion uses more distinct normalized statements than SQLx's default cache of
        // 100. Keep them prepared on the one long-lived writer connection.
        let options = SqliteConnectOptions::from_str(database_url)?
            .foreign_keys(true)
            .statement_cache_capacity(512);
        let mut connection = SqliteConnection::connect_with(&options).await?;
        // These are intentionally set on this physical connection only.
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&mut connection)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&mut connection)
            .await?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub(crate) async fn with_connection<T>(
        &self,
        operation: impl for<'a> FnOnce(
            &'a mut SqliteConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, sqlx::Error>> + Send + 'a>,
        >,
    ) -> Result<T, sqlx::Error> {
        let mut connection = self.connection.lock().await;
        operation(&mut connection).await
    }

    /// Closes the physical connection. Replacement callers must not retain cloned handles.
    pub(crate) async fn close(self) -> Result<(), sqlx::Error> {
        let mutex = Arc::try_unwrap(self.connection).map_err(|_| {
            sqlx::Error::Protocol(
                "cannot close SQLite writer while cloned database handles remain".to_owned(),
            )
        })?;
        mutex.into_inner().close().await
    }

    pub(crate) async fn check_integrity(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_sqlite_integrity(&mut connection).await
    }

    pub(crate) async fn initialize_schema(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        schema::initialize(&mut connection).await
    }

    pub(crate) async fn rebuild_search(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        rebuild_search(&mut connection).await
    }

    pub(crate) async fn rebuild_cve_search(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        rebuild_cve_search(&mut connection).await
    }

    pub(crate) async fn rebuild_osv_search(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        rebuild_osv_search(&mut connection).await
    }

    pub(crate) async fn prepare_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        prepare_cve_bulk_load(&mut connection).await
    }

    pub(crate) async fn finish_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        finish_cve_bulk_load(&mut connection).await
    }

    pub(crate) async fn prepare_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        prepare_osv_bulk_load(&mut connection).await
    }

    pub(crate) async fn finish_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        finish_osv_bulk_load(&mut connection).await
    }

    pub(crate) async fn check_schema(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_required_schema(&mut connection).await?;
        check_search_integrity(&mut connection).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_writer_connection_enforces_foreign_keys() {
        let writer = SqliteWriter::connect("sqlite::memory:").await.unwrap();
        writer.initialize_schema().await.unwrap();
        let enabled: i64 = writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("PRAGMA foreign_keys")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(enabled, 1);
        let rejected = writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO cve_affected (cve_db_id, version_text, raw_json) VALUES (999, '', '{}')")
                        .execute(connection)
                        .await
                })
            })
            .await;
        assert!(rejected.is_err());
    }
}
