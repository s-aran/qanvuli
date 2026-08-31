//! Single-owner SQLite writer.

use super::maintenance::{
    check_cve_search_full, check_foreign_key_integrity, check_osv_search_full,
    check_required_schema, check_search_integrity_quick, check_sqlite_integrity,
    check_sqlite_quick, finish_cve_bulk_load, finish_cve_bulk_load_with_index_signal,
    finish_osv_bulk_load, prepare_cve_bulk_load, prepare_osv_bulk_load, rebuild_cve_search,
    rebuild_osv_search, rebuild_search, refresh_cve_search_for_ids,
};
use super::schema;
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{str::FromStr, sync::Arc};
use tokio::sync::Mutex;

const INTERACTIVE_READ_CACHE_PRAGMA: &str = "PRAGMA cache_size = -32768";
const INTERACTIVE_READ_MMAP_PRAGMA: &str = "PRAGMA mmap_size = 268435456";

#[derive(Clone, Debug)]
pub(crate) struct SqliteWriter {
    connection: Arc<Mutex<SqliteConnection>>,
    database_url: Arc<str>,
}

impl SqliteWriter {
    pub(crate) async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        // Bulk ingestion uses more distinct normalized statements than SQLx's default cache of
        // 100. Keep them prepared on the one long-lived writer connection.
        let options = SqliteConnectOptions::from_str(database_url)?
            .foreign_keys(true)
            .statement_cache_capacity(512);
        let mut connection = SqliteConnection::connect_with(&options).await?;
        // These PRAGMAs are connection-scoped.
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&mut connection)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&mut connection)
            .await?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            database_url: Arc::from(database_url),
        })
    }

    /// Opens another connection to the same file-backed database so independent reads do not
    /// queue behind this connection. An in-memory URL names a database per connection, so keep
    /// sharing the original connection in that case.
    pub(crate) async fn independent_connection(&self) -> Result<Self, sqlx::Error> {
        let url = self.database_url.as_ref();
        if url.contains(":memory:") || url.to_ascii_lowercase().contains("mode=memory") {
            return Ok(self.clone());
        }
        Self::connect(url).await
    }

    /// Opens a query-only connection with a larger cache for interactive search workloads.
    pub(crate) async fn independent_read_connection(&self) -> Result<Self, sqlx::Error> {
        let url = self.database_url.as_ref();
        if url.contains(":memory:") || url.to_ascii_lowercase().contains("mode=memory") {
            // A separate SQLite in-memory connection would have different contents. Do not set
            // query_only on the shared writer connection either.
            return Ok(self.clone());
        }
        let options = SqliteConnectOptions::from_str(url)?
            .foreign_keys(true)
            .statement_cache_capacity(512);
        let mut connection = SqliteConnection::connect_with(&options).await?;
        sqlx::query("PRAGMA query_only = ON")
            .execute(&mut connection)
            .await?;
        sqlx::query(INTERACTIVE_READ_CACHE_PRAGMA)
            .execute(&mut connection)
            .await?;
        sqlx::query(INTERACTIVE_READ_MMAP_PRAGMA)
            .execute(&mut connection)
            .await?;
        sqlx::query("PRAGMA temp_store = MEMORY")
            .execute(&mut connection)
            .await?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            database_url: self.database_url.clone(),
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

    /// Closes the writer before database replacement.
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

    pub(crate) async fn check_quick(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_required_schema(&mut connection).await?;
        check_search_integrity_quick(&mut connection).await
    }

    pub(crate) async fn check_scan(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_required_schema(&mut connection).await?;
        check_sqlite_quick(&mut connection).await?;
        check_foreign_key_integrity(&mut connection).await?;
        check_cve_search_full(&mut connection).await?;
        check_osv_search_full(&mut connection).await
    }

    pub(crate) async fn check_sqlite_quick(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_sqlite_quick(&mut connection).await
    }

    pub(crate) async fn check_foreign_key_integrity(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_foreign_key_integrity(&mut connection).await
    }

    pub(crate) async fn check_cve_search_full(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_cve_search_full(&mut connection).await
    }

    pub(crate) async fn check_osv_search_full(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_osv_search_full(&mut connection).await
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

    pub(crate) async fn refresh_cve_search_for_ids(
        &self,
        cve_ids: Vec<String>,
    ) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        refresh_cve_search_for_ids(&mut connection, cve_ids).await
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

    pub(crate) async fn finish_cve_bulk_load_with_index_signal(
        &self,
        index_started: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        finish_cve_bulk_load_with_index_signal(&mut connection, Some(index_started)).await
    }

    pub(crate) async fn prepare_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        prepare_osv_bulk_load(&mut connection).await
    }

    pub(crate) async fn finish_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        finish_osv_bulk_load(&mut connection).await
    }

    pub(crate) async fn check_search_integrity_quick(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_required_schema(&mut connection).await?;
        check_search_integrity_quick(&mut connection).await
    }

    pub(crate) async fn check_required_schema(&self) -> Result<(), sqlx::Error> {
        let mut connection = self.connection.lock().await;
        check_required_schema(&mut connection).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_writer_connection_enforces_foreign_keys() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-writer-connections-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let database_url = format!(
            "sqlite:///{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        );
        let writer = SqliteWriter::connect(&database_url).await.unwrap();
        writer.initialize_schema().await.unwrap();
        let independent = writer.independent_connection().await.unwrap();
        assert!(!Arc::ptr_eq(&writer.connection, &independent.connection));

        for connection in [&writer, &independent] {
            let enabled: i64 = connection
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
            let rejected = connection
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

        independent.close().await.unwrap();
        writer.close().await.unwrap();
        for candidate in [
            path.clone(),
            path.with_extension("sqlite-wal"),
            path.with_extension("sqlite-shm"),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[tokio::test]
    async fn independent_reader_is_query_only_and_tuned_for_interactive_search() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-reader-connections-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let database_url = format!(
            "sqlite:///{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        );
        let writer = SqliteWriter::connect(&database_url).await.unwrap();
        writer.initialize_schema().await.unwrap();
        let reader = writer.independent_read_connection().await.unwrap();

        let (query_only, cache_size, mmap_size, temp_store): (i64, i64, i64, i64) = reader
            .with_connection(|connection| {
                Box::pin(async move {
                    Ok((
                        sqlx::query_scalar("PRAGMA query_only")
                            .fetch_one(&mut *connection)
                            .await?,
                        sqlx::query_scalar("PRAGMA cache_size")
                            .fetch_one(&mut *connection)
                            .await?,
                        sqlx::query_scalar("PRAGMA mmap_size")
                            .fetch_one(&mut *connection)
                            .await?,
                        sqlx::query_scalar("PRAGMA temp_store")
                            .fetch_one(&mut *connection)
                            .await?,
                    ))
                })
            })
            .await
            .unwrap();
        assert_eq!(query_only, 1);
        assert_eq!(cache_size, -32 * 1024);
        assert_eq!(mmap_size, 256 * 1024 * 1024);
        assert_eq!(temp_store, 2);
        let rejected = reader
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO app_metadata (key, value) VALUES ('reader', 'write')")
                        .execute(connection)
                        .await
                })
            })
            .await;
        assert!(rejected.is_err());

        reader.close().await.unwrap();
        writer.close().await.unwrap();
        for candidate in [
            path.clone(),
            path.with_extension("sqlite-wal"),
            path.with_extension("sqlite-shm"),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }
}
