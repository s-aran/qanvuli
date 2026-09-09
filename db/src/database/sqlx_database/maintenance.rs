use super::*;

impl SqlxDatabase {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self {
            writer: SqliteWriter::connect(url).await?,
        })
    }

    /// Opens an independent connection to the same file-backed database.
    ///
    /// This is useful for concurrent read operations, since cloned handles intentionally share
    /// one connection. In-memory databases keep sharing their original connection so they retain
    /// the same contents.
    pub async fn independent_connection(&self) -> Result<Self, sqlx::Error> {
        Ok(Self {
            writer: self.writer.independent_connection().await?,
        })
    }

    /// Opens an independent query-only connection tuned for interactive reads.
    pub async fn independent_read_connection(&self) -> Result<Self, sqlx::Error> {
        Ok(Self {
            writer: self.writer.independent_read_connection().await?,
        })
    }

    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        self.writer.initialize_schema().await
    }

    /// Compatibility name retained for existing database callers.
    pub async fn initialize_schema(&self) -> Result<(), sqlx::Error> {
        self.initialize().await
    }

    /// Adds optional OSV ordering indexes used by interactive, incrementally paged searches.
    /// Existing databases can acquire these without a full schema rebuild.
    pub async fn ensure_osv_sort_indexes(&self) -> Result<(), sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::raw_sql(
                        r#"
                        CREATE INDEX IF NOT EXISTS idx_osv_published_asc ON osv_advisories(published_at IS NULL, published_at ASC, osv_id ASC);
                        CREATE INDEX IF NOT EXISTS idx_osv_published_desc ON osv_advisories(published_at IS NULL, published_at DESC, osv_id DESC);
                        CREATE INDEX IF NOT EXISTS idx_osv_modified_osv_id ON osv_advisories(modified_at, osv_id);
                        "#,
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn close(self) -> Result<(), sqlx::Error> {
        self.writer.close().await
    }

    pub async fn rebuild_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_search().await
    }

    pub async fn rebuild_cve_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_cve_search().await
    }

    /// Refreshes search projections for the CVEs changed by a delta update.
    pub async fn refresh_cve_search_for_ids(
        &self,
        cve_ids: Vec<String>,
    ) -> Result<(), sqlx::Error> {
        self.writer.refresh_cve_search_for_ids(cve_ids).await
    }

    pub async fn rebuild_osv_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_osv_search().await
    }

    /// Verifies schema plus a fixed number of indexed search-projection sentinels.
    pub async fn check_search_integrity_quick(&self) -> Result<(), sqlx::Error> {
        self.writer.check_search_integrity_quick().await
    }

    /// Verifies schema shape/version without requiring derived search data to be healthy.
    pub async fn check_required_schema(&self) -> Result<(), sqlx::Error> {
        self.writer.check_required_schema().await
    }

    /// Prepares a replacement database for bulk CVE loading.
    pub async fn prepare_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_cve_bulk_load().await
    }

    /// Builds deferred indexes/search data and restores normal SQLite durability.
    pub async fn finish_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_cve_bulk_load().await
    }

    pub async fn finish_cve_bulk_load_with_index_signal(
        &self,
        index_started: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), sqlx::Error> {
        self.writer
            .finish_cve_bulk_load_with_index_signal(index_started)
            .await
    }

    pub async fn prepare_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_osv_bulk_load().await
    }

    pub async fn finish_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_osv_bulk_load().await
    }

    /// Rebuilds identifier edges from normalized OSV relations.
    pub async fn rebuild_identifier_graph(&self) -> Result<(), sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    rebuild_osv_identifier_edges(
                        &mut transaction,
                        &chrono::Utc::now().to_rfc3339(),
                    )
                    .await?;
                    transaction.commit().await
                })
            })
            .await
    }

    pub async fn check(&self) -> Result<(), sqlx::Error> {
        self.writer.check_quick().await
    }

    /// Runs SQLite quick_check and complete search correspondence scans.
    pub async fn check_scan(&self) -> Result<(), sqlx::Error> {
        self.writer.check_scan().await
    }

    /// Runs only SQLite quick_check (plus connection foreign-key enforcement verification).
    /// Replacement validation uses this separately so failures identify the exact stage.
    pub async fn check_scan_sqlite(&self) -> Result<(), sqlx::Error> {
        self.writer.check_sqlite_quick().await
    }

    /// Runs the expensive SQLite file-integrity stage used by `db check --full`.
    pub async fn check_full_sqlite(&self) -> Result<(), sqlx::Error> {
        self.writer.check_integrity().await
    }

    /// Runs the complete foreign-key scan used by `db check --full`.
    pub async fn check_full_foreign_keys(&self) -> Result<(), sqlx::Error> {
        self.writer.check_foreign_key_integrity().await
    }

    /// Runs native FTS and complete CVE projection checks.
    pub async fn check_full_cve_search(&self) -> Result<(), sqlx::Error> {
        self.writer.check_cve_search_full().await
    }

    /// Runs native FTS and complete OSV projection checks.
    pub async fn check_full_osv_search(&self) -> Result<(), sqlx::Error> {
        self.writer.check_osv_search_full().await
    }

    pub const fn schema_version() -> i64 {
        schema::SCHEMA_VERSION
    }

    /// Finds a CVE by its public identifier.
    pub async fn import_kev_json(&self, raw_json: String) -> Result<usize, sqlx::Error> {
        Ok(self.import_kev_json_with_status(raw_json, true).await?.0)
    }

    /// Imports KEV data and reports whether the snapshot changed.
    pub async fn import_kev_json_with_status(
        &self,
        raw_json: String,
        force: bool,
    ) -> Result<(usize, bool), sqlx::Error> {
        let catalog = KevCatalog::parse_json(raw_json.as_bytes())
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV JSON: {error}")))?;
        catalog
            .validate_schema_shape()
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV catalog: {error}")))?;
        let count = catalog.vulnerabilities.len();
        let hash = Md5::digest(raw_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.writer.with_connection(|connection| Box::pin(async move {
            let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kev_raw_records WHERE content_hash=? AND raw_json=?)")
                .bind(&hash)
                .bind(&raw_json)
                .fetch_one(&mut *connection)
                .await?;
            if unchanged && !force {
                return Ok(false);
            }
            let mut transaction = connection.begin().await?;
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('KEV', 'CISA KEV', 'enrichment', 'known_exploited_vulnerabilities.json', 'json')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
            sqlx::query("INSERT INTO kev_raw_records (record_id, source_path, provider_modified_at, score_date, fetched_at, content_hash, raw_json) VALUES (?, NULL, NULL, NULL, ?, ?, ?) ON CONFLICT(record_id) DO UPDATE SET fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json")
                .bind(&catalog.catalog_version).bind(&now).bind(hash).bind(&raw_json)
                .execute(&mut *transaction).await?;
            let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM kev_raw_records WHERE record_id=?")
                .bind(&catalog.catalog_version).fetch_one(&mut *transaction).await?;
            for entry in catalog.vulnerabilities {
                sqlx::query("INSERT INTO kev_entries (cve_id, raw_record_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, fetched_at) SELECT cve_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM cve WHERE cve_id=? ON CONFLICT(cve_id) DO UPDATE SET raw_record_id=excluded.raw_record_id, vendor_project=excluded.vendor_project, product=excluded.product, vulnerability_name=excluded.vulnerability_name, date_added=excluded.date_added, short_description=excluded.short_description, required_action=excluded.required_action, due_date=excluded.due_date, known_ransomware_campaign_use=excluded.known_ransomware_campaign_use, notes=excluded.notes, fetched_at=excluded.fetched_at")
                    .bind(raw_record_id)
                    .bind(entry.vendor_project)
                    .bind(entry.product)
                    .bind(entry.vulnerability_name)
                    .bind(entry.date_added)
                    .bind(entry.short_description)
                    .bind(entry.required_action)
                    .bind(entry.due_date)
                    .bind(entry.known_ransomware_campaign_use)
                    .bind(entry.notes)
                    .bind(&now)
                    .bind(entry.cve_id)
                    .execute(&mut *transaction).await?;
            }
            transaction.commit().await?;
            Ok(true)
        })).await.map(|changed| (count, changed))
    }

    /// Atomically replaces the current EPSS snapshot.
    pub async fn import_epss_csv(&self, csv: String) -> Result<usize, sqlx::Error> {
        Ok(self.import_epss_csv_with_status(csv, true).await?.0)
    }

    /// Imports EPSS data and reports whether the snapshot changed.
    pub async fn import_epss_csv_with_status(
        &self,
        csv: String,
        force: bool,
    ) -> Result<(usize, bool), sqlx::Error> {
        let parsed = EpssCurrentCsv::parse(&csv)
            .map_err(|error| sqlx::Error::Protocol(format!("invalid EPSS CSV: {error}")))?;
        let count = parsed.rows.len();
        let hash = Md5::digest(csv.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.writer.with_connection(|connection| Box::pin(async move {
            let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM epss_raw_records WHERE content_hash=? AND raw_csv=?)")
                .bind(&hash)
                .bind(&csv)
                .fetch_one(&mut *connection)
                .await?;
            if unchanged && !force {
                return Ok(false);
            }
            let mut transaction = connection.begin().await?;
            sqlx::query("CREATE TEMP TABLE IF NOT EXISTS epss_import_stage (cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, percentile REAL NOT NULL, input_order INTEGER NOT NULL) WITHOUT ROWID")
                .execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM epss_import_stage")
                .execute(&mut *transaction).await?;
            // Four bindings per row keep each statement below conservative SQLite limits.
            for (batch_index, rows) in parsed.rows.chunks(200).enumerate() {
                let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT INTO epss_import_stage (cve_id, epss, percentile, input_order) ",
                );
                query.push_values(rows.iter().enumerate(), |mut row, (offset, value)| {
                    row.push_bind(&value.cve_id)
                        .push_bind(value.epss)
                        .push_bind(value.percentile)
                        .push_bind(i64::try_from(batch_index * 200 + offset).unwrap_or(i64::MAX));
                });
                query.push(" ON CONFLICT(cve_id) DO UPDATE SET epss=excluded.epss, percentile=excluded.percentile, input_order=excluded.input_order WHERE excluded.input_order >= epss_import_stage.input_order");
                query.build().execute(&mut *transaction).await?;
            }
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('EPSS', 'FIRST EPSS', 'enrichment', 'epss_scores-current.csv', 'csv')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
            sqlx::query("INSERT INTO epss_raw_records (score_date, fetched_at, content_hash, raw_csv) VALUES (?, ?, ?, ?) ON CONFLICT(score_date) DO UPDATE SET fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_csv=excluded.raw_csv")
                .bind(&parsed.score_date).bind(&now).bind(hash).bind(&csv).execute(&mut *transaction).await?;
            let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM epss_raw_records WHERE score_date=?")
                .bind(&parsed.score_date)
                .fetch_one(&mut *transaction).await?;
            // Replace the snapshot atomically so removed CVEs do not leave stale scores.
            sqlx::query("DELETE FROM epss_current").execute(&mut *transaction).await?;
            sqlx::query("INSERT INTO epss_current (cve_id, raw_record_id, epss, percentile, score_date, model_version, fetched_at) SELECT c.cve_id, ?, s.epss, s.percentile, ?, ?, ? FROM epss_import_stage s JOIN cve c ON c.cve_id=s.cve_id")
                .bind(raw_record_id)
                .bind(&parsed.score_date)
                .bind(&parsed.model_version)
                .bind(&now)
                .execute(&mut *transaction).await?;
            transaction.commit().await?;
            Ok(true)
        })).await.map(|changed| (count, changed))
    }
}
