use super::*;

impl SqlxDatabase {
    pub async fn search_osv(
        &self,
        query: &str,
        limit: i64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        self.search_osv_paginated(query, limit, 0).await
    }

    pub async fn search_osv_paginated(
        &self,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        self.search_osv_paginated_sorted(query, CveSummarySortOrder::RelationRankAsc, limit, offset)
            .await
    }

    pub(crate) async fn search_osv_paginated_sorted(
        &self,
        query: &str,
        sort_order: CveSummarySortOrder,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut statement = QueryBuilder::<Sqlite>::new("SELECT advisory.osv_id, advisory.published_at, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=advisory.osv_id) AS package_summary FROM osv_text_fts JOIN osv_advisories AS advisory ON advisory.osv_id=osv_text_fts.osv_id WHERE osv_text_fts MATCH ");
            statement.push_bind(query);
            match sort_order {
                CveSummarySortOrder::PublishedAsc => statement.push(" ORDER BY advisory.published_at IS NULL ASC, advisory.published_at ASC, advisory.osv_id ASC"),
                CveSummarySortOrder::PublishedDesc => statement.push(" ORDER BY advisory.published_at IS NULL ASC, advisory.published_at DESC, advisory.osv_id DESC"),
                CveSummarySortOrder::UpdatedAsc => statement.push(" ORDER BY advisory.modified_at ASC, advisory.osv_id ASC"),
                CveSummarySortOrder::UpdatedDesc => statement.push(" ORDER BY advisory.modified_at DESC, advisory.osv_id DESC"),
                CveSummarySortOrder::CveIdAsc | CveSummarySortOrder::ScoreAsc => statement.push(" ORDER BY advisory.osv_id ASC"),
                CveSummarySortOrder::CveIdDesc | CveSummarySortOrder::ScoreDesc => statement.push(" ORDER BY advisory.osv_id DESC"),
                CveSummarySortOrder::RelationRankAsc => statement.push(" ORDER BY bm25(osv_text_fts) ASC, advisory.osv_id ASC"),
                CveSummarySortOrder::RelationRankDesc => statement.push(" ORDER BY bm25(osv_text_fts) DESC, advisory.osv_id DESC"),
            };
            statement.push(" LIMIT ").push_bind(limit.max(1)).push(" OFFSET ").push_bind(offset.max(0));
            statement.build_query_as().fetch_all(connection).await
        })).await
    }

    pub(crate) async fn osvs_by_ids_sorted(
        &self,
        ids: &[String],
        sort_order: CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut query = QueryBuilder::<Sqlite>::new("SELECT advisory.osv_id, advisory.published_at, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=advisory.osv_id) AS package_summary FROM json_each(");
            query.push_bind(ids_json).push(") AS requested JOIN osv_advisories AS advisory ON advisory.osv_id=requested.value");
            match sort_order {
                CveSummarySortOrder::PublishedAsc => query.push(" ORDER BY advisory.published_at IS NULL ASC, advisory.published_at ASC, advisory.osv_id ASC"),
                CveSummarySortOrder::PublishedDesc => query.push(" ORDER BY advisory.published_at IS NULL ASC, advisory.published_at DESC, advisory.osv_id DESC"),
                CveSummarySortOrder::UpdatedAsc => query.push(" ORDER BY advisory.modified_at ASC, advisory.osv_id ASC"),
                CveSummarySortOrder::UpdatedDesc => query.push(" ORDER BY advisory.modified_at DESC, advisory.osv_id DESC"),
                CveSummarySortOrder::CveIdAsc | CveSummarySortOrder::ScoreAsc => query.push(" ORDER BY advisory.osv_id ASC"),
                CveSummarySortOrder::CveIdDesc | CveSummarySortOrder::ScoreDesc => query.push(" ORDER BY advisory.osv_id DESC"),
                CveSummarySortOrder::RelationRankAsc => query.push(" ORDER BY CAST(requested.key AS INTEGER) ASC"),
                CveSummarySortOrder::RelationRankDesc => query.push(" ORDER BY CAST(requested.key AS INTEGER) DESC"),
            };
            query.push(" LIMIT ").push_bind(limit.max(1) as i64).push(" OFFSET ").push_bind(offset as i64);
            query.build_query_as().fetch_all(connection).await
        })).await
    }

    /// Finds one OSV advisory by its public identifier.
    pub async fn find_osv_summary(
        &self,
        osv_id: &str,
    ) -> Result<Option<SqlxOsvSummary>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT advisory.osv_id, advisory.published_at, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=advisory.osv_id) AS package_summary FROM osv_advisories AS advisory WHERE advisory.osv_id=? COLLATE NOCASE")
                        .bind(osv_id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Returns provider publication/modification timestamps for source-specific filtering.
    pub async fn osv_advisory_dates(
        &self,
        osv_id: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT published_at, modified_at FROM osv_advisories WHERE osv_id=?",
                    )
                    .bind(osv_id)
                    .fetch_optional(connection)
                    .await
                })
            })
            .await
    }

    /// Returns OSV publication/modification timestamps in caller order using bounded statements.
    pub async fn osv_advisory_dates_batch(
        &self,
        osv_ids: &[String],
    ) -> Result<Vec<Option<(Option<String>, Option<String>)>>, sqlx::Error> {
        if osv_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = osv_ids.to_vec();
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut dates = BTreeMap::new();
            for batch in requested.chunks(OSV_DATE_BATCH_SIZE) {
                let requested_json = serde_json::to_string(batch).map_err(|error| {
                    sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}"))
                })?;
                    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                        "SELECT advisory.osv_id, advisory.published_at, advisory.modified_at FROM osv_advisories advisory WHERE advisory.osv_id IN (SELECT value FROM json_each(?))",
                    )
                    .bind(requested_json)
                    .fetch_all(&mut *connection)
                    .await?;
                dates.extend(rows.into_iter().map(|(id, published, modified)| {
                    (id, (published, modified))
                }));
            }
            Ok(requested
                .into_iter()
                .map(|id| dates.get(&id).cloned())
                .collect())
        })).await
    }

    /// Starts an OSV synchronization and returns its last completed cursor.
    ///
    /// The cursor advances only after imports, indexes, and checks succeed.
    pub async fn begin_osv_sync(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    let cursor = sqlx::query("SELECT last_cursor FROM source_sync_state WHERE source='OSV'")
                        .fetch_optional(&mut *transaction)
                        .await?
                        .map(|row| row.try_get::<Option<String>, _>(0))
                        .transpose()?
                        .flatten();
                    let attempted_at = chrono::Utc::now().to_rfc3339();
                    sqlx::query("INSERT INTO source_sync_state (source, last_attempt_at, status) VALUES ('OSV', ?, 'running') ON CONFLICT(source) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, status='running', error_message=NULL")
                        .bind(attempted_at)
                        .execute(&mut *transaction)
                        .await?;
                    transaction.commit().await?;
                    Ok(cursor)
                })
            })
            .await
    }

    /// Records a successful complete OSV synchronization and advances the cursor once.
    pub async fn complete_osv_sync(&self, cursor: &str) -> Result<(), sqlx::Error> {
        let cursor = cursor.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let succeeded_at = chrono::Utc::now().to_rfc3339();
                    sqlx::query("UPDATE source_sync_state SET last_success_at=?, status='success', last_cursor=?, error_message=NULL WHERE source='OSV'")
                        .bind(succeeded_at)
                        .bind(cursor)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
    }

    /// Records a failed OSV synchronization without advancing the previous completed cursor.
    pub async fn fail_osv_sync(&self, error: &str) -> Result<(), sqlx::Error> {
        let error = error.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("UPDATE source_sync_state SET status='failed', error_message=? WHERE source='OSV'")
                        .bind(error)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
    }

    /// Imports a parsed batch in one transaction. Cursor advancement remains the caller's
    /// explicit all-or-nothing completion step, so retries are safe after a partial failure.
    pub async fn import_osv_records(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        Ok(self
            .import_osv_record_batch(records, true, false)
            .await?
            .examined)
    }

    /// Imports OSV batches while deferring the global FTS rebuild to the ZIP-level caller.
    pub async fn import_osv_records_deferred_search(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        Ok(self
            .import_osv_records_deferred_search_with_stats(records)
            .await?
            .examined)
    }

    /// Imports an OSV batch and reports records skipped by the batch hash comparison.
    pub async fn import_osv_records_deferred_search_with_stats(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<OsvImportStats, sqlx::Error> {
        self.import_osv_record_batch(records, false, false).await
    }

    /// Imports an incremental OSV batch and updates FTS only for inserted or changed IDs.
    /// Unchanged hashes produce no normalized or search writes.
    pub async fn import_osv_records_incremental_with_stats(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<OsvImportStats, sqlx::Error> {
        self.import_osv_record_batch(records, true, false).await
    }

    /// Inserts an OSV batch into an empty replacement database. Unlike the update path, this
    /// avoids conflict handling and child-row deletion while bulk-load indexes are absent.
    pub async fn import_osv_records_bulk_init(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        Ok(self
            .import_osv_record_batch(records, false, true)
            .await?
            .examined)
    }

    /// Imports one OSV advisory atomically.
    pub async fn import_osv_record(&self, record: OsvRawRecord) -> Result<(), sqlx::Error> {
        self.import_osv_record_with_search(record, true).await
    }

    async fn import_osv_record_with_search(
        &self,
        record: OsvRawRecord,
        update_search: bool,
    ) -> Result<(), sqlx::Error> {
        let advisory = OsvAdvisory::parse_json(record.raw_json.as_bytes())
            .map_err(|error| sqlx::Error::Protocol(format!("invalid OSV JSON: {error}")))?;
        advisory
            .validate_schema_shape()
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let raw_json = record.raw_json;
        let modified_at = canonical_utc(advisory.modified.as_deref().expect("validated modified"))
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV modified timestamp: {error}"))
            })?;
        let published_at = advisory
            .published
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV published timestamp: {error}"))
            })?;
        let withdrawn_at = advisory
            .withdrawn
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV withdrawn timestamp: {error}"))
            })?;
        let search_aliases = advisory.aliases.join(" ");
        let search_packages = advisory
            .affected
            .iter()
            .filter_map(|affected| affected.package.as_ref())
            .flat_map(|package| {
                [
                    package.ecosystem.as_deref(),
                    package.name.as_deref(),
                    package.purl.as_deref(),
                ]
            })
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction).await?;
                    sqlx::query("INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET source_path=excluded.source_path, provider_published_at=excluded.provider_published_at, provider_modified_at=excluded.provider_modified_at, fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json")
                        .bind(&advisory.id)
                        .bind(&record.source_path)
                        .bind(&published_at)
                        .bind(&modified_at)
                        .bind(chrono::Utc::now().to_rfc3339())
                        .bind(Md5::digest(raw_json.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>())
                        .bind(&raw_json)
                        .execute(&mut *transaction).await?;
                    let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM osv_raw_records WHERE osv_id=?")
                        .bind(&advisory.id).fetch_one(&mut *transaction).await?;
                    sqlx::query("INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET schema_version=excluded.schema_version, published_at=excluded.published_at, modified_at=excluded.modified_at, withdrawn_at=excluded.withdrawn_at, summary=excluded.summary, details=excluded.details, raw_record_id=excluded.raw_record_id")
                        .bind(&advisory.id)
                        .bind(advisory.schema_version.as_deref().unwrap_or_default())
                        .bind(&published_at)
                        .bind(&modified_at)
                        .bind(&withdrawn_at)
                        .bind(&advisory.summary)
                        .bind(&advisory.details)
                        .bind(raw_record_id)
                        .execute(&mut *transaction).await?;
                    let now = chrono::Utc::now().to_rfc3339();
                    sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, 'osv', 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                        .bind(&advisory.id).bind(&now).bind(&now).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_aliases WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_references WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_range_events WHERE range_id IN (SELECT id FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?))").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_affected_packages WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    delete_osv_identifier_edges(&mut transaction, &advisory.id).await?;
                    for (relation_type, identifiers) in [("alias", &advisory.aliases), ("upstream", &advisory.upstream), ("related", &advisory.related)] {
                        for identifier in identifiers {
                            let identifier_type = if identifier.starts_with("CVE-") { "cve" } else if identifier.starts_with("GHSA-") { "ghsa" } else { "other" };
                            sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, ?, 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                                .bind(identifier).bind(identifier_type).bind(&now).bind(&now).execute(&mut *transaction).await?;
                            if relation_type == "alias" {
                                sqlx::query("INSERT OR IGNORE INTO osv_aliases(osv_id, alias_id) VALUES (?, ?)")
                                    .bind(&advisory.id).bind(identifier).execute(&mut *transaction).await?;
                            }
                            sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                                .bind(&advisory.id).bind(identifier).bind(relation_type).bind(&now).execute(&mut *transaction).await?;
                            if relation_type != "upstream" {
                                sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                                    .bind(identifier).bind(&advisory.id).bind(relation_type).bind(&now).execute(&mut *transaction).await?;
                            }
                        }
                    }
                    for reference in &advisory.references {
                        sqlx::query("INSERT OR IGNORE INTO osv_references(osv_id, reference_type, url) VALUES (?, ?, ?)")
                            .bind(&advisory.id).bind(&reference.reference_type).bind(&reference.url).execute(&mut *transaction).await?;
                    }
                    for (affected_order, affected) in advisory.affected.iter().enumerate() {
                        let package = affected.package.as_ref();
                        let source_ecosystem =
                            package.and_then(|value| value.ecosystem.as_deref());
                        let parsed_package_purl = package
                            .and_then(|value| value.purl.as_deref())
                            .and_then(parse_package_purl);
                        let package_ecosystem = canonical_imported_package_ecosystem(
                            source_ecosystem,
                            parsed_package_purl
                                .as_ref()
                                .map(|parsed| parsed.ecosystem.as_str()),
                        );
                        let package_name = package
                            .and_then(|value| value.name.as_deref())
                            .map(|name| {
                                package_ecosystem.as_deref().or(source_ecosystem).map_or_else(
                                    || name.to_owned(),
                                    |ecosystem| normalize_package_name(ecosystem, name),
                                )
                            });
                        let package_purl =
                            parsed_package_purl.map(|parsed| parsed.identity_purl);
                        sqlx::query("INSERT INTO osv_affected_packages (osv_id, affected_order, ecosystem, package_name, purl) VALUES (?, ?, ?, ?, ?)")
                            .bind(&advisory.id)
                            .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                            .bind(package_ecosystem)
                            .bind(package_name)
                            .bind(package_purl)
                            .execute(&mut *transaction).await?;
                        let package_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()").fetch_one(&mut *transaction).await?;
                        for (range_order, range) in affected.ranges.iter().enumerate() {
                            sqlx::query("INSERT INTO osv_ranges (affected_package_id, affected_order, range_order, range_type) VALUES (?, ?, ?, ?)")
                                .bind(package_id)
                                .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                                .bind(i64::try_from(range_order).unwrap_or(i64::MAX))
                                .bind(range.range_type.as_deref().unwrap_or("ECOSYSTEM"))
                                .execute(&mut *transaction).await?;
                            let range_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()").fetch_one(&mut *transaction).await?;
                            let mut event_order = 0_i64;
                            for event in &range.events {
                                for (kind, value) in event.event_pairs() {
                                    sqlx::query("INSERT INTO osv_range_events (range_id, event_type, value, event_order) VALUES (?, ?, ?, ?)")
                                        .bind(range_id).bind(kind).bind(value).bind(event_order).execute(&mut *transaction).await?;
                                    event_order += 1;
                                }
                            }
                        }
                        for version in &affected.versions {
                            sqlx::query("INSERT OR IGNORE INTO osv_versions VALUES (?, ?)")
                                .bind(package_id).bind(version).execute(&mut *transaction).await?;
                        }
                    }
                    if update_search {
                        sqlx::query("DELETE FROM osv_text_fts WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                        sqlx::query("INSERT INTO osv_text_fts(rowid, osv_id, summary, details, aliases, packages) VALUES ((SELECT rowid FROM osv_advisories WHERE osv_id=?), ?, ?, ?, ?, ?)")
                            .bind(&advisory.id).bind(&advisory.id).bind(advisory.summary.as_deref().unwrap_or_default()).bind(advisory.details.as_deref().unwrap_or_default()).bind(search_aliases).bind(search_packages).execute(&mut *transaction).await?;
                    }
                    transaction.commit().await
                })
            })
            .await
    }

    async fn import_osv_record_batch(
        &self,
        records: Vec<OsvRawRecord>,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<OsvImportStats, sqlx::Error> {
        let count = records.len();
        if records.is_empty() {
            return Ok(OsvImportStats::default());
        }
        let parsed_records = tokio::task::spawn_blocking(move || {
            records
                .into_par_iter()
                .map(Self::osv_batch_input)
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("OSV parser task panicked: {error}")))?
        .map_err(sqlx::Error::Protocol)?;
        let fetched_at = chrono::Utc::now().to_rfc3339();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    let mut existing_hashes = BTreeMap::new();
                    if !bulk_init {
                        // Stay below conservative SQLite variable limits while avoiding an
                        // additional lookup for every advisory.
                        for chunk in parsed_records.chunks(500) {
                            let mut query = QueryBuilder::<Sqlite>::new(
                                "SELECT osv_id, content_hash FROM osv_raw_records WHERE osv_id IN (",
                            );
                            let mut separated = query.separated(", ");
                            for record in chunk {
                                separated.push_bind(&record.advisory.id);
                            }
                            separated.push_unseparated(")");
                            let rows: Vec<(String, String)> = query
                                .build_query_as()
                                .fetch_all(&mut *transaction)
                                .await?;
                            existing_hashes.extend(rows);
                        }
                    }
                    let mut stats = OsvImportStats {
                        examined: count,
                        ..OsvImportStats::default()
                    };
                    for record in parsed_records {
                        match existing_hashes.get(&record.advisory.id) {
                            Some(hash) if hash == &record.content_hash => {
                                stats.unchanged += 1;
                                continue;
                            }
                            Some(_) => stats.updated += 1,
                            None => stats.inserted += 1,
                        }
                        Self::write_osv_batch_record(
                            &mut transaction,
                            record,
                            &fetched_at,
                            update_search,
                            bulk_init,
                        )
                        .await?;
                    }
                    transaction.commit().await?;
                    Ok(stats)
                })
            })
            .await
    }

    fn osv_batch_input(record: OsvRawRecord) -> Result<OsvBatchInput, String> {
        let advisory = OsvAdvisory::parse_json(record.raw_json.as_bytes())
            .map_err(|error| format!("invalid OSV JSON: {error}"))?;
        advisory
            .validate_schema_shape()
            .map_err(|error| error.to_string())?;
        let modified_at = canonical_utc(advisory.modified.as_deref().expect("validated modified"))
            .map_err(|error| format!("invalid OSV modified timestamp: {error}"))?;
        let published_at = advisory
            .published
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| format!("invalid OSV published timestamp: {error}"))?;
        let withdrawn_at = advisory
            .withdrawn
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| format!("invalid OSV withdrawn timestamp: {error}"))?;
        let search_aliases = advisory.aliases.join(" ");
        let search_packages = advisory
            .affected
            .iter()
            .filter_map(|affected| affected.package.as_ref())
            .flat_map(|package| {
                [
                    package.ecosystem.as_deref(),
                    package.name.as_deref(),
                    package.purl.as_deref(),
                ]
            })
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let content_hash = Md5::digest(record.raw_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(OsvBatchInput {
            advisory,
            source_path: record.source_path,
            raw_json: record.raw_json,
            modified_at,
            published_at,
            withdrawn_at,
            content_hash,
            search_aliases,
            search_packages,
        })
    }

    async fn write_osv_batch_record(
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        record: OsvBatchInput,
        fetched_at: &str,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<(), sqlx::Error> {
        let advisory = record.advisory;
        let raw_record_sql = if bulk_init {
            "INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET source_path=excluded.source_path, provider_published_at=excluded.provider_published_at, provider_modified_at=excluded.provider_modified_at, fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json"
        };
        let raw_record_result = sqlx::query(raw_record_sql)
            .bind(&advisory.id)
            .bind(&record.source_path)
            .bind(&record.published_at)
            .bind(&record.modified_at)
            .bind(fetched_at)
            .bind(&record.content_hash)
            .bind(&record.raw_json)
            .execute(&mut **transaction)
            .await?;
        let raw_record_id: i64 = if bulk_init {
            raw_record_result.last_insert_rowid()
        } else {
            sqlx::query_scalar("SELECT id FROM osv_raw_records WHERE osv_id=?")
                .bind(&advisory.id)
                .fetch_one(&mut **transaction)
                .await?
        };
        let advisory_sql = if bulk_init {
            "INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET schema_version=excluded.schema_version, published_at=excluded.published_at, modified_at=excluded.modified_at, withdrawn_at=excluded.withdrawn_at, summary=excluded.summary, details=excluded.details, raw_record_id=excluded.raw_record_id"
        };
        sqlx::query(advisory_sql)
            .bind(&advisory.id)
            .bind(advisory.schema_version.as_deref().unwrap_or_default())
            .bind(&record.published_at)
            .bind(&record.modified_at)
            .bind(&record.withdrawn_at)
            .bind(&advisory.summary)
            .bind(&advisory.details)
            .bind(raw_record_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, 'osv', 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
            .bind(&advisory.id)
            .bind(fetched_at)
            .bind(fetched_at)
            .execute(&mut **transaction)
            .await?;
        if !bulk_init {
            delete_osv_identifier_edges(transaction, &advisory.id).await?;
            for sql in [
                "DELETE FROM osv_aliases WHERE osv_id=?",
                "DELETE FROM osv_references WHERE osv_id=?",
                "DELETE FROM osv_range_events WHERE range_id IN (SELECT id FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?))",
                "DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_affected_packages WHERE osv_id=?",
            ] {
                sqlx::query(sql)
                    .bind(&advisory.id)
                    .execute(&mut **transaction)
                    .await?;
            }
        }
        for (relation_type, identifiers) in [
            ("alias", &advisory.aliases),
            ("upstream", &advisory.upstream),
            ("related", &advisory.related),
        ] {
            for identifier in identifiers {
                let identifier_type = if identifier.starts_with("CVE-") {
                    "cve"
                } else if identifier.starts_with("GHSA-") {
                    "ghsa"
                } else {
                    "other"
                };
                sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, ?, 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                    .bind(identifier)
                    .bind(identifier_type)
                    .bind(fetched_at)
                    .bind(fetched_at)
                    .execute(&mut **transaction)
                    .await?;
                if relation_type == "alias" {
                    sqlx::query(
                        "INSERT OR IGNORE INTO osv_aliases(osv_id, alias_id) VALUES (?, ?)",
                    )
                    .bind(&advisory.id)
                    .bind(identifier)
                    .execute(&mut **transaction)
                    .await?;
                }
                sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                    .bind(&advisory.id)
                    .bind(identifier)
                    .bind(relation_type)
                    .bind(fetched_at)
                    .execute(&mut **transaction)
                    .await?;
                if relation_type != "upstream" {
                    sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                        .bind(identifier)
                        .bind(&advisory.id)
                        .bind(relation_type)
                        .bind(fetched_at)
                        .execute(&mut **transaction)
                        .await?;
                }
            }
        }
        for references in advisory.references.chunks(250) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT OR IGNORE INTO osv_references(osv_id, reference_type, url) ",
            );
            query.push_values(references, |mut row, reference| {
                row.push_bind(&advisory.id)
                    .push_bind(&reference.reference_type)
                    .push_bind(&reference.url);
            });
            query.build().execute(&mut **transaction).await?;
        }
        for (affected_order, affected) in advisory.affected.iter().enumerate() {
            let package = affected.package.as_ref();
            let source_ecosystem = package.and_then(|value| value.ecosystem.as_deref());
            let parsed_package_purl = package
                .and_then(|value| value.purl.as_deref())
                .and_then(parse_package_purl);
            let package_ecosystem = canonical_imported_package_ecosystem(
                source_ecosystem,
                parsed_package_purl
                    .as_ref()
                    .map(|parsed| parsed.ecosystem.as_str()),
            );
            let package_name = package.and_then(|value| value.name.as_deref()).map(|name| {
                package_ecosystem
                    .as_deref()
                    .or(source_ecosystem)
                    .map_or_else(
                        || name.to_owned(),
                        |ecosystem| normalize_package_name(ecosystem, name),
                    )
            });
            let package_purl = parsed_package_purl.map(|parsed| parsed.identity_purl);
            let package_result = sqlx::query("INSERT INTO osv_affected_packages (osv_id, affected_order, ecosystem, package_name, purl) VALUES (?, ?, ?, ?, ?)")
                .bind(&advisory.id)
                .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                .bind(package_ecosystem)
                .bind(package_name)
                .bind(package_purl)
                .execute(&mut **transaction)
                .await?;
            let package_id = package_result.last_insert_rowid();
            for (range_order, range) in affected.ranges.iter().enumerate() {
                let range_result = sqlx::query("INSERT INTO osv_ranges (affected_package_id, affected_order, range_order, range_type) VALUES (?, ?, ?, ?)")
                    .bind(package_id)
                    .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                    .bind(i64::try_from(range_order).unwrap_or(i64::MAX))
                    .bind(range.range_type.as_deref().unwrap_or("ECOSYSTEM"))
                    .execute(&mut **transaction)
                    .await?;
                let range_id = range_result.last_insert_rowid();
                let mut event_rows = Vec::new();
                let mut event_order = 0_i64;
                for event in &range.events {
                    for (kind, value) in event.event_pairs() {
                        event_rows.push((kind, value, event_order));
                        event_order += 1;
                    }
                }
                for events in event_rows.chunks(200) {
                    let mut query = QueryBuilder::<Sqlite>::new(
                        "INSERT INTO osv_range_events (range_id, event_type, value, event_order) ",
                    );
                    query.push_values(events, |mut row, (kind, value, order)| {
                        row.push_bind(range_id)
                            .push_bind(*kind)
                            .push_bind(*value)
                            .push_bind(*order);
                    });
                    query.build().execute(&mut **transaction).await?;
                }
            }
            for versions in affected.versions.chunks(400) {
                let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT OR IGNORE INTO osv_versions (affected_package_id, version) ",
                );
                query.push_values(versions, |mut row, version| {
                    row.push_bind(package_id).push_bind(version);
                });
                query.build().execute(&mut **transaction).await?;
            }
        }
        if update_search {
            sqlx::query("DELETE FROM osv_text_fts WHERE osv_id=?")
                .bind(&advisory.id)
                .execute(&mut **transaction)
                .await?;
            sqlx::query("INSERT INTO osv_text_fts(rowid, osv_id, summary, details, aliases, packages) VALUES ((SELECT rowid FROM osv_advisories WHERE osv_id=?), ?, ?, ?, ?, ?)")
                .bind(&advisory.id)
                .bind(&advisory.id)
                .bind(advisory.summary.as_deref().unwrap_or_default())
                .bind(advisory.details.as_deref().unwrap_or_default())
                .bind(record.search_aliases)
                .bind(record.search_packages)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }
}
