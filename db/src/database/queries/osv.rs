use super::*;

impl SqlxDatabase {
    pub async fn find_osv_raw_json_by_id(
        &self,
        osv_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        let raw: Option<String> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT raw_json FROM osv_raw_records WHERE osv_id=? COLLATE NOCASE",
                    )
                    .bind(osv_id)
                    .fetch_optional(connection)
                    .await
                })
            })
            .await?;
        raw.map(|raw| {
            serde_json::from_str(&raw)
                .map_err(|error| sqlx::Error::Protocol(format!("invalid stored OSV JSON: {error}")))
        })
        .transpose()
    }

    pub async fn search_osv_summaries_free_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_free_text_sorted(
            query,
            crate::CveSummarySortOrder::RelationRankAsc,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_free_text_sorted(
        &self,
        query: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        let rows = self
            .search_osv_paginated_sorted(query, sort_order, limit as i64, offset as i64)
            .await?;
        Ok(rows.into_iter().map(osv_summary).collect())
    }

    pub async fn osv_summaries_by_ids_sorted(
        &self,
        ids: &[String],
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        Ok(self
            .osvs_by_ids_sorted(ids, sort_order, limit, offset)
            .await?
            .into_iter()
            .map(osv_summary)
            .collect())
    }

    pub async fn search_osv_summaries_by_package(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_by_exact_package(None, &[], None, query, limit, offset)
            .await
    }

    pub async fn find_enriched_osv(&self, osv_id: &str) -> Result<Option<OsvSummary>, sqlx::Error> {
        Ok(self.find_osv_summary(osv_id).await?.map(osv_summary))
    }

    pub async fn get_enriched_osv_many(
        &self,
        ids: &[String],
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        let mut rows = Vec::new();
        for id in ids {
            if let Some(row) = self.find_enriched_osv(id).await? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Resolves a page of OSV advisories to CVEs that exist in the local CVE table.
    ///
    /// The `osv_aliases` primary key starts with `osv_id`, so this remains one indexed
    /// lookup for the whole page instead of an identifier-graph query per result.
    pub async fn cve_aliases_for_osv_ids(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<HashMap<String, Vec<String>>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let include_rejected = include_rejected(scope);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows: Vec<(String, String)> = sqlx::query_as(
                        "SELECT alias.osv_id, cve.cve_id \
                         FROM osv_aliases AS alias \
                         JOIN cve ON cve.cve_id=alias.alias_id \
                         WHERE alias.osv_id IN (SELECT value FROM json_each(?)) \
                           AND (? OR cve.state=0) \
                         ORDER BY alias.osv_id, cve.cve_id",
                    )
                    .bind(ids_json)
                    .bind(include_rejected)
                    .fetch_all(connection)
                    .await?;
                    let mut aliases = HashMap::<String, Vec<String>>::new();
                    for (osv_id, cve_id) in rows {
                        aliases.entry(osv_id).or_default().push(cve_id);
                    }
                    Ok(aliases)
                })
            })
            .await
    }

    /// Loads complete OSV summaries for a page of CVEs in one indexed query.
    pub async fn osv_summaries_for_cve_ids(
        &self,
        ids: &[String],
    ) -> Result<HashMap<String, Vec<OsvSummary>>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        "SELECT alias.alias_id AS cve_id, advisory.osv_id, \
                                advisory.schema_version, advisory.published_at, \
                                advisory.modified_at, advisory.withdrawn_at, \
                                advisory.summary, advisory.details, \
                                (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') \
                                 FROM osv_affected_packages AS package \
                                 WHERE package.osv_id=advisory.osv_id) AS package_summary \
                         FROM osv_aliases AS alias \
                         JOIN osv_advisories AS advisory ON advisory.osv_id=alias.osv_id \
                         WHERE alias.alias_id IN (SELECT value FROM json_each(?)) \
                         ORDER BY alias.alias_id, advisory.modified_at DESC, advisory.osv_id",
                    )
                    .bind(ids_json)
                    .fetch_all(connection)
                    .await?;
                    let mut advisories = HashMap::<String, Vec<OsvSummary>>::new();
                    for row in rows {
                        advisories
                            .entry(row.try_get("cve_id")?)
                            .or_default()
                            .push(OsvSummary {
                                osv_id: row.try_get("osv_id")?,
                                schema_version: row.try_get("schema_version")?,
                                published_at: row.try_get("published_at")?,
                                modified_at: row.try_get("modified_at")?,
                                withdrawn_at: row.try_get("withdrawn_at")?,
                                summary: row.try_get("summary")?,
                                details: row.try_get("details")?,
                                package_summary: row.try_get("package_summary")?,
                            });
                    }
                    Ok(advisories)
                })
            })
            .await
    }

    pub async fn osv_advisory_families(&self) -> Result<Vec<String>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT CASE WHEN instr(osv_id, '-')>0 THEN substr(osv_id, 1, instr(osv_id, '-')-1) ELSE osv_id END FROM osv_advisories ORDER BY 1")
                .fetch_all(connection).await
        })).await
    }

    pub async fn search_osv_summaries_scoped(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_sorted(
            query,
            families,
            ecosystems,
            crate::CveSummarySortOrder::UpdatedDesc,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_scoped_sorted(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query,
                families,
                ecosystems,
                package: OsvPackageFilter::Any,
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_scoped_by_exact_package(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_by_exact_package_sorted(
            query,
            families,
            ecosystems,
            package,
            crate::CveSummarySortOrder::UpdatedDesc,
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_osv_summaries_scoped_by_exact_package_sorted(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query,
                families,
                ecosystems,
                package: OsvPackageFilter::Exact(package),
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_osv_summaries_scoped_by_package_sorted(
        &self,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_by_package_and_text_sorted(
            None, families, ecosystems, package, sort_order, limit, offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_osv_summaries_scoped_by_package_and_text_sorted(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query,
                families,
                ecosystems,
                package: OsvPackageFilter::Contains(package),
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    async fn search_osv_scoped_inner(
        &self,
        filters: OsvScopedFilters<'_>,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        if filters.query.is_none()
            && filters.families.is_empty()
            && filters.ecosystems.is_none_or(<[String]>::is_empty)
            && matches!(filters.package, OsvPackageFilter::Any)
        {
            return self
                .search_osv_unfiltered_sorted(sort_order, limit, offset)
                .await;
        }
        let query_terms = filters
            .query
            .map(crate::database::search::fts_tokens)
            .unwrap_or_default()
            .into_iter()
            .map(|term| format!("%{term}%"))
            .collect::<Vec<_>>();
        let (package, package_like) = match filters.package {
            OsvPackageFilter::Any => (None, None),
            OsvPackageFilter::Exact(value) => (Some(value.to_owned()), None),
            OsvPackageFilter::Contains(value) => (None, Some(format!("%{value}%"))),
        };
        let families = filters.families.to_vec();
        let ecosystems = filters.ecosystems.unwrap_or_default().to_vec();
        self.writer.with_connection(|connection| Box::pin(async move {
            let families_json = serde_json::to_string(&families).unwrap_or_default();
            let ecosystems_json = serde_json::to_string(&ecosystems).unwrap_or_default();
            let query_terms_json = serde_json::to_string(&query_terms).unwrap_or_default();
            let stored_package = sql_normalized_package_name("p.package_name", "p.ecosystem");
            let input_package = sql_normalized_package_name("input.package_name", "p.ecosystem");
            let order_by = match sort_order {
                crate::CveSummarySortOrder::PublishedAsc => "a.published_at IS NULL ASC, a.published_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::PublishedDesc => "a.published_at IS NULL ASC, a.published_at DESC, a.osv_id DESC",
                crate::CveSummarySortOrder::UpdatedAsc => "a.modified_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::UpdatedDesc => "a.modified_at DESC, a.osv_id DESC",
                crate::CveSummarySortOrder::CveIdAsc | crate::CveSummarySortOrder::ScoreAsc => "a.osv_id ASC",
                crate::CveSummarySortOrder::CveIdDesc | crate::CveSummarySortOrder::ScoreDesc => "a.osv_id DESC",
                crate::CveSummarySortOrder::RelationRankAsc => "a.published_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::RelationRankDesc => "a.published_at DESC, a.osv_id DESC",
            };
            let statement = format!("WITH input(package_name, package_like) AS (VALUES (?, ?)) SELECT DISTINCT a.osv_id, a.published_at, COALESCE(a.modified_at, '') AS modified_at, a.summary, a.details, a.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=a.osv_id) AS package_summary FROM input CROSS JOIN osv_advisories a LEFT JOIN osv_affected_packages p ON p.osv_id=a.osv_id WHERE (json_array_length(?)=0 OR NOT EXISTS(SELECT 1 FROM json_each(?) term WHERE NOT (a.osv_id LIKE term.value OR COALESCE(a.summary, '') LIKE term.value OR COALESCE(a.details, '') LIKE term.value OR EXISTS(SELECT 1 FROM osv_affected_packages text_package WHERE text_package.osv_id=a.osv_id AND (COALESCE(text_package.ecosystem, '') LIKE term.value OR COALESCE(text_package.package_name, '') LIKE term.value OR COALESCE(text_package.purl, '') LIKE term.value))))) AND (json_array_length(?)=0 OR EXISTS(SELECT 1 FROM json_each(?) f WHERE a.osv_id LIKE f.value || '-%')) AND (json_array_length(?)=0 OR p.ecosystem IN (SELECT value FROM json_each(?))) AND (input.package_name IS NULL OR {stored_package}={input_package} COLLATE BINARY) AND (input.package_like IS NULL OR p.package_name LIKE input.package_like OR p.purl LIKE input.package_like) ORDER BY {order_by} LIMIT ? OFFSET ?");
            let rows: Vec<SqlxOsvSummary> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
                .bind(&package)
                .bind(&package_like)
                .bind(&query_terms_json).bind(&query_terms_json)
                .bind(&families_json).bind(&families_json).bind(&ecosystems_json).bind(&ecosystems_json)
                .bind(limit as i64).bind(offset as i64)
                .fetch_all(connection).await?;
            Ok(rows.into_iter().map(osv_summary).collect())
        })).await
    }

    async fn search_osv_unfiltered_sorted(
        &self,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut statement = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
                "SELECT a.osv_id, a.published_at, COALESCE(a.modified_at, '') AS modified_at, a.summary, a.details, a.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=a.osv_id) AS package_summary FROM osv_advisories AS a",
            );
            match sort_order {
                crate::CveSummarySortOrder::PublishedAsc => statement.push(
                    " ORDER BY a.published_at IS NULL ASC, a.published_at ASC, a.osv_id ASC",
                ),
                crate::CveSummarySortOrder::PublishedDesc => statement.push(
                    " ORDER BY a.published_at IS NULL ASC, a.published_at DESC, a.osv_id DESC",
                ),
                crate::CveSummarySortOrder::UpdatedAsc => {
                    statement.push(" ORDER BY a.modified_at ASC, a.osv_id ASC")
                }
                crate::CveSummarySortOrder::UpdatedDesc => {
                    statement.push(" ORDER BY a.modified_at DESC, a.osv_id DESC")
                }
                crate::CveSummarySortOrder::CveIdAsc
                | crate::CveSummarySortOrder::ScoreAsc => {
                    statement.push(" ORDER BY a.osv_id ASC")
                }
                crate::CveSummarySortOrder::CveIdDesc
                | crate::CveSummarySortOrder::ScoreDesc => {
                    statement.push(" ORDER BY a.osv_id DESC")
                }
                crate::CveSummarySortOrder::RelationRankAsc => {
                    statement.push(" ORDER BY a.published_at ASC, a.osv_id ASC")
                }
                crate::CveSummarySortOrder::RelationRankDesc => {
                    statement.push(" ORDER BY a.published_at DESC, a.osv_id DESC")
                }
            };
            statement
                .push(" LIMIT ")
                .push_bind(i64::try_from(limit).unwrap_or(i64::MAX).max(1))
                .push(" OFFSET ")
                .push_bind(i64::try_from(offset).unwrap_or(i64::MAX));
            let rows: Vec<SqlxOsvSummary> = statement.build_query_as().fetch_all(connection).await?;
            Ok(rows.into_iter().map(osv_summary).collect())
        })).await
    }

    pub async fn count_osv_summaries_scoped(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query,
            families,
            ecosystems,
            package: OsvPackageFilter::Any,
        })
        .await
    }

    pub async fn count_osv_summaries_scoped_by_exact_package(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query,
            families,
            ecosystems,
            package: OsvPackageFilter::Exact(package),
        })
        .await
    }

    pub async fn count_osv_summaries_free_text(&self, query: &str) -> Result<u64, sqlx::Error> {
        let Some(query) = crate::database::search::fts_query(query) else {
            return Ok(0);
        };
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM osv_text_fts WHERE osv_text_fts MATCH ?",
                    )
                    .bind(query)
                    .fetch_one(c)
                    .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn count_osv_summaries_by_package(&self, query: &str) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query: None,
            families: &[],
            ecosystems: None,
            package: OsvPackageFilter::Exact(query),
        })
        .await
    }

    pub async fn count_osv_summaries_scoped_by_package(
        &self,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_summaries_scoped_by_package_and_text(None, families, ecosystems, package)
            .await
    }

    pub async fn count_osv_summaries_scoped_by_package_and_text(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query,
            families,
            ecosystems,
            package: OsvPackageFilter::Contains(package),
        })
        .await
    }

    async fn count_osv_scoped_inner(
        &self,
        filters: OsvScopedFilters<'_>,
    ) -> Result<u64, sqlx::Error> {
        let query_terms = filters
            .query
            .map(crate::database::search::fts_tokens)
            .unwrap_or_default()
            .into_iter()
            .map(|term| format!("%{term}%"))
            .collect::<Vec<_>>();
        let query_terms = serde_json::to_string(&query_terms)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let families = serde_json::to_string(filters.families)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let ecosystems = serde_json::to_string(filters.ecosystems.unwrap_or_default())
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let (package, package_like) = match filters.package {
            OsvPackageFilter::Any => (None, None),
            OsvPackageFilter::Exact(value) => (Some(value.to_owned()), None),
            OsvPackageFilter::Contains(value) => (None, Some(format!("%{value}%"))),
        };
        self.writer.with_connection(|c| Box::pin(async move {
            let stored_package = sql_normalized_package_name("p.package_name", "p.ecosystem");
            let input_package = sql_normalized_package_name("input.package_name", "p.ecosystem");
            let statement = format!("WITH input(package_name, package_like) AS (VALUES (?, ?)) SELECT COUNT(DISTINCT a.osv_id) FROM input CROSS JOIN osv_advisories a LEFT JOIN osv_affected_packages p ON p.osv_id=a.osv_id WHERE (json_array_length(?)=0 OR NOT EXISTS(SELECT 1 FROM json_each(?) term WHERE NOT (a.osv_id LIKE term.value OR COALESCE(a.summary, '') LIKE term.value OR COALESCE(a.details, '') LIKE term.value OR EXISTS(SELECT 1 FROM osv_affected_packages text_package WHERE text_package.osv_id=a.osv_id AND (COALESCE(text_package.ecosystem, '') LIKE term.value OR COALESCE(text_package.package_name, '') LIKE term.value OR COALESCE(text_package.purl, '') LIKE term.value))))) AND (json_array_length(?)=0 OR EXISTS(SELECT 1 FROM json_each(?) f WHERE a.osv_id LIKE f.value || '-%')) AND (json_array_length(?)=0 OR p.ecosystem IN (SELECT value FROM json_each(?))) AND (input.package_name IS NULL OR {stored_package}={input_package} COLLATE BINARY) AND (input.package_like IS NULL OR p.package_name LIKE input.package_like OR p.purl LIKE input.package_like)");
            let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(statement))
                .bind(&package)
                .bind(&package_like)
                .bind(&query_terms).bind(&query_terms)
                .bind(&families).bind(&families).bind(&ecosystems).bind(&ecosystems)
                .fetch_one(c).await?;
            Ok(n as u64)
        })).await
    }
}
