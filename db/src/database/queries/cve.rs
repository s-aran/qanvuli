use super::*;

impl SqlxDatabase {
    pub async fn find_cve_raw_json_by_id(
        &self,
        cve_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        self.cve_raw_json(cve_id)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    sqlx::Error::Protocol(format!("invalid stored CVE JSON: {error}"))
                })
            })
            .transpose()
    }

    pub async fn find_cve_model_by_id(
        &self,
        cve_id: &str,
    ) -> Result<Option<RawCveStatusRecord>, sqlx::Error> {
        self.cve_raw_json(cve_id)
            .await?
            .map(|raw| {
                parse_json_with_raw(raw).map_err(|error| {
                    sqlx::Error::Protocol(format!("invalid stored CVE JSON: {error}"))
                })
            })
            .transpose()
    }

    pub async fn find_cve_summary_with_detail(
        &self,
        cve_id: &str,
    ) -> Result<Option<CveSummaryWithDetail>, sqlx::Error> {
        Ok(self.cve_summary_with_detail(cve_id).await?.map(Into::into))
    }

    /// Loads CVE summaries and normalized details in bounded set-based queries.
    pub async fn cve_summaries_with_details_batch(
        &self,
        cve_ids: &[String],
        state_scope: CveStateScope,
    ) -> Result<Vec<Option<CveSummaryWithDetail>>, sqlx::Error> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = cve_ids.to_vec();
        let include_rejected = include_rejected(state_scope);
        let mut by_id = HashMap::new();
        for batch in requested.chunks(CVE_ID_BATCH_SIZE) {
            let requested_json = serde_json::to_string(batch)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let summaries: Vec<CveSummary> = self
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        let rows: Vec<SqlxCveSummary> = sqlx::query_as(
                            "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve c WHERE c.cve_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0)",
                        )
                        .bind(requested_json)
                        .bind(include_rejected)
                        .fetch_all(connection)
                        .await?;
                        Ok(rows.into_iter().map(CveSummary::from).collect())
                    })
                })
                .await?;
            for row in self.attach_cve_overview_details(summaries).await? {
                by_id.insert(row.summary.cve_id.clone(), row);
            }
        }
        Ok(requested
            .into_iter()
            .map(|id| by_id.get(&id).cloned())
            .collect())
    }

    pub async fn attach_cve_overview_details(
        &self,
        rows: Vec<CveSummary>,
    ) -> Result<Vec<CveSummaryWithDetail>, sqlx::Error> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let cve_ids_json = serde_json::to_string(
            &rows
                .iter()
                .map(|row| row.cve_id.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let mut details = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let id_rows: Vec<(i64, String, String)> = sqlx::query_as(
                        "SELECT c.id, c.cve_id, c.raw_json FROM cve c JOIN json_each(?) requested ON requested.value=c.cve_id",
                    )
                    .bind(cve_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let db_ids_json = serde_json::to_string(
                        &id_rows.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
                    )
                    .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
                    let cve_id_by_db_id = id_rows
                        .iter()
                        .map(|(id, cve_id, _)| (*id, cve_id.clone()))
                        .collect::<HashMap<_, _>>();
                    let affected_descriptions_by_db_id = id_rows
                        .iter()
                        .map(|(id, _, raw_json)| (*id, cve_affected_descriptions(raw_json)))
                        .collect::<HashMap<_, _>>();
                    let mut details = id_rows
                        .into_iter()
                        .map(|(_, cve_id, _)| (cve_id, CveDetail::default()))
                        .collect::<HashMap<_, _>>();

                    let cwes: Vec<(i64, i32, Option<String>)> = sqlx::query_as(
                        "SELECT link.cve_db_id, cwe.id, cwe.description FROM cve_cwe link JOIN cwe ON cwe.id=link.cwe_id WHERE link.cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY link.cve_db_id, cwe.id",
                    )
                    .bind(&db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (db_id, id, description) in cwes {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            detail.cwes.push(CveCweDetail { id, description });
                        }
                    }

                    let cvss: Vec<CompatCvssRow> = sqlx::query_as(
                        "SELECT cve_db_id, version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cve_db_id, base_score DESC, version",
                    )
                    .bind(&db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (db_id, version, base_score, base_severity, vector_string, source) in cvss {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            detail.cvss.push(CveCvssDetail {
                                version,
                                base_score,
                                base_severity,
                                vector_string,
                                source,
                            });
                        }
                    }

                    let affected: Vec<CompatAffectedRow> = sqlx::query_as(
                        "SELECT cve_db_id, vendor, product, package_name, collection_url, default_status, raw_json FROM cve_affected WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cve_db_id, id",
                    )
                    .bind(db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let mut affected_indexes = HashMap::<i64, usize>::new();
                    for (db_id, vendor, product, package_name, collection_url, default_status, raw_json) in affected {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            let affected_index = affected_indexes.entry(db_id).or_default();
                            let description = affected_descriptions_by_db_id
                                .get(&db_id)
                                .and_then(|descriptions| descriptions.get(*affected_index))
                                .cloned()
                                .flatten();
                            *affected_index += 1;
                            let versions = cve_stored_versions(&raw_json)
                                .unwrap_or_else(|error| {
                                    tracing::warn!(cve_id = %cve_id, %error, "failed to parse cve_affected.raw_json");
                                    Vec::new()
                                })
                                .into_iter()
                                .map(|version| CveAffectedVersionDetail {
                                    version: version.version,
                                    status: version.status,
                                    version_type: version.version_type,
                                    less_than: version.less_than,
                                    less_than_or_equal: version.less_than_or_equal,
                                })
                                .collect();
                            detail.affected.push(CveAffectedDetail {
                                vendor,
                                product,
                                package_name,
                                description,
                                collection_url,
                                default_status,
                                versions,
                            });
                        }
                    }
                    Ok(details)
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|summary| CveSummaryWithDetail {
                detail: details.remove(&summary.cve_id).unwrap_or_default(),
                summary,
            })
            .collect())
    }

    pub async fn search_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let Some(query) = crate::database::search::fts_query(query) else {
            return Ok(Vec::new());
        };
        let include_rejected = include_rejected(scope);
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts f JOIN cve c ON c.cve_id=f.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.published_at DESC, c.cve_id LIMIT ? OFFSET ?")
                .bind(query).bind(include_rejected).bind(limit as i64).bind(offset as i64)
                .fetch_all(connection).await?;
            Ok(rows.into_iter().map(summary).collect())
        })).await
    }

    pub async fn cve_summaries_by_ids_with_state_scope(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let include_rejected = include_rejected(scope);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query_as(
                        "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en \
                         FROM json_each(?) AS requested \
                         JOIN cve AS c ON c.cve_id=requested.value \
                         WHERE (? OR c.state=0) \
                         ORDER BY CAST(requested.key AS INTEGER)",
                    )
                    .bind(ids_json)
                    .bind(include_rejected)
                    .fetch_all(connection)
                    .await?;
                    Ok(rows.into_iter().map(summary).collect())
                })
            })
            .await
    }

    pub async fn cve_summaries_by_ids_sorted(
        &self,
        ids: &[String],
        scope: CveStateScope,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .cves_by_ids_sorted(ids, scope, sort_order, limit, offset)
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_cwe_with_state_scope(
        &self,
        cwe_ids: &[String],
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_cwes(
                cwe_ids,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_affected(
                vendor.map(str::to_owned),
                product.map(str::to_owned),
                false,
                false,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_vendor_product_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        exclude_wordpress_collection: bool,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        if let Some(product_exact) = product_exact {
            let vendor = vendor_exact.or(vendor).map(str::to_owned);
            return Ok(self
                .search_cves_by_affected_product_key(
                    vendor,
                    vendor_exact.is_some(),
                    product_exact.to_owned(),
                    exclude_wordpress_collection,
                    include_rejected(scope),
                    limit as i64,
                    offset as i64,
                )
                .await?
                .into_iter()
                .map(summary)
                .collect());
        }
        let vendor = vendor_exact.or(vendor).map(str::to_owned);
        let product = product_exact.or(product).map(str::to_owned);
        let exact = vendor_exact.is_some() || product_exact.is_some();
        Ok(self
            .search_cves_by_affected(
                vendor,
                product,
                exact,
                exclude_wordpress_collection,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_cvss_with_state_scope(
        &self,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_cvss(
                SqlxCvssSearch {
                    min_score,
                    max_score,
                    severity: severity.map(str::to_owned),
                    version: version.map(str::to_owned),
                },
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_product_cvss_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let filters = SqlxCveSearch {
            vendor_like: vendor.map(|v| format!("%{v}%")),
            product_like: product.map(|v| format!("%{v}%")),
            vendor_exact: vendor_exact.map(str::to_owned),
            product_exact: product_exact.map(str::to_owned),
            cvss: SqlxCvssSearch {
                min_score,
                max_score,
                severity: severity.map(str::to_owned),
                version: version.map(str::to_owned),
            },
            sort_order: crate::CveSummarySortOrder::ScoreDesc,
            ..Default::default()
        };
        Ok(self
            .search_cves_advanced(
                filters,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_date_with_state_scope(
        &self,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_dates(
                published_since.map(str::to_owned),
                updated_since.map(str::to_owned),
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_id_prefix(prefix, include_rejected(scope), limit as i64, offset as i64)
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let rows = self
            .search_cves_advanced_with_kev(
                advanced_cve_filters(options),
                include_rejected(options.state_scope),
                options.kev_only,
                limit as i64,
                offset as i64,
            )
            .await?;
        Ok(rows.into_iter().map(summary).collect())
    }

    pub async fn count_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
    ) -> Result<u64, sqlx::Error> {
        self.count_cves_advanced_with_kev(
            advanced_cve_filters(options),
            include_rejected(options.state_scope),
            options.kev_only,
        )
        .await
    }

    pub async fn count_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let Some(query) = crate::database::search::fts_query(query) else {
            return Ok(0);
        };
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(*) FROM cve_summary_fts f JOIN cve c ON c.cve_id=f.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0)").bind(query).bind(include).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let vendor = vendor.map(|v| format!("%{v}%"));
        let product = product.map(|v| format!("%{v}%"));
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT c.id) FROM cve c JOIN cve_affected a ON a.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR a.vendor LIKE ?) AND (? IS NULL OR a.product LIKE ? OR a.package_name LIKE ?)").bind(include).bind(&vendor).bind(&vendor).bind(&product).bind(&product).bind(&product).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_cwe_with_state_scope(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let ids: Vec<i64> = ids
            .iter()
            .filter_map(|id| {
                id.trim()
                    .strip_prefix("CWE-")
                    .unwrap_or(id.trim())
                    .parse()
                    .ok()
            })
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let json = serde_json::to_string(&ids).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT c.id) FROM cve c JOIN cve_cwe w ON w.cve_db_id=c.id WHERE w.cwe_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0)").bind(json).bind(include).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let prefix = format!("{}%", prefix.trim());
        let include = include_rejected(scope);
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM cve WHERE cve_id LIKE ? AND (? OR state=0)",
                    )
                    .bind(prefix)
                    .bind(include)
                    .fetch_one(c)
                    .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn find_cve_references(
        &self,
        cve_id: &str,
    ) -> Result<Vec<CveReference>, sqlx::Error> {
        let Some(detail) = self.cve_detail(cve_id).await? else {
            return Ok(Vec::new());
        };
        Ok(detail
            .references
            .into_iter()
            .map(|row| CveReference {
                url: Some(row.url),
                name: row.name,
                tags: serde_json::from_str(&row.tags_json).unwrap_or_default(),
            })
            .collect())
    }
}
