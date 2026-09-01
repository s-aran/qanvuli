use super::ssvc::replace_ssvc_for_cves;
use super::*;

impl SqlxDatabase {
    pub async fn find_cve_summary_with_detail_with_state_scope(
        &self,
        cve_id: &str,
        state_scope: CveStateScope,
    ) -> Result<Option<CveSummaryWithDetail>, sqlx::Error> {
        let row = self.cve_summary_with_detail(cve_id).await?;
        Ok(row
            .filter(|row| state_scope == CveStateScope::IncludeRejected || row.summary.state == 0)
            .map(CveSummaryWithDetail::from))
    }

    /// Closes the writer before database replacement.
    pub async fn find_cve_summary(
        &self,
        cve_id: &str,
    ) -> Result<Option<SqlxCveSummary>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE cve_id=?")
                .bind(cve_id).fetch_optional(connection).await
        })).await
    }

    /// Returns the original provider JSON for a CVE.
    pub async fn cve_raw_json(&self, cve_id: &str) -> Result<Option<String>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT raw_json FROM cve WHERE cve_id=?")
                        .bind(cve_id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Searches CVE identifiers by prefix.
    pub async fn search_cves_by_id_prefix(
        &self,
        prefix: &str,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let prefix = format!("{}%", prefix.trim());
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE cve_id LIKE ? AND (? OR state=0) ORDER BY cve_id LIMIT ? OFFSET ?")
                .bind(prefix).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches the stable external-content CVE FTS index and returns public identifiers.
    pub async fn search_cves(
        &self,
        query: &str,
        include_rejected: bool,
        limit: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts AS fts JOIN cve AS c ON c.cve_id=fts.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.updated_at DESC LIMIT ?")
                .bind(query).bind(include_rejected).bind(limit.max(1)).fetch_all(connection).await
        })).await
    }

    /// Searches only the normalized CVE reference projection, not title or description text.
    pub async fn search_cves_by_reference_text(
        &self,
        query: &str,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let query = format!("reference_text : ({query})");
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts AS fts JOIN cve AS c ON c.cve_id=fts.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.updated_at DESC LIMIT ? OFFSET ?")
                .bind(query).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Lists recent CVEs using canonical UTC timestamps.
    pub async fn recent_cves(
        &self,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE (? OR state=0) ORDER BY updated_at DESC, cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches CVEs by CWE IDs using a bound JSON array, not dynamically generated SQL.
    pub async fn search_cves_by_cwes(
        &self,
        cwe_ids: &[String],
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let ids = cwe_ids
            .iter()
            .filter_map(|id| {
                id.trim()
                    .strip_prefix("CWE-")
                    .unwrap_or(id.trim())
                    .parse::<i64>()
                    .ok()
            })
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = serde_json::to_string(&ids)
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CWE IDs: {error}")))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_cwe ON cve_cwe.cve_db_id=c.id WHERE cve_cwe.cwe_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0) ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(ids).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches the normalized CWE catalog by numeric ID or description text.
    pub async fn search_cwes(
        &self,
        query: Option<&str>,
        limit: i64,
    ) -> Result<Vec<SqlxCwe>, sqlx::Error> {
        let query = query.map(str::trim).filter(|query| !query.is_empty());
        let id = query.and_then(|query| {
            query
                .trim_start_matches("CWE-")
                .trim_start_matches("CWE")
                .parse::<i64>()
                .ok()
        });
        let text = if id.is_none() {
            query.map(|query| format!("%{query}%"))
        } else {
            None
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT id, description FROM cwe WHERE (? IS NULL OR id=?) AND (? IS NULL OR description LIKE ?) ORDER BY id LIMIT ?")
                .bind(id).bind(id).bind(&text).bind(&text).bind(limit.max(1)).fetch_all(connection).await
        })).await
    }

    /// Looks up a CWE by its external numeric identifier.
    pub async fn find_cwe(&self, id: i64) -> Result<Option<SqlxCwe>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT id, description FROM cwe WHERE id=?")
                        .bind(id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Searches normalized affected vendor/product/package fields with bound LIKE predicates.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_cves_by_affected(
        &self,
        vendor: Option<String>,
        product: Option<String>,
        exact: bool,
        exclude_wordpress_collection: bool,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let vendor = vendor.map(|value| if exact { value } else { format!("%{value}%") });
        let product_rank = product.clone();
        let product = product.map(|value| if exact { value } else { format!("%{value}%") });
        let product_fts = product_rank
            .as_deref()
            .and_then(fts_query)
            .map(|query| format!("product_text : ({query})"));
        self.writer.with_connection(|connection| Box::pin(async move {
            if let Some(product_fts) = product_fts {
                // Exact and word-boundary product matches always sort ahead of plain substring
                // matches. The existing affected FTS projection can therefore produce the page
                // without scanning every affected row when it contains enough high-rank matches.
                let fast: Vec<SqlxCveSummary> = sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_affected_summary_fts AS fts CROSS JOIN cve AS c ON c.cve_id=fts.cve_id JOIN cve_affected AS affected ON affected.cve_db_id=c.id WHERE cve_affected_summary_fts MATCH ? AND (? OR c.state=0) AND (? OR affected.collection_url NOT LIKE '%wordpress.org%') AND (? IS NULL OR CASE WHEN ? THEN affected.vendor=? ELSE affected.vendor LIKE ? END) AND (? IS NULL OR CASE WHEN ? THEN (affected.product=? OR affected.package_name=?) ELSE (affected.product LIKE ? OR affected.package_name LIKE ?) END) GROUP BY c.id HAVING MIN(CASE WHEN ? IS NULL THEN 0 WHEN affected.product=? OR affected.package_name=? THEN 0 WHEN affected.product LIKE ? || ' %' OR affected.product LIKE '% ' || ? OR affected.product LIKE ? || '-%' OR affected.product LIKE '%-' || ? OR affected.package_name LIKE ? || ' %' OR affected.package_name LIKE '% ' || ? OR affected.package_name LIKE ? || '-%' OR affected.package_name LIKE '%-' || ? THEN 1 ELSE 2 END) < 2 ORDER BY MIN(CASE WHEN ? IS NULL THEN 0 WHEN affected.product=? OR affected.package_name=? THEN 0 WHEN affected.product LIKE ? || ' %' OR affected.product LIKE '% ' || ? OR affected.product LIKE ? || '-%' OR affected.product LIKE '%-' || ? OR affected.package_name LIKE ? || ' %' OR affected.package_name LIKE '% ' || ? OR affected.package_name LIKE ? || '-%' OR affected.package_name LIKE '%-' || ? THEN 1 ELSE 2 END), c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                    .bind(product_fts)
                    .bind(include_rejected)
                    .bind(!exclude_wordpress_collection)
                    .bind(&vendor).bind(exact).bind(&vendor).bind(&vendor)
                    .bind(&product).bind(exact).bind(&product).bind(&product).bind(&product).bind(&product)
                    .bind(&product_rank).bind(&product_rank).bind(&product_rank)
                    .bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank)
                    .bind(&product_rank).bind(&product_rank).bind(&product_rank)
                    .bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank)
                    .bind(limit.max(1)).bind(offset.max(0)).fetch_all(&mut *connection).await?;
                if fast.len() >= limit.max(1) as usize {
                    return Ok(fast);
                }
            }
            // SQLite otherwise prefers the CVE ordering side of this join and performs an
            // indexed affected-row lookup for every CVE. CROSS JOIN fixes the loop order so the
            // affected projection is scanned once and only matching CVEs are loaded and sorted.
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_affected AS affected CROSS JOIN cve AS c ON c.id=affected.cve_db_id WHERE (? OR c.state=0) AND (? OR affected.collection_url NOT LIKE '%wordpress.org%') AND (? IS NULL OR CASE WHEN ? THEN affected.vendor=? ELSE affected.vendor LIKE ? END) AND (? IS NULL OR CASE WHEN ? THEN (affected.product=? OR affected.package_name=?) ELSE (affected.product LIKE ? OR affected.package_name LIKE ?) END) GROUP BY c.id ORDER BY MIN(CASE WHEN ? IS NULL THEN 0 WHEN affected.product=? OR affected.package_name=? THEN 0 WHEN affected.product LIKE ? || ' %' OR affected.product LIKE '% ' || ? OR affected.product LIKE ? || '-%' OR affected.product LIKE '%-' || ? OR affected.package_name LIKE ? || ' %' OR affected.package_name LIKE '% ' || ? OR affected.package_name LIKE ? || '-%' OR affected.package_name LIKE '%-' || ? THEN 1 ELSE 2 END), c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(!exclude_wordpress_collection)
                .bind(&vendor).bind(exact).bind(&vendor).bind(&vendor)
                .bind(&product).bind(exact).bind(&product).bind(&product).bind(&product).bind(&product)
                .bind(&product_rank).bind(&product_rank).bind(&product_rank)
                .bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches normalized CVSS fields with optional score, severity, and version filters.
    pub async fn search_cves_by_cvss(
        &self,
        options: SqlxCvssSearch,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_cvss AS cvss ON cvss.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR cvss.base_score >= ?) AND (? IS NULL OR cvss.base_score <= ?) AND (? IS NULL OR UPPER(cvss.base_severity)=UPPER(?)) AND (? IS NULL OR cvss.version=?) GROUP BY c.id ORDER BY MAX(cvss.base_score) DESC, c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(options.min_score).bind(options.min_score)
                .bind(options.max_score).bind(options.max_score)
                .bind(&options.severity).bind(&options.severity)
                .bind(&options.version).bind(&options.version)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches canonical UTC published/updated timestamps.
    pub async fn search_cves_by_dates(
        &self,
        published_since: Option<String>,
        updated_since: Option<String>,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE (? OR state=0) AND (? IS NULL OR published_at >= ?) AND (? IS NULL OR updated_at >= ?) ORDER BY updated_at DESC, cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&published_since).bind(&published_since)
                .bind(&updated_since).bind(&updated_since)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Runs a combined normalized search in one query while preserving AND semantics between
    /// supplied filters.
    pub async fn search_cves_advanced(
        &self,
        filters: SqlxCveSearch,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.search_cves_advanced_with_kev(filters, include_rejected, false, limit, offset)
            .await
    }

    pub(crate) async fn search_cves_advanced_with_kev(
        &self,
        filters: SqlxCveSearch,
        include_rejected: bool,
        kev_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let cwe_ids = filters
            .cwe_ids
            .iter()
            .filter_map(|value| prefixed_numeric_id(value, "CWE"))
            .collect::<Vec<_>>();
        let cwe_ids = (!filters.cwe_ids.is_empty())
            .then(|| serde_json::to_string(&cwe_ids))
            .transpose()
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CWE IDs: {error}")))?;
        let capec_ids = filters
            .capec_ids
            .iter()
            .filter_map(|value| prefixed_numeric_id(value, "CAPEC"))
            .collect::<Vec<_>>();
        let capec_ids = (!filters.capec_ids.is_empty())
            .then(|| serde_json::to_string(&capec_ids))
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("failed to encode CAPEC IDs: {error}"))
            })?;
        let text = filters.text.as_deref().and_then(fts_query);
        let unfiltered = text.is_none()
            && filters.cve_id_prefix.is_none()
            && filters.cwe_ids.is_empty()
            && filters.capec_ids.is_empty()
            && filters.vendor_like.is_none()
            && filters.product_like.is_none()
            && filters.vendor_exact.is_none()
            && filters.product_exact.is_none()
            && filters.cvss.min_score.is_none()
            && filters.cvss.max_score.is_none()
            && filters.cvss.severity.is_none()
            && filters.cvss.version.is_none()
            && filters.ssvc.is_empty()
            && filters.published_since.is_none()
            && filters.published_until.is_none()
            && filters.updated_since.is_none()
            && filters.updated_until.is_none()
            && !kev_only;
        let uses_published_order = matches!(
            filters.sort_order,
            CveSummarySortOrder::PublishedAsc
                | CveSummarySortOrder::PublishedDesc
                | CveSummarySortOrder::RelationRankAsc
                | CveSummarySortOrder::RelationRankDesc
        );
        let use_published_index = if uses_published_order && unfiltered {
            true
        } else if uses_published_order && let Some(text) = text.clone() {
            let candidates: i64 = self.writer.with_connection(|connection| Box::pin(async move {
                // Only the threshold decision matters here. Counting every FTS hit makes common
                // terms needlessly scan the complete posting list before the real page query.
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM (SELECT 1 FROM cve_summary_fts WHERE cve_summary_fts MATCH ? LIMIT ?)",
                )
                .bind(text)
                .bind(FTS_PUBLISHED_INDEX_MIN_CANDIDATES)
                .fetch_one(connection)
                .await
            })).await?;
            candidates >= FTS_PUBLISHED_INDEX_MIN_CANDIDATES
        } else {
            false
        };
        let use_updated_index = unfiltered
            && matches!(
                filters.sort_order,
                CveSummarySortOrder::UpdatedAsc | CveSummarySortOrder::UpdatedDesc
            );
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut query = QueryBuilder::<Sqlite>::new(if use_published_index {
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c INDEXED BY idx_cve_published_at_cve_id WHERE 1=1"
            } else if use_updated_index {
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c INDEXED BY idx_cve_updated_at_cve_id WHERE 1=1"
            } else {
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c WHERE 1=1"
            });
            if !include_rejected { query.push(" AND c.state=0"); }
            if let Some(value) = filters.published_since { query.push(" AND c.published_at >= ").push_bind(value); }
            if let Some(value) = filters.published_until { query.push(" AND c.published_at <= ").push_bind(value); }
            if let Some(value) = filters.updated_since { query.push(" AND c.updated_at >= ").push_bind(value); }
            if let Some(value) = filters.updated_until { query.push(" AND c.updated_at <= ").push_bind(value); }
            if let Some(value) = filters.cve_id_prefix { query.push(" AND c.cve_id LIKE ").push_bind(format!("{}%", value.trim())); }
            if let Some(value) = text {
                query.push(" AND c.cve_id IN (SELECT cve_id FROM cve_summary_fts WHERE cve_summary_fts MATCH ").push_bind(value).push(")");
            }
            if let Some(value) = cwe_ids {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cwe WHERE cve_cwe.cve_db_id=c.id AND cve_cwe.cwe_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
            }
            if let Some(value) = capec_ids {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cwe JOIN capec_cwe ON capec_cwe.cwe_id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=c.id AND capec_cwe.capec_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
            }
            if kev_only {
                query.push(" AND EXISTS (SELECT 1 FROM kev_entries WHERE kev_entries.cve_id=c.cve_id)");
            }
            if !filters.ssvc.is_empty() {
                query.push(" AND EXISTS (SELECT 1 FROM ssvc_assessments AS ssvc WHERE ssvc.cve_id=c.cve_id");
                if let Some(value) = filters.ssvc.exploitation { query.push(" AND ssvc.exploitation=").push_bind(value.as_str()); }
                if let Some(value) = filters.ssvc.automatable { query.push(" AND ssvc.automatable=").push_bind(value.as_str()); }
                if let Some(value) = filters.ssvc.technical_impact { query.push(" AND ssvc.technical_impact=").push_bind(value.as_str()); }
                query.push(")");
            }
            let has_affected = filters.vendor_like.is_some() || filters.product_like.is_some() || filters.vendor_exact.is_some() || filters.product_exact.is_some();
            if has_affected {
                query.push(" AND EXISTS (SELECT 1 FROM cve_affected AS affected WHERE affected.cve_db_id=c.id");
                if let Some(value) = filters.vendor_like { query.push(" AND affected.vendor LIKE ").push_bind(value); }
                if let Some(value) = filters.product_like { query.push(" AND affected.product LIKE ").push_bind(value); }
                if let Some(value) = filters.vendor_exact { query.push(" AND affected.vendor=").push_bind(value); }
                if let Some(value) = filters.product_exact { query.push(" AND affected.product=").push_bind(value); }
                query.push(")");
            }
            let has_cvss = filters.cvss.min_score.is_some() || filters.cvss.max_score.is_some() || filters.cvss.severity.is_some() || filters.cvss.version.is_some();
            if has_cvss {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cvss AS cvss WHERE cvss.cve_db_id=c.id");
                if let Some(value) = filters.cvss.min_score { query.push(" AND cvss.base_score >= ").push_bind(value); }
                if let Some(value) = filters.cvss.max_score { query.push(" AND cvss.base_score <= ").push_bind(value); }
                if let Some(value) = filters.cvss.severity { query.push(" AND lower(cvss.base_severity)=lower(").push_bind(value).push(")"); }
                if let Some(value) = filters.cvss.version { query.push(" AND cvss.version=").push_bind(value); }
                query.push(")");
            }
            match filters.sort_order {
                CveSummarySortOrder::PublishedAsc if use_published_index => query.push(" ORDER BY c.published_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::PublishedDesc if use_published_index => query.push(" ORDER BY c.published_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::UpdatedAsc if use_updated_index => query.push(" ORDER BY c.updated_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::UpdatedDesc if use_updated_index => query.push(" ORDER BY c.updated_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::PublishedAsc => query.push(" ORDER BY c.published_at ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::PublishedDesc => query.push(" ORDER BY c.published_at DESC, ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::UpdatedAsc => query.push(" ORDER BY c.updated_at ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::UpdatedDesc => query.push(" ORDER BY c.updated_at DESC, ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::CveIdAsc => query.push(" ORDER BY ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::CveIdDesc => query.push(" ORDER BY ").push(CVE_ID_DESC_KEYS),
                // Relation rank is only meaningful for identifier-graph searches. Keep the
                // normal CVE list deterministic when no graph ranking is available.
                CveSummarySortOrder::RelationRankAsc if use_published_index => query.push(" ORDER BY c.published_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::RelationRankDesc if use_published_index => query.push(" ORDER BY c.published_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::RelationRankAsc => query.push(" ORDER BY c.published_at ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::RelationRankDesc => query.push(" ORDER BY c.published_at DESC, ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::ScoreAsc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::ScoreDesc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) DESC, ").push(CVE_ID_DESC_KEYS),
            };
            query.push(" LIMIT ").push_bind(limit.max(1)).push(" OFFSET ").push_bind(offset.max(0));
            query.build_query_as().fetch_all(connection).await
        })).await
    }

    pub(crate) async fn count_cves_advanced_with_kev(
        &self,
        filters: SqlxCveSearch,
        include_rejected: bool,
        kev_only: bool,
    ) -> Result<u64, sqlx::Error> {
        let cwe_ids = filters
            .cwe_ids
            .iter()
            .filter_map(|value| prefixed_numeric_id(value, "CWE"))
            .collect::<Vec<_>>();
        let cwe_ids = (!filters.cwe_ids.is_empty())
            .then(|| serde_json::to_string(&cwe_ids))
            .transpose()
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CWE IDs: {error}")))?;
        let capec_ids = filters
            .capec_ids
            .iter()
            .filter_map(|value| prefixed_numeric_id(value, "CAPEC"))
            .collect::<Vec<_>>();
        let capec_ids = (!filters.capec_ids.is_empty())
            .then(|| serde_json::to_string(&capec_ids))
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("failed to encode CAPEC IDs: {error}"))
            })?;
        let text = filters.text.as_deref().and_then(fts_query);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut query =
                        QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM cve AS c WHERE 1=1");
                    if !include_rejected {
                        query.push(" AND c.state=0");
                    }
                    if let Some(value) = filters.published_since {
                        query.push(" AND c.published_at >= ").push_bind(value);
                    }
                    if let Some(value) = filters.published_until {
                        query.push(" AND c.published_at <= ").push_bind(value);
                    }
                    if let Some(value) = filters.updated_since {
                        query.push(" AND c.updated_at >= ").push_bind(value);
                    }
                    if let Some(value) = filters.updated_until {
                        query.push(" AND c.updated_at <= ").push_bind(value);
                    }
                    if let Some(value) = filters.cve_id_prefix {
                        query
                            .push(" AND c.cve_id LIKE ")
                            .push_bind(format!("{}%", value.trim()));
                    }
                    if let Some(value) = text {
                        query.push(" AND c.cve_id IN (SELECT cve_id FROM cve_summary_fts WHERE cve_summary_fts MATCH ").push_bind(value).push(")");
                    }
                    if let Some(value) = cwe_ids {
                        query.push(" AND EXISTS (SELECT 1 FROM cve_cwe WHERE cve_cwe.cve_db_id=c.id AND cve_cwe.cwe_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
                    }
                    if let Some(value) = capec_ids {
                        query.push(" AND EXISTS (SELECT 1 FROM cve_cwe JOIN capec_cwe ON capec_cwe.cwe_id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=c.id AND capec_cwe.capec_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
                    }
                    if kev_only {
                        query.push(" AND EXISTS (SELECT 1 FROM kev_entries WHERE kev_entries.cve_id=c.cve_id)");
                    }
                    if !filters.ssvc.is_empty() {
                        query.push(" AND EXISTS (SELECT 1 FROM ssvc_assessments AS ssvc WHERE ssvc.cve_id=c.cve_id");
                        if let Some(value) = filters.ssvc.exploitation {
                            query.push(" AND ssvc.exploitation=").push_bind(value.as_str());
                        }
                        if let Some(value) = filters.ssvc.automatable {
                            query.push(" AND ssvc.automatable=").push_bind(value.as_str());
                        }
                        if let Some(value) = filters.ssvc.technical_impact {
                            query.push(" AND ssvc.technical_impact=").push_bind(value.as_str());
                        }
                        query.push(")");
                    }
                    let has_affected = filters.vendor_like.is_some()
                        || filters.product_like.is_some()
                        || filters.vendor_exact.is_some()
                        || filters.product_exact.is_some();
                    if has_affected {
                        query.push(" AND EXISTS (SELECT 1 FROM cve_affected AS affected WHERE affected.cve_db_id=c.id");
                        if let Some(value) = filters.vendor_like {
                            query.push(" AND affected.vendor LIKE ").push_bind(value);
                        }
                        if let Some(value) = filters.product_like {
                            query.push(" AND affected.product LIKE ").push_bind(value);
                        }
                        if let Some(value) = filters.vendor_exact {
                            query.push(" AND affected.vendor=").push_bind(value);
                        }
                        if let Some(value) = filters.product_exact {
                            query.push(" AND affected.product=").push_bind(value);
                        }
                        query.push(")");
                    }
                    let has_cvss = filters.cvss.min_score.is_some()
                        || filters.cvss.max_score.is_some()
                        || filters.cvss.severity.is_some()
                        || filters.cvss.version.is_some();
                    if has_cvss {
                        query.push(" AND EXISTS (SELECT 1 FROM cve_cvss AS cvss WHERE cvss.cve_db_id=c.id");
                        if let Some(value) = filters.cvss.min_score {
                            query.push(" AND cvss.base_score >= ").push_bind(value);
                        }
                        if let Some(value) = filters.cvss.max_score {
                            query.push(" AND cvss.base_score <= ").push_bind(value);
                        }
                        if let Some(value) = filters.cvss.severity {
                            query.push(" AND lower(cvss.base_severity)=lower(").push_bind(value).push(")");
                        }
                        if let Some(value) = filters.cvss.version {
                            query.push(" AND cvss.version=").push_bind(value);
                        }
                        query.push(")");
                    }
                    let row = query.build().fetch_one(connection).await?;
                    let count = row.try_get::<i64, _>(0)?;
                    Ok(count.max(0) as u64)
                })
            })
            .await
    }

    /// Loads a page from an explicit CVE identifier set using the same ordering as searches.
    pub(crate) async fn cves_by_ids_sorted(
        &self,
        ids: &[String],
        scope: CveStateScope,
        sort_order: CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let include_rejected = matches!(scope, CveStateScope::IncludeRejected);
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut query = QueryBuilder::<Sqlite>::new(
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM json_each(",
            );
            query.push_bind(ids_json).push(") AS requested JOIN cve AS c ON c.cve_id=requested.value WHERE ")
                .push_bind(include_rejected).push(" OR c.state=0");
            match sort_order {
                CveSummarySortOrder::PublishedAsc => query.push(" ORDER BY c.published_at ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::PublishedDesc => query.push(" ORDER BY c.published_at DESC, ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::UpdatedAsc => query.push(" ORDER BY c.updated_at ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::UpdatedDesc => query.push(" ORDER BY c.updated_at DESC, ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::CveIdAsc => query.push(" ORDER BY ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::CveIdDesc => query.push(" ORDER BY ").push(CVE_ID_DESC_KEYS),
                CveSummarySortOrder::RelationRankAsc => query.push(" ORDER BY CAST(requested.key AS INTEGER) ASC"),
                CveSummarySortOrder::RelationRankDesc => query.push(" ORDER BY CAST(requested.key AS INTEGER) DESC"),
                CveSummarySortOrder::ScoreAsc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) ASC, ").push(CVE_ID_ASC_KEYS),
                CveSummarySortOrder::ScoreDesc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) DESC, ").push(CVE_ID_DESC_KEYS),
            };
            query.push(" LIMIT ").push_bind(limit.max(1) as i64).push(" OFFSET ").push_bind(offset as i64);
            query.build_query_as().fetch_all(connection).await
        })).await
    }

    /// Loads full normalized detail in batches per CVE, preserving source ordering in each detail.
    pub async fn cve_detail(&self, cve_id: &str) -> Result<Option<SqlxCveDetail>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let Some(id): Option<i64> = sqlx::query_scalar("SELECT id FROM cve WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await? else { return Ok(None); };
            let cvss = sqlx::query_as("SELECT version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let cwes = sqlx::query_as("SELECT cwe.id, cwe.description FROM cve_cwe JOIN cwe ON cwe.id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=? ORDER BY cwe.id").bind(id).fetch_all(&mut *connection).await?;
            let raw_json: String = sqlx::query_scalar("SELECT raw_json FROM cve WHERE id=?").bind(id).fetch_one(&mut *connection).await?;
            let affected_descriptions = cve_affected_descriptions(&raw_json);
            let affected_rows: Vec<AffectedRow> = sqlx::query_as("SELECT id, vendor, product, package_name, raw_json FROM cve_affected WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let mut affected = Vec::with_capacity(affected_rows.len());
            for (affected_index, (_affected_id, vendor, product, package_name, raw_json)) in affected_rows.into_iter().enumerate() {
                let versions = cve_stored_versions(&raw_json)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|version| SqlxAffectedVersion {
                        version: version.version,
                        status: version.status,
                        version_type: version.version_type,
                        less_than: version.less_than,
                        less_than_or_equal: version.less_than_or_equal,
                    })
                    .collect();
                let description = affected_descriptions.get(affected_index).cloned().flatten();
                affected.push(SqlxAffected { vendor, product, package_name, description, versions });
            }
            let references = serde_json::from_str::<Value>(&raw_json)
                .map(|value| cve_references(value.pointer("/containers/cna"), value.pointer("/containers/adp")))
                .unwrap_or_default();
            let epss = sqlx::query_as("SELECT epss, percentile, score_date, model_version FROM epss_current WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let kev = sqlx::query_as("SELECT vendor_project, product, vulnerability_name, COALESCE(date_added, '') AS date_added, due_date FROM kev_entries WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let ssvc_rows: Vec<super::ssvc::SsvcRow> = sqlx::query_as("SELECT cve_id, provider, role, version, assessed_at, exploitation, automatable, technical_impact, fetched_at FROM ssvc_assessments WHERE cve_id=? ORDER BY provider, role").bind(&cve_id).fetch_all(&mut *connection).await?;
            let ssvc = ssvc_rows.into_iter().map(super::ssvc::ssvc_info).collect::<Result<Vec<_>, _>>()?;
            let osv_advisories = sqlx::query_as("SELECT advisory.osv_id, advisory.published_at, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=advisory.osv_id) AS package_summary FROM osv_aliases AS alias JOIN osv_advisories AS advisory ON advisory.osv_id=alias.osv_id WHERE alias.alias_id=? ORDER BY advisory.modified_at DESC, advisory.osv_id").bind(&cve_id).fetch_all(&mut *connection).await?;
            Ok(Some(SqlxCveDetail { cvss, cwes, affected, references, epss, kev, ssvc, osv_advisories }))
        })).await
    }

    pub async fn cve_summary_with_detail(
        &self,
        cve_id: &str,
    ) -> Result<Option<SqlxCveSummaryWithDetail>, sqlx::Error> {
        let Some(summary) = self.find_cve_summary(cve_id).await? else {
            return Ok(None);
        };
        let detail = self
            .cve_detail(cve_id)
            .await?
            .expect("summary and detail share the CVE parent row");
        Ok(Some(SqlxCveSummaryWithDetail { summary, detail }))
    }

    /// Loads normalized details in a fixed number of set-based queries and restores caller order.
    pub async fn cve_details(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<Option<SqlxCveDetail>>, sqlx::Error> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = cve_ids.to_vec();
        let requested_json = serde_json::to_string(&requested)
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CVE IDs: {error}")))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let parents: Vec<(i64, String, String)> = sqlx::query_as(
                "SELECT id, cve_id, raw_json FROM cve WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            let parent_ids = parents.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
            let parent_ids_json = serde_json::to_string(&parent_ids)
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CVE row IDs: {error}")))?;
            let mut details = BTreeMap::<i64, SqlxCveDetail>::new();
            let mut ids_by_cve = BTreeMap::<String, i64>::new();
            let mut affected_descriptions_by_id = BTreeMap::<i64, Vec<Option<String>>>::new();
            for (id, cve_id, raw_json) in parents {
                let references = serde_json::from_str::<Value>(&raw_json)
                    .map(|value| cve_references(value.pointer("/containers/cna"), value.pointer("/containers/adp")))
                    .unwrap_or_default();
                details.insert(id, SqlxCveDetail { references, ..SqlxCveDetail::default() });
                affected_descriptions_by_id.insert(id, cve_affected_descriptions(&raw_json));
                ids_by_cve.insert(cve_id, id);
            }

            let cvss_rows: Vec<BatchedCvssRow> =
                sqlx::query_as("SELECT cve_db_id, version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY id")
                    .bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            for (id, version, base_score, base_severity, vector_string, source) in cvss_rows {
                if let Some(detail) = details.get_mut(&id) {
                    detail.cvss.push(SqlxCvss { version, base_score, base_severity, vector_string, source });
                }
            }
            let cwe_rows: Vec<(i64, i64, Option<String>)> = sqlx::query_as(
                "SELECT link.cve_db_id, cwe.id, cwe.description FROM cve_cwe link JOIN cwe ON cwe.id=link.cwe_id WHERE link.cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cwe.id",
            ).bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            for (id, cwe_id, description) in cwe_rows {
                if let Some(detail) = details.get_mut(&id) {
                    detail.cwes.push(SqlxCwe { id: cwe_id, description });
                }
            }
            let affected_rows: Vec<BatchedAffectedRow> =
                sqlx::query_as("SELECT cve_db_id, vendor, product, package_name, raw_json FROM cve_affected WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY id")
                    .bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            let mut affected_indexes = BTreeMap::<i64, usize>::new();
            for (id, vendor, product, package_name, raw_json) in affected_rows {
                let versions = cve_stored_versions(&raw_json)
                    .unwrap_or_default().into_iter()
                    .map(|version| SqlxAffectedVersion {
                        version: version.version,
                        status: version.status,
                        version_type: version.version_type,
                        less_than: version.less_than,
                        less_than_or_equal: version.less_than_or_equal,
                    })
                    .collect();
                if let Some(detail) = details.get_mut(&id) {
                    let affected_index = affected_indexes.entry(id).or_default();
                    let description = affected_descriptions_by_id
                        .get(&id)
                        .and_then(|descriptions| descriptions.get(*affected_index))
                        .cloned()
                        .flatten();
                    *affected_index += 1;
                    detail.affected.push(SqlxAffected { vendor, product, package_name, description, versions });
                }
            }
            let epss_rows: Vec<BatchedEpssRow> = sqlx::query_as(
                "SELECT cve_id, epss, percentile, score_date, model_version FROM epss_current WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, epss, percentile, score_date, model_version) in epss_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").epss = Some(SqlxEpss { epss, percentile, score_date, model_version });
                }
            }
            let kev_rows: Vec<BatchedKevRow> = sqlx::query_as(
                "SELECT cve_id, vendor_project, product, vulnerability_name, COALESCE(date_added, ''), due_date FROM kev_entries WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, vendor_project, product, vulnerability_name, date_added, due_date) in kev_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").kev = Some(SqlxKev { vendor_project, product, vulnerability_name, date_added, due_date });
                }
            }
            let ssvc_rows: Vec<super::ssvc::SsvcRow> = sqlx::query_as(
                "SELECT cve_id, provider, role, version, assessed_at, exploitation, automatable, technical_impact, fetched_at FROM ssvc_assessments WHERE cve_id IN (SELECT value FROM json_each(?)) ORDER BY provider, role",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for row in ssvc_rows {
                let cve_id = row.0.clone();
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").ssvc.push(super::ssvc::ssvc_info(row)?);
                }
            }
            let osv_rows: Vec<BatchedOsvRow> = sqlx::query_as(
                "SELECT alias.alias_id, advisory.osv_id, advisory.published_at, COALESCE(advisory.modified_at, ''), advisory.summary, advisory.details, advisory.withdrawn_at FROM osv_aliases alias JOIN osv_advisories advisory ON advisory.osv_id=alias.osv_id WHERE alias.alias_id IN (SELECT value FROM json_each(?)) ORDER BY advisory.modified_at DESC, advisory.osv_id",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, osv_id, published_at, modified_at, summary, osv_details, withdrawn_at) in osv_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").osv_advisories.push(SqlxOsvSummary { osv_id, published_at, modified_at, summary, details: osv_details, withdrawn_at, package_summary: None });
                }
            }
            Ok(requested.into_iter().map(|cve_id| {
                ids_by_cve.get(&cve_id).and_then(|id| details.get(id)).cloned()
            }).collect())
        })).await
    }

    pub async fn database_status(&self) -> Result<SqlxDatabaseStatus, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM cve) AS cve_count, (SELECT COUNT(*) FROM osv_advisories) AS osv_count, (SELECT COUNT(*) FROM cwe) AS cwe_count, (SELECT COUNT(*) FROM capec) AS capec_count, (SELECT COUNT(*) FROM capec_category) AS capec_category_count, (SELECT COUNT(*) FROM capec_view) AS capec_view_count, (SELECT COUNT(*) FROM capec_external_reference) AS capec_reference_count, (SELECT COUNT(*) FROM cve_affected) AS affected_count, (SELECT COUNT(*) FROM cve_cvss) AS cvss_count, (SELECT MAX(updated_at) FROM cve) AS latest_cve_updated_at")
                .fetch_one(connection).await
        })).await
    }

    /// Returns the newest CVE update timestamp without scanning unrelated table counts.
    /// The TUI uses this lightweight value for its status line on startup and after update.
    pub async fn latest_cve_updated_at(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT updated_at FROM cve ORDER BY updated_at DESC, cve_id DESC LIMIT 1",
                    )
                    .fetch_optional(connection)
                    .await
                })
            })
            .await
    }

    pub async fn kev_entries(
        &self,
        cve_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxKevEntry>, sqlx::Error> {
        let cve_id = cve_id.map(str::to_owned);
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT kev.cve_id, kev.vendor_project, kev.product, kev.vulnerability_name, COALESCE(kev.date_added, '') AS date_added, kev.due_date FROM kev_entries AS kev WHERE (? IS NULL OR kev.cve_id=?) ORDER BY kev.date_added DESC, kev.cve_id LIMIT ? OFFSET ?")
                .bind(&cve_id).bind(&cve_id).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    pub async fn search_epss_risk(
        &self,
        min_score: Option<f64>,
        min_percentile: Option<f64>,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxEpssRisk>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve.cve_id, epss.epss, epss.percentile, EXISTS(SELECT 1 FROM kev_entries WHERE kev_entries.cve_id=cve.cve_id) AS kev_listed FROM epss_current AS epss JOIN cve ON cve.cve_id=epss.cve_id WHERE (? OR cve.state=0) AND (? IS NULL OR epss.epss>=?) AND (? IS NULL OR epss.percentile>=?) ORDER BY epss.epss DESC, epss.percentile DESC, cve.cve_id LIMIT ? OFFSET ?")
                .bind(include_rejected).bind(min_score).bind(min_score).bind(min_percentile).bind(min_percentile).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    pub async fn source_sync_states(&self) -> Result<Vec<SqlxSourceSyncState>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT source, last_attempt_at, last_success_at, status, last_cursor, error_message FROM source_sync_state ORDER BY source")
                .fetch_all(connection).await
        })).await
    }

    /// Returns the cursor from the last successfully committed OSV synchronization.
    pub async fn osv_sync_cursor(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT last_cursor FROM source_sync_state WHERE source='OSV' AND status='success'")
                .fetch_optional(connection).await.map(Option::flatten)
        })).await
    }

    pub async fn metadata_value(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let key = key.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT value FROM app_metadata WHERE key=?")
                        .bind(key)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Resolves alias-equivalent identifiers transitively.
    ///
    /// Upstream and related edges do not establish vulnerability identity.
    pub async fn set_metadata_value(&self, key: &str, value: &str) -> Result<(), sqlx::Error> {
        let key = key.to_owned();
        let value = value.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at")
                .bind(key).bind(value).bind(chrono::Utc::now().to_rfc3339()).execute(connection).await?;
            Ok(())
        })).await
    }

    /// Replaces CWE metadata and `ChildOf` relationships.
    ///
    /// Catalog data replaces placeholder rows created during CVE import.
    pub async fn upsert_cwe_catalog(
        &self,
        catalog: &WeaknessCatalog,
    ) -> Result<usize, sqlx::Error> {
        let mut entries = Vec::new();
        if let Some(weaknesses) = &catalog.weaknesses {
            entries.extend(weaknesses.weakness.iter().map(|weakness| {
                let parent_id = weakness.related_weaknesses.as_ref().and_then(|relations| {
                    relations
                        .related_weakness
                        .iter()
                        .find(|relation| matches!(relation.nature, RelatedNature::ChildOf))
                        .map(|relation| relation.cwe_id)
                });
                (
                    weakness.id,
                    weakness.description.clone(),
                    weakness.status.as_ref().to_owned(),
                    parent_id,
                )
            }));
        }
        if let Some(categories) = &catalog.categories {
            entries.extend(categories.category.iter().map(|category| {
                (
                    category.id,
                    category.name.clone(),
                    category.status.as_ref().to_owned(),
                    None,
                )
            }));
        }
        if let Some(views) = &catalog.views {
            entries.extend(views.view.iter().map(|view| {
                (
                    view.id,
                    view.name.clone(),
                    view.status.as_ref().to_owned(),
                    None,
                )
            }));
        }
        let count = entries.len();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    for chunk in entries.chunks(2_000) {
                        let mut query = QueryBuilder::<Sqlite>::new(
                            "INSERT INTO cwe (id, description, status, parent_id) ",
                        );
                        query.push_values(chunk, |mut row, (id, description, status, parent_id)| {
                            row.push_bind(id)
                                .push_bind(description)
                                .push_bind(status)
                                .push_bind(parent_id);
                        });
                        query.push(" ON CONFLICT(id) DO UPDATE SET description=excluded.description, status=excluded.status, parent_id=excluded.parent_id");
                        query.build().execute(&mut *transaction).await?;
                    }
                    transaction.commit().await?;
                    Ok(count)
                })
            })
            .await
    }

    pub async fn mark_cve_asset_applied(
        &self,
        filename: &str,
        source_url: &str,
    ) -> Result<(), sqlx::Error> {
        let filename = filename.to_owned();
        let source_url = source_url.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at")
                .bind(format!("cve_asset:{filename}")).bind(source_url).bind(chrono::Utc::now().to_rfc3339()).execute(connection).await?;
            Ok(())
        })).await
    }

    /// Searches OSV advisories through the stable external-content FTS index.
    pub async fn import_cve_raw_json(&self, raw_json: String) -> Result<(), sqlx::Error> {
        self.import_cve_raw_jsons(vec![raw_json]).await.map(|_| ())
    }

    /// Imports a CVE batch in one writer transaction. Parsing and ZIP decoding happen before this
    /// call, while every normalized write remains owned by the single physical SQLite connection.
    pub async fn import_cve_raw_jsons(&self, records: Vec<String>) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, true, false)
            .await
    }

    /// Imports a batch while deferring global search-index maintenance to the caller.
    pub async fn import_cve_raw_jsons_deferred_search(
        &self,
        records: Vec<String>,
    ) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, false, false)
            .await
    }

    /// As above, but returns the parent identifiers whose search rows must be refreshed.
    pub async fn import_cve_raw_jsons_deferred_search_with_ids(
        &self,
        records: Vec<String>,
    ) -> Result<(usize, Vec<String>), sqlx::Error> {
        let cve_ids = records
            .iter()
            .map(|raw_json| {
                let value: Value = serde_json::from_str(raw_json)
                    .map_err(|error| sqlx::Error::Protocol(format!("invalid CVE JSON: {error}")))?;
                value
                    .pointer("/cveMetadata/cveId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        sqlx::Error::Protocol("CVE record is missing cveMetadata.cveId".to_owned())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let imported = self
            .import_cve_raw_jsons_with_search(records, false, false)
            .await?;
        Ok((imported, cve_ids))
    }

    /// Imports a full-replacement batch into an empty database without conflict checks or stale
    /// child deletion. Callers must prepare the CVE bulk-load mode before using this path.
    pub async fn import_cve_raw_jsons_bulk_init(
        &self,
        records: Vec<String>,
    ) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, false, true)
            .await
    }

    async fn import_cve_raw_jsons_with_search(
        &self,
        records: Vec<String>,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<usize, sqlx::Error> {
        let count = records.len();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    // Updating external-content FTS once per normalized CVE is substantially
                    // slower than rebuilding its stable-rowid index once for the whole batch.
                    // DDL is transactional in SQLite: any error rolls the trigger drop back.
                    schema::suspend_cve_search_sync(&mut transaction).await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('CVE', 'CVE List V5', 'vulnerability_db', 'all_CVEs_at_midnight.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    let mut records = records.into_iter();
                    loop {
                        let batch = records
                            .by_ref()
                            .take(CVE_NORMALIZE_BATCH_SIZE)
                            .collect::<Vec<_>>();
                        if batch.is_empty() {
                            break;
                        }
                        // Bound materialized JSON DOMs independently of the caller's ZIP chunk.
                        // This mirrors the old 2k database batches while retaining one outer
                        // transaction, so larger chunks improve I/O without multiplying memory.
                        let records = batch
                            .into_par_iter()
                            .map(|raw_json| {
                                let mut bytes = raw_json.as_bytes().to_vec();
                                let value = simd_json::from_slice(&mut bytes)
                                    .map_err(|error| format!("invalid CVE JSON: {error}"))?;
                                let parent = Self::cve_parent_input(raw_json, &value)
                                    .map_err(|error| error.to_string())?;
                                Ok((parent, value))
                            })
                            .collect::<Result<Vec<_>, String>>()
                            .map_err(sqlx::Error::Protocol)?;
                        Self::write_cve_identifiers(&mut transaction, &records, bulk_init).await?;
                        let cve_ids =
                            Self::write_cve_parents(&mut transaction, &records, bulk_init).await?;
                        if !bulk_init {
                            Self::delete_existing_cve_children(&mut transaction, &records).await?;
                        }
                        Self::insert_cve_children(&mut transaction, &records, &cve_ids).await?;
                        replace_ssvc_for_cves(&mut transaction, &records, bulk_init).await?;
                    }
                    if update_search {
                        rebuild_cve_search(&mut transaction).await?;
                    }
                    schema::restore_cve_search_sync(&mut transaction).await?;
                    transaction.commit().await
                })
            })
            .await?;
        Ok(count)
    }

    /// Populates CVE identifier master nodes in bulk. Edges are rebuilt from their normalized
    /// sources after the import, so this needs no row-at-a-time graph maintenance.
    async fn write_cve_identifiers(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        insert_only: bool,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        // Five bindings per row: keep each statement below SQLite's variable limit.
        for chunk in records.chunks(5_000) {
            let mut builder = QueryBuilder::<Sqlite>::new(
                "INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) ",
            );
            builder.push_values(chunk, |mut row, (parent, _)| {
                row.push_bind(&parent.cve_id)
                    .push_bind("cve")
                    .push_bind("CVE")
                    .push_bind(&now)
                    .push_bind(&now);
            });
            if !insert_only {
                builder.push(" ON CONFLICT(identifier) DO UPDATE SET identifier_type='cve', last_seen_at=excluded.last_seen_at");
            }
            builder.build().execute(&mut *transaction).await?;
        }
        Ok(())
    }

    /// Removes stale normalized children in set-based statements before re-inserting a batch.
    /// Cascades from `cve_affected` also remove affected-version descendants.
    async fn delete_existing_cve_children(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
    ) -> Result<(), sqlx::Error> {
        for chunk in records.chunks(900) {
            for table in ["cve_affected", "cve_cvss", "cve_cwe"] {
                let mut query = QueryBuilder::<Sqlite>::new(format!(
                    "DELETE FROM {table} WHERE cve_db_id IN (SELECT id FROM cve WHERE cve_id IN ("
                ));
                let mut separated = query.separated(", ");
                for (parent, _) in chunk {
                    separated.push_bind(&parent.cve_id);
                }
                query.push("))");
                query.build().execute(&mut *transaction).await?;
            }
        }
        Ok(())
    }

    fn cve_parent_input(raw_json: String, value: &Value) -> Result<CveParentInput, sqlx::Error> {
        let metadata = value
            .get("cveMetadata")
            .ok_or_else(|| sqlx::Error::Protocol("CVE record is missing cveMetadata".to_owned()))?;
        let cve_id = metadata
            .get("cveId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                sqlx::Error::Protocol("CVE record is missing cveMetadata.cveId".to_owned())
            })?
            .to_owned();
        let state = match metadata.get("state").and_then(Value::as_str) {
            Some("PUBLISHED") => 0,
            Some("REJECTED") => 1,
            Some(other) => {
                return Err(sqlx::Error::Protocol(format!(
                    "unsupported CVE state: {other}"
                )));
            }
            None => {
                return Err(sqlx::Error::Protocol(
                    "CVE record is missing cveMetadata.state".to_owned(),
                ));
            }
        };
        let published_value = metadata
            .get("datePublished")
            .and_then(Value::as_str)
            .unwrap_or("1970-01-01T00:00:00Z");
        let published_at = canonical_cve_utc(published_value).map_err(|error| {
            sqlx::Error::Protocol(format!(
                "invalid CVE published timestamp for {cve_id} ({published_value:?}): {error}"
            ))
        })?;
        let updated_value = metadata
            .get("dateUpdated")
            .and_then(Value::as_str)
            .unwrap_or(&published_at);
        let updated_at = canonical_cve_utc(updated_value).map_err(|error| {
            sqlx::Error::Protocol(format!(
                "invalid CVE updated timestamp for {cve_id} ({updated_value:?}): {error}"
            ))
        })?;
        let cna = value.pointer("/containers/cna");
        let title = cna
            .and_then(|cna| cna.get("title"))
            .and_then(Value::as_str)
            .unwrap_or(&cve_id)
            .to_owned();
        let description_en = cna
            .and_then(|cna| cna.get("descriptions"))
            .and_then(Value::as_array)
            .and_then(|descriptions| {
                descriptions
                    .iter()
                    .find(|description| {
                        description.get("lang").and_then(Value::as_str) == Some("en")
                    })
                    .or_else(|| descriptions.first())
            })
            .and_then(|description| description.get("value"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let references = cve_references(cna, value.pointer("/containers/adp"));
        let reference_text = references
            .iter()
            .map(|reference| {
                format!(
                    "{} {} {}",
                    reference.url,
                    reference.name.clone().unwrap_or_default(),
                    reference.tags_json
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        Ok(CveParentInput {
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en,
            serial: metadata.get("serial").and_then(Value::as_i64).unwrap_or(0),
            reference_text,
            raw_json,
        })
    }

    async fn write_cve_parents(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        insert_only: bool,
    ) -> Result<ahash::AHashMap<String, i64>, sqlx::Error> {
        for chunk in records.chunks(2_000) {
            let mut builder = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve (cve_id, state, published_at, updated_at, serial, title, description_en, reference_text, raw_json) ",
            );
            builder.push_values(chunk, |mut row, (parent, _)| {
                row.push_bind(&parent.cve_id)
                    .push_bind(parent.state)
                    .push_bind(&parent.published_at)
                    .push_bind(&parent.updated_at)
                    .push_bind(parent.serial)
                    .push_bind(&parent.title)
                    .push_bind(&parent.description_en)
                    .push_bind(&parent.reference_text)
                    .push_bind(&parent.raw_json);
            });
            if !insert_only {
                builder.push(" ON CONFLICT(cve_id) DO UPDATE SET state=excluded.state, published_at=excluded.published_at, updated_at=excluded.updated_at, serial=excluded.serial, title=excluded.title, description_en=excluded.description_en, reference_text=excluded.reference_text, raw_json=excluded.raw_json");
            }
            builder.build().execute(&mut *transaction).await?;
        }
        let mut ids = ahash::AHashMap::with_capacity(records.len());
        for chunk in records.chunks(900) {
            let mut query =
                QueryBuilder::<Sqlite>::new("SELECT cve_id, id FROM cve WHERE cve_id IN (");
            let mut separated = query.separated(", ");
            for (parent, _) in chunk {
                separated.push_bind(&parent.cve_id);
            }
            query.push(")");
            for row in query.build().fetch_all(&mut *transaction).await? {
                ids.insert(row.try_get("cve_id")?, row.try_get("id")?);
            }
        }
        Ok(ids)
    }

    async fn insert_cve_children(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        cve_ids: &ahash::AHashMap<String, i64>,
    ) -> Result<(), sqlx::Error> {
        let mut cvss_rows = Vec::<CvssInput>::new();
        let mut affected_rows = Vec::<AffectedInput>::new();
        let mut cwe_catalog = BTreeMap::<i64, Option<String>>::new();
        let mut cwe_links = Vec::<(i64, i64)>::new();

        for (parent, value) in records {
            let cve_db_id = *cve_ids.get(&parent.cve_id).ok_or_else(|| {
                sqlx::Error::Protocol(format!("missing staged CVE row: {}", parent.cve_id))
            })?;
            let cna = value.pointer("/containers/cna");
            if let Some(metrics) = cna
                .and_then(|value| value.get("metrics"))
                .and_then(Value::as_array)
            {
                for (source, metric) in metrics
                    .iter()
                    .flat_map(|metric| metric.as_object().into_iter().flat_map(|map| map.iter()))
                {
                    let Some(metric) = metric.as_object() else {
                        continue;
                    };
                    let Some(version) = metric.get("version").and_then(Value::as_str) else {
                        continue;
                    };
                    cvss_rows.push((
                        cve_db_id,
                        version.to_owned(),
                        metric.get("baseScore").and_then(Value::as_f64),
                        metric
                            .get("baseSeverity")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        metric
                            .get("vectorString")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        source.to_owned(),
                    ));
                }
            }
            if let Some(problem_types) = cna
                .and_then(|value| value.get("problemTypes"))
                .and_then(Value::as_array)
            {
                for description in problem_types.iter().flat_map(|problem_type| {
                    problem_type
                        .get("descriptions")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                }) {
                    let Some(cwe_id) = description
                        .get("cweId")
                        .and_then(Value::as_str)
                        .and_then(|value| value.strip_prefix("CWE-"))
                        .and_then(|value| value.parse::<i64>().ok())
                    else {
                        continue;
                    };
                    let description = description
                        .get("description")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    cwe_catalog
                        .entry(cwe_id)
                        .and_modify(|current| {
                            if current.is_none() {
                                *current = description.clone();
                            }
                        })
                        .or_insert(description);
                    cwe_links.push((cve_db_id, cwe_id));
                }
            }
            if let Some(affected) = cna
                .and_then(|value| value.get("affected"))
                .and_then(Value::as_array)
            {
                for item in affected {
                    let versions = item
                        .get("versions")
                        .and_then(Value::as_array)
                        .map(|versions| {
                            versions
                                .iter()
                                .map(|version| CveStoredVersion {
                                    version: version
                                        .get("version")
                                        .and_then(Value::as_str)
                                        .map(ToOwned::to_owned),
                                    status: version
                                        .get("status")
                                        .and_then(Value::as_str)
                                        .map(ToOwned::to_owned),
                                    version_type: version
                                        .get("versionType")
                                        .and_then(Value::as_str)
                                        .map(ToOwned::to_owned),
                                    less_than: version
                                        .get("lessThan")
                                        .and_then(Value::as_str)
                                        .map(ToOwned::to_owned),
                                    less_than_or_equal: version
                                        .get("lessThanOrEqual")
                                        .and_then(Value::as_str)
                                        .map(ToOwned::to_owned),
                                    changes: version
                                        .get("changes")
                                        .and_then(Value::as_array)
                                        .into_iter()
                                        .flatten()
                                        .filter_map(|change| {
                                            Some(CveStoredVersionChange {
                                                at: change.get("at")?.as_str()?.to_owned(),
                                                status: change.get("status")?.as_str()?.to_owned(),
                                            })
                                        })
                                        .collect(),
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let version_text = versions
                        .iter()
                        .filter_map(|version| version.version.as_deref())
                        .collect::<Vec<_>>()
                        .join(" ");
                    let versions_json = serde_json::to_string(&versions).map_err(|error| {
                        sqlx::Error::Protocol(format!(
                            "failed to encode affected versions: {error}"
                        ))
                    })?;
                    affected_rows.push((
                        cve_db_id,
                        item.get("vendor")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("product")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("packageName")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("collectionURL")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("defaultStatus")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        version_text,
                        versions_json,
                    ));
                }
            }
        }

        let cwe_rows = cwe_catalog.into_iter().collect::<Vec<_>>();
        for chunk in cwe_rows.chunks(8_000) {
            let mut query = QueryBuilder::<Sqlite>::new("INSERT INTO cwe(id, description) ");
            query.push_values(chunk, |mut row, (id, description)| {
                row.push_bind(id).push_bind(description);
            });
            query.push(" ON CONFLICT(id) DO UPDATE SET description=COALESCE(excluded.description, cwe.description)");
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in cvss_rows.chunks(4_000) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve_cvss(cve_db_id, version, base_score, base_severity, vector_string, source, raw_json) ",
            );
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0)
                    .push_bind(&value.1)
                    .push_bind(value.2)
                    .push_bind(&value.3)
                    .push_bind(&value.4)
                    .push_bind(&value.5)
                    .push_bind("{}");
            });
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in cwe_links.chunks(8_000) {
            let mut query =
                QueryBuilder::<Sqlite>::new("INSERT OR IGNORE INTO cve_cwe(cve_db_id, cwe_id) ");
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0).push_bind(value.1);
            });
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in affected_rows.chunks(3_000) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve_affected(cve_db_id, vendor, product, package_name, collection_url, default_status, version_text, raw_json) ",
            );
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0)
                    .push_bind(&value.1)
                    .push_bind(&value.2)
                    .push_bind(&value.3)
                    .push_bind(&value.4)
                    .push_bind(&value.5)
                    .push_bind(&value.6)
                    .push_bind(&value.7);
            });
            query.build().execute(&mut *transaction).await?;
        }
        Ok(())
    }
}
