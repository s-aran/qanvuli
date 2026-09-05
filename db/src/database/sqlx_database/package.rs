use super::*;

impl SqlxDatabase {
    pub async fn search_cve_summaries_by_affected_component_with_state_scope(
        &self,
        search: SqlxAffectedComponentSearch,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let SqlxAffectedComponentSearch {
            vendor,
            component,
            published_since,
            updated_since,
            state_scope,
            limit,
            offset,
        } = search;
        let include_rejected = state_scope == CveStateScope::IncludeRejected;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows: Vec<SqlxCveSummary> = sqlx::query_as(
                        "SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve c JOIN cve_affected a ON a.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR a.vendor LIKE '%' || ? || '%') AND (a.product LIKE '%' || ? || '%' OR a.package_name LIKE '%' || ? || '%') AND (? IS NULL OR c.published_at>=?) AND (? IS NULL OR c.updated_at>=?) ORDER BY c.published_at DESC, c.cve_id DESC LIMIT ? OFFSET ?",
                    )
                    .bind(include_rejected)
                    .bind(&vendor)
                    .bind(&vendor)
                    .bind(&component)
                    .bind(&component)
                    .bind(&published_since)
                    .bind(&published_since)
                    .bind(&updated_since)
                    .bind(&updated_since)
                    .bind(i64::try_from(limit).unwrap_or(i64::MAX).max(1))
                    .bind(i64::try_from(offset).unwrap_or(i64::MAX))
                    .fetch_all(connection)
                    .await?;
                    Ok(rows.into_iter().map(CveSummary::from).collect())
                })
            })
            .await
    }

    pub async fn query_package_matches(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<EnrichedFinding>, sqlx::Error> {
        let query = PackageQuery {
            ecosystem: ecosystem.to_owned(),
            package: package.to_owned(),
            version: version.to_owned(),
            purl: purl.map(str::to_owned),
        };
        Ok(self
            .query_package_matches_batch(std::slice::from_ref(&query))
            .await?
            .pop()
            .unwrap_or_default())
    }

    /// Returns whether the local OSV corpus has any non-withdrawn advisory for this package
    /// identity, independently of the queried version.
    pub async fn has_osv_package_advisory(
        &self,
        ecosystem: &str,
        package: &str,
        purl: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        validate_package_query_identity(ecosystem, package, purl)?;
        let ecosystem = ecosystem.to_owned();
        let ecosystem_key = ecosystem_identity_key(&ecosystem);
        let package = normalize_package_name(&ecosystem, package);
        let purl = purl.map(package_identity_purl);
        let purl_base = purl.as_deref().map(purl_base_identity).map(str::to_owned);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let normalized_name =
                        sql_normalized_package_name("package.package_name", "?");
                    let ecosystem_matches = sql_ecosystem_matches("package.ecosystem", "?");
                    let statement = format!(
                        "SELECT EXISTS(SELECT 1 FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND {ecosystem_matches} AND (({normalized_name}=? AND (? IS NULL OR package.purl IS NULL OR package.purl=? OR (instr(package.purl, '?')=0 AND instr(package.purl, '#')=0 AND package.purl=?))) OR (? IS NOT NULL AND package.purl=?)))"
                    );
                    // The statement shape is generated solely from fixed local
                    // SQL fragments; all caller data remains bound parameters.
                    let exists: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(statement))
                    .bind(&ecosystem_key)
                    .bind(&ecosystem)
                    .bind(package)
                    .bind(&purl)
                    .bind(&purl)
                    .bind(&purl_base)
                    .bind(&purl)
                    .bind(&purl)
                    .fetch_one(connection)
                    .await?;
                    Ok(exists != 0)
                })
            })
            .await
    }

    /// Returns local OSV coverage for every query in order, without evaluating versions.
    pub async fn has_osv_package_advisories_batch(
        &self,
        packages: &[PackageQuery],
    ) -> Result<Vec<bool>, sqlx::Error> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = packages.to_vec();
        for package in &mut packages {
            validate_package_query_identity(
                &package.ecosystem,
                &package.package,
                package.purl.as_deref(),
            )?;
            package.package = normalize_package_name(&package.ecosystem, &package.package);
            package.purl = package.purl.as_deref().map(package_identity_purl);
        }
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let input = package_queries_json(&packages)?;
                    let normalized_name = sql_normalized_package_name(
                        "package.package_name",
                        "input.ecosystem",
                    );
                    let ecosystem_matches =
                        sql_ecosystem_matches("package.ecosystem", "input.ecosystem_key");
                    let statement = format!(
                        "WITH input AS (SELECT CAST(key AS INTEGER) AS query_index, json_extract(value, '$.ecosystem') AS ecosystem, json_extract(value, '$.ecosystem_key') AS ecosystem_key, json_extract(value, '$.package') AS package_name, json_extract(value, '$.purl') AS purl, json_extract(value, '$.purl_base') AS purl_base FROM json_each(?)) SELECT input.query_index, EXISTS(SELECT 1 FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND {ecosystem_matches} AND (({normalized_name}=input.package_name AND (input.purl IS NULL OR package.purl IS NULL OR package.purl=input.purl OR (instr(package.purl, '?')=0 AND instr(package.purl, '#')=0 AND package.purl=input.purl_base))) OR (input.purl IS NOT NULL AND package.purl=input.purl))) FROM input ORDER BY input.query_index"
                    );
                    let rows: Vec<(i64, i64)> =
                        sqlx::query_as(sqlx::AssertSqlSafe(statement))
                    .bind(input)
                    .fetch_all(connection)
                    .await?;
                    let mut coverage = vec![false; packages.len()];
                    for (index, covered) in rows {
                        if let Ok(index) = usize::try_from(index)
                            && let Some(value) = coverage.get_mut(index)
                        {
                            *value = covered != 0;
                        }
                    }
                    Ok(coverage)
                })
            })
            .await
    }

    /// Matches package/version queries with bounded candidate scans and bounded follow-up reads
    /// for ranges, explicit versions, and CVE aliases.
    pub async fn query_package_matches_batch(
        &self,
        packages: &[PackageQuery],
    ) -> Result<Vec<Vec<EnrichedFinding>>, sqlx::Error> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = packages.to_vec();
        for package in &mut packages {
            validate_package_query_identity(
                &package.ecosystem,
                &package.package,
                package.purl.as_deref(),
            )?;
            package.package = normalize_package_name(&package.ecosystem, &package.package);
            package.purl = package.purl.as_deref().map(package_identity_purl);
        }
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut output = vec![Vec::new(); packages.len()];
            for (query_batch_index, package_batch) in
                packages.chunks(PACKAGE_QUERY_BATCH_SIZE).enumerate()
            {
                let input_json = package_queries_json(package_batch)?;
                let normalized_name =
                    sql_normalized_package_name("package.package_name", "input.ecosystem");
                let ecosystem_matches =
                    sql_ecosystem_matches("package.ecosystem", "input.ecosystem_key");
                let candidate_statement = format!(
                    "WITH input AS (SELECT CAST(key AS INTEGER) AS query_index, json_extract(value, '$.ecosystem') AS ecosystem, json_extract(value, '$.ecosystem_key') AS ecosystem_key, json_extract(value, '$.package') AS package_name, json_extract(value, '$.purl') AS purl, json_extract(value, '$.purl_base') AS purl_base FROM json_each(?)) SELECT input.query_index, package.id, package.osv_id FROM input JOIN osv_affected_packages AS package ON {ecosystem_matches} AND (({normalized_name}=input.package_name AND (input.purl IS NULL OR package.purl IS NULL OR package.purl=input.purl OR (instr(package.purl, '?')=0 AND instr(package.purl, '#')=0 AND package.purl=input.purl_base))) OR (input.purl IS NOT NULL AND package.purl=input.purl)) JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL ORDER BY input.query_index, package.osv_id, package.id"
                );
                let candidates: Vec<(i64, i64, String)> =
                    sqlx::query_as(sqlx::AssertSqlSafe(candidate_statement))
                .bind(&input_json)
                .fetch_all(&mut *connection)
                .await?;

                let package_ids = candidates
                    .iter()
                    .map(|(_, id, _)| *id)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut ranges_by_package = BTreeMap::<i64, Vec<OsvRange>>::new();
                let mut versions_by_package = BTreeMap::<i64, BTreeSet<String>>::new();
                for package_id_batch in package_ids.chunks(PACKAGE_ID_BATCH_SIZE) {
                    let package_ids_json = serde_json::to_string(package_id_batch).map_err(|error| {
                        sqlx::Error::Protocol(format!("failed to encode OSV package IDs: {error}"))
                    })?;
                    let events: Vec<(i64, i64, String, String, String)> = sqlx::query_as(
                        "SELECT range.affected_package_id, range.id, range.range_type, event.event_type, event.value FROM osv_ranges AS range JOIN osv_range_events AS event ON event.range_id=range.id WHERE range.affected_package_id IN (SELECT value FROM json_each(?)) ORDER BY range.affected_package_id, range.id, event.id",
                    )
                    .bind(&package_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let mut current_range = None;
                    for (package_id, range_id, range_type, event_type, value) in events {
                        let ranges = ranges_by_package.entry(package_id).or_default();
                        if current_range != Some((package_id, range_id)) {
                            current_range = Some((package_id, range_id));
                            ranges.push(OsvRange { range_type, events: Vec::new() });
                        }
                        ranges.last_mut().expect("range inserted").events.push((event_type, value));
                    }
                    let version_rows: Vec<(i64, String)> = sqlx::query_as(
                        "SELECT affected_package_id, version FROM osv_versions WHERE affected_package_id IN (SELECT value FROM json_each(?))",
                    )
                    .bind(&package_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (package_id, version) in version_rows {
                        versions_by_package.entry(package_id).or_default().insert(version);
                    }
                }

                let osv_ids = candidates
                    .iter()
                    .map(|(_, _, id)| id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut aliases_by_osv = BTreeMap::<String, Vec<String>>::new();
                for osv_id_batch in osv_ids.chunks(OSV_ID_BATCH_SIZE) {
                    let osv_ids_json = serde_json::to_string(osv_id_batch).map_err(|error| {
                        sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}"))
                    })?;
                    let alias_rows: Vec<(String, String)> = sqlx::query_as(
                        "SELECT osv_id, alias_id FROM osv_aliases WHERE osv_id IN (SELECT value FROM json_each(?)) ORDER BY osv_id, alias_id",
                    )
                    .bind(osv_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (osv_id, alias) in alias_rows {
                        aliases_by_osv.entry(osv_id).or_default().push(alias);
                    }
                }

                let query_offset = query_batch_index * PACKAGE_QUERY_BATCH_SIZE;
                for (query_index, package_id, osv_id) in candidates {
                    let local_index = usize::try_from(query_index).map_err(|_| {
                        sqlx::Error::Protocol("invalid package query index".to_owned())
                    })?;
                    let output_index = query_offset + local_index;
                    let query = packages.get(output_index).ok_or_else(|| {
                        sqlx::Error::Protocol("package query index is out of bounds".to_owned())
                    })?;
                    let explicit_versions = versions_by_package.get(&package_id);
                    let ranges = ranges_by_package
                        .get(&package_id)
                        .map(Vec::as_slice)
                        .unwrap_or_default();
                    let matched = if explicit_versions.is_some_and(|versions| {
                        versions.iter().any(|version| {
                            versions_equivalent(&query.ecosystem, version, &query.version)
                        })
                    }) {
                        crate::database::package_eval::VersionMatch {
                            status: "affected".to_owned(),
                            confidence: "high".to_owned(),
                        }
                    } else if explicit_versions.is_some_and(|versions| !versions.is_empty())
                        && ranges.is_empty()
                    {
                        crate::database::package_eval::VersionMatch {
                            status: "not_affected".to_owned(),
                            confidence: "high".to_owned(),
                        }
                    } else {
                        evaluate_version(&query.ecosystem, &query.version, ranges)
                    };
                    if matched.status == "not_affected" {
                        continue;
                    }
                    let affected = AffectedStatus { status: matched.status, confidence: matched.confidence };
                    let fixed_versions = ranges_by_package
                        .get(&package_id)
                        .into_iter()
                        .flatten()
                        .flat_map(|range| range.events.iter())
                        .filter(|(event_type, _)| event_type == "fixed")
                        .map(|(_, version)| version.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let aliases = aliases_by_osv.get(&osv_id).cloned().unwrap_or_default();
                    let cve_ids = aliases
                        .iter()
                        .filter(|alias| alias.to_ascii_uppercase().starts_with("CVE-"))
                        .cloned()
                        .collect();
                    output[output_index].push(EnrichedFinding {
                        source: "osv".to_owned(), primary_id: osv_id.clone(), cve_ids, aliases, aliases_status: "available".to_owned(), package: query.clone(), affected: affected.clone(), fixed_versions_status: "available".to_owned(), priority_signals: PrioritySignals { known_exploited: false, epss_percentile: None, has_fixed_version: !fixed_versions.is_empty(), affected_confidence: affected.confidence, suggested_priority: "unknown".to_owned(), reasons: Vec::new(), enrichment_status: "not_queried".to_owned() }, fixed_versions, enrichment: FindingEnrichment { kev: None, kev_status: "not_queried".to_owned(), epss: None, epss_status: "not_queried".to_owned() }, evidence: Vec::new(), evidence_status: "not_queried".to_owned()
                    });
                }

                // CVE List supplements OSV for package advisories that have not
                // been mirrored into OSV. package_name is authoritative when it
                // exists; product is the documented fallback for older records.
                let normalized_cve_name = sql_normalized_cve_component_name(
                    "COALESCE(NULLIF(affected.package_name, ''), affected.product)",
                );
                let normalized_input_name =
                    sql_normalized_cve_component_name("input.package_name");
                let cve_statement = format!(
                    "WITH input AS (SELECT CAST(key AS INTEGER) AS query_index, json_extract(value, '$.ecosystem') AS ecosystem, json_extract(value, '$.package') AS package_name FROM json_each(?)) SELECT input.query_index, c.cve_id, affected.default_status, affected.raw_json, affected.package_name, affected.product, affected.collection_url FROM input JOIN cve_affected AS affected ON {normalized_cve_name}={normalized_input_name} JOIN cve AS c ON c.id=affected.cve_db_id WHERE c.state=0 ORDER BY input.query_index, c.cve_id, affected.id"
                );
                let cve_candidates: Vec<CvePackageCandidate> = sqlx::query_as(sqlx::AssertSqlSafe(cve_statement))
                .bind(&input_json)
                .fetch_all(&mut *connection)
                .await?;
                for (query_index, cve_id, default_status, raw_json, package_name, product, collection_url) in cve_candidates {
                    let local_index = usize::try_from(query_index).map_err(|_| {
                        sqlx::Error::Protocol("invalid CVE package query index".to_owned())
                    })?;
                    let output_index = query_offset + local_index;
                    let query = packages.get(output_index).ok_or_else(|| {
                        sqlx::Error::Protocol("CVE package query index is out of bounds".to_owned())
                    })?;
                    let identity = cve_package_identity(
                        &query.ecosystem,
                        package_name.as_deref(),
                        product.as_deref(),
                        collection_url.as_deref(),
                    );
                    if identity == CvePackageIdentity::Excluded {
                        continue;
                    }
                    let versions = cve_stored_versions(&raw_json)
                        .map_err(|error| {
                            sqlx::Error::Protocol(format!("failed to parse cve_affected.raw_json for {cve_id}: {error}"))
                        })?
                        .into_iter()
                        .map(|version| CveVersionRange {
                            version: version.version,
                            status: version.status,
                            version_type: version.version_type,
                            less_than: version.less_than,
                            less_than_or_equal: version.less_than_or_equal,
                            changes: version
                                .changes
                                .into_iter()
                                .map(|change| CveVersionChange {
                                    at: change.at,
                                    status: change.status,
                                })
                                .collect(),
                        })
                        .collect::<Vec<_>>();
                    let mut matched = evaluate_cve_version_ranges(
                        &query.ecosystem,
                        &query.version,
                        default_status.as_deref(),
                        &versions,
                    );
                    if identity == CvePackageIdentity::Probable && matched.status == "affected" {
                        matched.confidence = "medium".to_owned();
                    }
                    if identity == CvePackageIdentity::Ambiguous
                        && matched.status != "not_affected"
                    {
                        matched.status = "unknown".to_owned();
                        matched.confidence = "low".to_owned();
                    }
                    if matched.status == "not_affected" {
                        continue;
                    }
                    let fixed_versions = versions
                        .iter()
                        .filter(|version| {
                            version
                                .status
                                .as_deref()
                                .or(default_status.as_deref())
                                .is_none_or(|status| status.eq_ignore_ascii_case("affected"))
                        })
                        .filter_map(|version| {
                            version.less_than.clone().or(version.less_than_or_equal.clone())
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let has_fixed_version = !fixed_versions.is_empty();
                    let affected = AffectedStatus {
                        status: matched.status,
                        confidence: matched.confidence,
                    };
                    output[output_index].push(EnrichedFinding {
                        source: "cve-list".to_owned(),
                        primary_id: cve_id.clone(),
                        cve_ids: vec![cve_id],
                        aliases: Vec::new(),
                        aliases_status: "not_queried".to_owned(),
                        package: query.clone(),
                        affected: affected.clone(),
                        fixed_versions,
                        fixed_versions_status: "available".to_owned(),
                        enrichment: FindingEnrichment {
                            kev: None,
                            kev_status: "not_queried".to_owned(),
                            epss: None,
                            epss_status: "not_queried".to_owned(),
                        },
                        priority_signals: PrioritySignals {
                            known_exploited: false,
                            epss_percentile: None,
                            has_fixed_version,
                            affected_confidence: affected.confidence,
                            suggested_priority: "unknown".to_owned(),
                            reasons: Vec::new(),
                            enrichment_status: "not_queried".to_owned(),
                        },
                        evidence: Vec::new(),
                        evidence_status: "not_queried".to_owned(),
                    });
                }
            }
            for findings in &mut output {
                *findings = consolidate_package_findings(std::mem::take(findings));
            }
            Ok(output)
        })).await
    }
}

impl SqlxDatabase {
    pub async fn resolve_identifier(
        &self,
        identifier: &str,
    ) -> Result<SqlxIdentifierResolution, sqlx::Error> {
        let identifier = identifier.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let related: Vec<String> = sqlx::query_scalar("WITH RECURSIVE related(identifier) AS (SELECT identifier FROM vulnerability_identifiers WHERE identifier=? COLLATE NOCASE UNION SELECT edge.to_identifier FROM vulnerability_identifier_edges AS edge JOIN related ON edge.from_identifier=related.identifier WHERE edge.relation_type='alias' UNION SELECT edge.from_identifier FROM vulnerability_identifier_edges AS edge JOIN related ON edge.to_identifier=related.identifier WHERE edge.relation_type='alias') SELECT identifier FROM related ORDER BY identifier")
                .bind(&identifier).fetch_all(&mut *connection).await?;
            let related_cve_ids = related.iter().filter(|value| value.starts_with("CVE-")).cloned().collect();
            let related_osv_ids = related.iter().filter(|value| !value.starts_with("CVE-")).cloned().collect();
            Ok(SqlxIdentifierResolution { identifier, related_cve_ids, related_osv_ids })
        })).await
    }

    /// Returns graph edges connected to a public identifier.
    pub async fn identifier_edges(
        &self,
        identifier: &str,
    ) -> Result<Vec<SqlxIdentifierEdge>, sqlx::Error> {
        let identifier = identifier.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT from_identifier, to_identifier, relation_type, source, confidence, evidence_json FROM vulnerability_identifier_edges WHERE from_identifier=? COLLATE NOCASE OR to_identifier=? COLLATE NOCASE ORDER BY relation_type, from_identifier, to_identifier, source")
                .bind(&identifier).bind(&identifier).fetch_all(connection).await
        })).await
    }

    /// Finds OSV package candidates and evaluates supported version ranges. A name match alone
    /// remains `unknown` rather than a confirmed vulnerability.
    pub async fn query_osv_package(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Vec<SqlxPackageFinding>, sqlx::Error> {
        self.query_osv_package_with_purl(ecosystem, package_name, version, None)
            .await
    }

    /// Queries OSV package records by normalized ecosystem/name and, when available, purl.
    /// A purl is an additional locator rather than a replacement for the source package name:
    /// feeds commonly omit it, so exact name matches must remain discoverable.
    pub async fn query_osv_package_with_purl(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<SqlxPackageFinding>, sqlx::Error> {
        validate_package_query_identity(ecosystem, package_name, purl)?;
        let ecosystem = ecosystem.to_owned();
        let ecosystem_key = ecosystem_identity_key(&ecosystem);
        let package_name = normalize_package_name(&ecosystem, package_name);
        let version = version.to_owned();
        let purl = purl.map(package_identity_purl);
        let purl_base = purl.as_deref().map(purl_base_identity).map(str::to_owned);
        self.writer.with_connection(|connection| Box::pin(async move {
            let normalized_name = sql_normalized_package_name("package.package_name", "?");
            let ecosystem_matches = sql_ecosystem_matches("package.ecosystem", "?");
            let statement = format!("SELECT package.id, package.osv_id FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND {ecosystem_matches} AND (({normalized_name}=? AND (? IS NULL OR package.purl IS NULL OR package.purl=? OR (instr(package.purl, '?')=0 AND instr(package.purl, '#')=0 AND package.purl=?))) OR (? IS NOT NULL AND package.purl=?)) ORDER BY package.osv_id");
            let packages: Vec<(i64, String)> =
                sqlx::query_as(sqlx::AssertSqlSafe(statement))
                .bind(&ecosystem_key).bind(&ecosystem).bind(&package_name).bind(&purl).bind(&purl).bind(&purl_base).bind(&purl).bind(&purl).fetch_all(&mut *connection).await?;
            let package_ids_json = serde_json::to_string(&packages.iter().map(|(id, _)| id).collect::<Vec<_>>())
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode OSV package IDs: {error}")))?;
            let osv_ids_json = serde_json::to_string(&packages.iter().map(|(_, id)| id).collect::<BTreeSet<_>>())
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}")))?;
            let events: Vec<(i64, i64, String, String, String)> = sqlx::query_as("SELECT range.affected_package_id, range.id, range.range_type, event.event_type, event.value FROM osv_ranges AS range JOIN osv_range_events AS event ON event.range_id=range.id WHERE range.affected_package_id IN (SELECT value FROM json_each(?)) ORDER BY range.affected_package_id, range.id, event.id")
                .bind(&package_ids_json).fetch_all(&mut *connection).await?;
            let mut ranges_by_package = BTreeMap::<i64, Vec<OsvRange>>::new();
            let mut current_range = None;
            for (package_id, range_id, range_type, event_type, value) in events {
                let ranges = ranges_by_package.entry(package_id).or_default();
                if current_range != Some((package_id, range_id)) {
                    current_range = Some((package_id, range_id));
                    ranges.push(OsvRange { range_type, events: Vec::new() });
                }
                ranges.last_mut().expect("range was inserted").events.push((event_type, value));
            }
            let explicit_version_rows: Vec<(i64, String)> = sqlx::query_as("SELECT affected_package_id, version FROM osv_versions WHERE affected_package_id IN (SELECT value FROM json_each(?))")
                .bind(&package_ids_json).fetch_all(&mut *connection).await?;
            let explicit_version_packages = explicit_version_rows
                .iter()
                .map(|(package_id, _)| *package_id)
                .collect::<BTreeSet<_>>();
            let explicit_versions = explicit_version_rows
                .into_iter()
                .filter(|(_, candidate)| versions_equivalent(&ecosystem, candidate, &version))
                .map(|(package_id, _)| package_id)
                .collect::<BTreeSet<_>>();
            let alias_rows: Vec<(String, String)> = sqlx::query_as("SELECT osv_id, alias_id FROM osv_aliases WHERE alias_id LIKE 'CVE-%' AND osv_id IN (SELECT value FROM json_each(?)) ORDER BY osv_id, alias_id")
                .bind(&osv_ids_json).fetch_all(&mut *connection).await?;
            let mut aliases_by_osv = BTreeMap::<String, Vec<String>>::new();
            for (osv_id, alias_id) in alias_rows {
                aliases_by_osv.entry(osv_id).or_default().push(alias_id);
            }
            let mut findings = Vec::with_capacity(packages.len());
            for (package_id, osv_id) in packages {
                let ranges = ranges_by_package.remove(&package_id).unwrap_or_default();
                let matched = if explicit_versions.contains(&package_id) {
                    crate::database::package_eval::VersionMatch {
                        status: "affected".to_owned(),
                        confidence: "high".to_owned(),
                    }
                } else if explicit_version_packages.contains(&package_id) && ranges.is_empty() {
                    crate::database::package_eval::VersionMatch {
                        status: "not_affected".to_owned(),
                        confidence: "high".to_owned(),
                    }
                } else {
                    evaluate_version(&ecosystem, &version, &ranges)
                };
                let cve_ids = aliases_by_osv.get(&osv_id).cloned().unwrap_or_default();
                findings.push(SqlxPackageFinding { osv_id, cve_ids, status: matched.status, confidence: matched.confidence });
            }
            Ok(findings)
        })).await
    }
}
