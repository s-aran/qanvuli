use super::*;

impl SqlxDatabase {
    pub async fn find_cwe_entry(&self, id: i32) -> Result<Option<CweEntry>, sqlx::Error> {
        let row: Option<CompatCweRow> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT id, description, status, parent_id FROM cwe WHERE id=?")
                        .bind(id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut entry = cwe_entries_with_relation_counts(vec![row]).remove(0);
        entry.capec_ids = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT capec_id FROM capec_cwe WHERE cwe_id=? ORDER BY capec_id",
                    )
                    .bind(id)
                    .fetch_all(connection)
                    .await
                })
            })
            .await?;
        Ok(Some(entry))
    }

    pub async fn search_cwe_entries(
        &self,
        query: &str,
        limit: u64,
        statuses: &[String],
    ) -> Result<Vec<CweEntry>, sqlx::Error> {
        self.search_cwe_entries_filtered(query, limit, statuses, None)
            .await
    }

    pub async fn search_cwe_entries_filtered(
        &self,
        query: &str,
        limit: u64,
        statuses: &[String],
        capec_id: Option<i32>,
    ) -> Result<Vec<CweEntry>, sqlx::Error> {
        let query = query.trim();
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let status_json = serde_json::to_string(statuses)
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let all_statuses = statuses.len() >= 6;
        let pattern = format!("%{query}%");
        let id = cwe_number(query);
        let query = query.to_owned();
        let rows: Vec<CompatCweRow> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT id, description, status, parent_id FROM cwe WHERE (? OR status IN (SELECT value FROM json_each(?))) AND (?='' OR description LIKE ? OR id=?) AND (? IS NULL OR EXISTS(SELECT 1 FROM capec_cwe link WHERE link.cwe_id=cwe.id AND link.capec_id=?)) ORDER BY id",
                    )
                    .bind(all_statuses)
                    .bind(status_json)
                    .bind(query)
                    .bind(pattern)
                    .bind(id)
                    .bind(capec_id)
                    .bind(capec_id)
                    .fetch_all(connection)
                    .await
                })
            })
            .await?;
        let mut entries = cwe_entries_tree_order(
            cwe_entries_with_relation_counts(rows),
            limit.max(1) as usize,
        );
        if !entries.is_empty() {
            let ids = entries.iter().map(|entry| entry.id).collect::<Vec<_>>();
            let ids_json = serde_json::to_string(&ids)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let links: Vec<(i32, i32)> = self
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_as("SELECT cwe_id,capec_id FROM capec_cwe WHERE cwe_id IN (SELECT value FROM json_each(?)) ORDER BY capec_id")
                            .bind(ids_json)
                            .fetch_all(connection)
                            .await
                    })
                })
                .await?;
            let mut by_cwe = HashMap::<i32, Vec<i32>>::new();
            for (cwe_id, capec_id) in links {
                by_cwe.entry(cwe_id).or_default().push(capec_id);
            }
            for entry in &mut entries {
                entry.capec_ids = by_cwe.remove(&entry.id).unwrap_or_default();
            }
        }
        Ok(entries)
    }

    pub async fn enriched_cve_summaries(
        &self,
        ids: &[String],
    ) -> Result<Vec<EnrichedCveSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query(
                r#"SELECT j.value AS cve_id,
                   COALESCE((SELECT group_concat(alias_id, ', ') FROM osv_aliases WHERE alias_id=j.value), '') AS aliases,
                   COALESCE((SELECT group_concat(osv_id, ', ') FROM osv_aliases WHERE alias_id=j.value), '') AS osv_ids,
                   COALESCE((SELECT group_concat(COALESCE(a.summary, a.osv_id), ' | ') FROM osv_aliases x JOIN osv_advisories a ON a.osv_id=x.osv_id WHERE x.alias_id=j.value), '') AS osv_summaries,
                   COALESCE((SELECT group_concat(COALESCE(p.ecosystem, '') || ':' || COALESCE(p.package_name, ''), ', ') FROM osv_aliases x JOIN osv_affected_packages p ON p.osv_id=x.osv_id WHERE x.alias_id=j.value), '') AS affected_packages,
                   EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=j.value) AS kev_listed,
                   k.date_added AS kev_date_added, k.due_date AS kev_due_date, k.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use,
                   e.epss, e.percentile AS epss_percentile, e.score_date AS epss_score_date, e.model_version AS epss_model_version,
                   (SELECT exploitation FROM ssvc_assessments s WHERE s.cve_id=j.value ORDER BY assessed_at DESC LIMIT 1) AS ssvc_exploitation,
                   (SELECT automatable FROM ssvc_assessments s WHERE s.cve_id=j.value ORDER BY assessed_at DESC LIMIT 1) AS ssvc_automatable,
                   (SELECT technical_impact FROM ssvc_assessments s WHERE s.cve_id=j.value ORDER BY assessed_at DESC LIMIT 1) AS ssvc_technical_impact
                   FROM json_each(?) j
                   LEFT JOIN kev_entries k ON k.cve_id=j.value
                   LEFT JOIN epss_current e ON e.cve_id=j.value
                   ORDER BY CAST(j.key AS INTEGER)"#
            ).bind(ids_json).fetch_all(connection).await?;
            rows.into_iter().map(|row| Ok(EnrichedCveSummary {
                cve_id: row.try_get("cve_id")?, aliases: row.try_get("aliases")?,
                osv_ids: row.try_get("osv_ids")?, osv_summaries: row.try_get("osv_summaries")?,
                affected_packages: row.try_get("affected_packages")?,
                kev_listed: row.try_get::<i64, _>("kev_listed")? != 0,
                kev_date_added: row.try_get("kev_date_added")?, kev_due_date: row.try_get("kev_due_date")?,
                kev_known_ransomware_campaign_use: row.try_get("kev_known_ransomware_campaign_use")?,
                epss: row.try_get("epss")?, epss_percentile: row.try_get("epss_percentile")?,
                epss_score_date: row.try_get("epss_score_date")?, epss_model_version: row.try_get("epss_model_version")?,
                ssvc_exploitation: row.try_get("ssvc_exploitation")?,
                ssvc_automatable: row.try_get("ssvc_automatable")?,
                ssvc_technical_impact: row.try_get("ssvc_technical_impact")?,
            })).collect()
        })).await
    }

    pub async fn database_status_enriched(&self) -> Result<DatabaseStatus, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            let row = sqlx::query("SELECT (SELECT COUNT(*) FROM cve) cve_count, (SELECT COUNT(*) FROM cve WHERE state=0) published_count, (SELECT COUNT(*) FROM cve WHERE state=1) rejected_count, (SELECT COUNT(*) FROM cwe) cwe_count, (SELECT COUNT(*) FROM cve_affected) affected_count, (SELECT COUNT(*) FROM cve_cvss) cvss_count, (SELECT MAX(updated_at) FROM cve) latest_cve_updated_at, (SELECT zip_datetime FROM cve_zip_file ORDER BY zip_datetime DESC LIMIT 1) latest_zip_datetime, (SELECT zip_filename FROM cve_zip_file ORDER BY zip_datetime DESC LIMIT 1) latest_zip_filename, (SELECT COUNT(*) FROM osv_advisories) osv_record_count, (SELECT COUNT(*) FROM kev_entries) kev_entry_count, (SELECT COUNT(*) FROM epss_current) epss_current_count, (SELECT COUNT(*) FROM ssvc_assessments) ssvc_assessment_count, (SELECT COUNT(*) FROM vulnerability_identifiers) identifier_node_count, (SELECT COUNT(*) FROM vulnerability_identifier_edges) identifier_edge_count").fetch_one(&mut *connection).await?;
            let source_rows = sqlx::query("SELECT source, display_name, source_type, default_filename, raw_format FROM db_sources ORDER BY source").fetch_all(&mut *connection).await?;
            let sources = source_rows.into_iter().map(|r| Ok(DbSource { source:r.try_get("source")?, display_name:r.try_get("display_name")?, source_type:r.try_get("source_type")?, default_filename:r.try_get("default_filename")?, raw_format:r.try_get("raw_format")? })).collect::<Result<Vec<_>, sqlx::Error>>()?;
            Ok(DatabaseStatus {
                cve: CveDatabaseStatus { cve_count:row.try_get("cve_count")?, published_count:row.try_get("published_count")?, rejected_count:row.try_get("rejected_count")?, cwe_count:row.try_get("cwe_count")?, affected_count:row.try_get("affected_count")?, cvss_count:row.try_get("cvss_count")?, latest_cve_updated_at:row.try_get("latest_cve_updated_at")?, latest_zip_datetime:row.try_get("latest_zip_datetime")?, latest_zip_filename:row.try_get("latest_zip_filename")? },
                sources,
                enrichment: EnrichmentDatabaseStatus { osv_record_count:row.try_get("osv_record_count")?, kev_entry_count:row.try_get("kev_entry_count")?, epss_current_count:row.try_get("epss_current_count")?, ssvc_assessment_count:row.try_get("ssvc_assessment_count")?, identifier_node_count:row.try_get("identifier_node_count")?, identifier_edge_count:row.try_get("identifier_edge_count")? },
            })
        })).await
    }

    pub async fn related_edges(
        &self,
        id: &str,
    ) -> Result<Vec<IdentifierEdgeEvidence>, sqlx::Error> {
        let id = id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT from_identifier,to_identifier,relation_type,source,confidence,evidence_json,created_at FROM vulnerability_identifier_edges WHERE from_identifier=? OR to_identifier=? ORDER BY relation_type,from_identifier,to_identifier")
                .bind(&id).bind(&id).fetch_all(connection).await?;
            rows.into_iter().map(|r| Ok(IdentifierEdgeEvidence { from_identifier:r.try_get("from_identifier")?, to_identifier:r.try_get("to_identifier")?, relation_type:r.try_get("relation_type")?, source:r.try_get("source")?, confidence:r.try_get("confidence")?, evidence_json:r.try_get("evidence_json")?, created_at:r.try_get("created_at")? })).collect()
        })).await
    }

    pub async fn get_enriched_cve(&self, cve_id: &str) -> Result<EnrichedCve, sqlx::Error> {
        let cve = self.find_cve_summary_with_detail(cve_id).await?;
        let severity = cve
            .as_ref()
            .map(|row| row.detail.cvss.clone())
            .unwrap_or_default();
        let cwe = cve
            .as_ref()
            .map(|row| {
                row.detail
                    .cwes
                    .iter()
                    .map(|item| format!("CWE-{}", item.id))
                    .collect()
            })
            .unwrap_or_default();
        let ssvc = cve
            .as_ref()
            .map(|row| row.detail.ssvc.clone())
            .unwrap_or_default();
        let id = cve_id.to_owned();
        let (aliases, advisories, packages, kev, epss, source_sync) = self.writer.with_connection(|connection| Box::pin(async move {
            let aliases: Vec<String> = sqlx::query_scalar("SELECT DISTINCT osv_id FROM osv_aliases WHERE alias_id=? ORDER BY osv_id").bind(&id).fetch_all(&mut *connection).await?;
            let advisory_rows = sqlx::query("SELECT a.osv_id,a.schema_version,a.published_at,a.modified_at,a.withdrawn_at,a.summary,a.details,(SELECT group_concat(COALESCE(p.ecosystem,'') || ':' || COALESCE(p.package_name,''), ', ') FROM osv_affected_packages p WHERE p.osv_id=a.osv_id) package_summary FROM osv_aliases x JOIN osv_advisories a ON a.osv_id=x.osv_id WHERE x.alias_id=? ORDER BY a.modified_at DESC,a.osv_id").bind(&id).fetch_all(&mut *connection).await?;
            let advisories = advisory_rows.into_iter().map(|r| Ok(OsvSummary { osv_id:r.try_get("osv_id")?, schema_version:r.try_get("schema_version")?, published_at:r.try_get("published_at")?, modified_at:r.try_get("modified_at")?, withdrawn_at:r.try_get("withdrawn_at")?, summary:r.try_get("summary")?, details:r.try_get("details")?, package_summary:r.try_get("package_summary")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            let package_rows=sqlx::query("SELECT p.osv_id,p.ecosystem,p.package_name,p.purl,COALESCE((SELECT group_concat(v.version, ', ') FROM osv_versions v WHERE v.affected_package_id=p.id),'') fixed_versions FROM osv_aliases x JOIN osv_affected_packages p ON p.osv_id=x.osv_id WHERE x.alias_id=? ORDER BY p.osv_id,p.affected_order").bind(&id).fetch_all(&mut *connection).await?;
            let packages=package_rows.into_iter().map(|r| Ok(AffectedPackageSummary { osv_id:r.try_get("osv_id")?, ecosystem:r.try_get("ecosystem")?, package_name:r.try_get("package_name")?, purl:r.try_get("purl")?, fixed_versions:r.try_get("fixed_versions")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            let kev_row=sqlx::query("SELECT cve_id,vendor_project,product,vulnerability_name,date_added,short_description,required_action,due_date,known_ransomware_campaign_use,notes,fetched_at FROM kev_entries WHERE cve_id=?").bind(&id).fetch_optional(&mut *connection).await?;
            let kev=kev_row.map(|r| -> Result<KevInfo, sqlx::Error> { Ok(KevInfo { cve_id:r.try_get("cve_id")?, vendor_project:r.try_get("vendor_project")?, product:r.try_get("product")?, vulnerability_name:r.try_get("vulnerability_name")?, date_added:r.try_get("date_added")?, short_description:r.try_get("short_description")?, required_action:r.try_get("required_action")?, due_date:r.try_get("due_date")?, known_ransomware_campaign_use:r.try_get("known_ransomware_campaign_use")?, notes:r.try_get("notes")?, fetched_at:r.try_get("fetched_at")? }) }).transpose()?;
            let epss_row=sqlx::query("SELECT cve_id,epss,percentile,score_date,model_version,fetched_at FROM epss_current WHERE cve_id=?").bind(&id).fetch_optional(&mut *connection).await?;
            let epss=epss_row.map(|r| -> Result<EpssInfo, sqlx::Error> { Ok(EpssInfo { cve_id:r.try_get("cve_id")?, epss:r.try_get("epss")?, percentile:r.try_get("percentile")?, score_date:r.try_get("score_date")?, model_version:r.try_get("model_version")?, fetched_at:r.try_get("fetched_at")? }) }).transpose()?;
            let sync_rows=sqlx::query("SELECT source,last_attempt_at,last_success_at,status,error_message,last_cursor,content_hash,schema_version,record_count FROM source_sync_state ORDER BY source").fetch_all(&mut *connection).await?;
            let source_sync=sync_rows.into_iter().map(|r| Ok(SourceSyncState { source:r.try_get("source")?, last_attempt_at:r.try_get("last_attempt_at")?, last_success_at:r.try_get("last_success_at")?, status:r.try_get("status")?, error_message:r.try_get("error_message")?, last_cursor:r.try_get("last_cursor")?, content_hash:r.try_get("content_hash")?, schema_version:r.try_get("schema_version")?, record_count:r.try_get("record_count")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            Ok((aliases,advisories,packages,kev,epss,source_sync))
        })).await?;
        let evidence = self
            .related_edges(cve_id)
            .await?
            .into_iter()
            .map(|edge| Evidence {
                kind: edge.relation_type,
                source: edge.source,
                from: Some(edge.from_identifier),
                to: Some(edge.to_identifier),
                cve_id: Some(cve_id.to_owned()),
                osv_id: None,
                detail: Some(edge.evidence_json),
            })
            .collect();
        Ok(EnrichedCve {
            cve_id: cve_id.to_owned(),
            cve,
            aliases,
            osv_advisories: advisories,
            affected_packages: packages,
            kev,
            epss,
            ssvc,
            severity,
            cwe,
            evidence,
            database_status: EnrichmentStatusSummary { source_sync },
        })
    }

    pub async fn query_package_enriched_with_evidence(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
        include_evidence: bool,
    ) -> Result<Vec<EnrichedFinding>, sqlx::Error> {
        let mut rows = self
            .query_package_matches(ecosystem, package, version, purl)
            .await?;
        if include_evidence {
            for row in &mut rows {
                row.evidence.push(Evidence {
                    kind: "package_version_evaluation".to_owned(),
                    source: row.source.clone(),
                    from: Some(format!(
                        "{}:{}@{}",
                        row.package.ecosystem, row.package.package, row.package.version
                    )),
                    to: Some(row.primary_id.clone()),
                    cve_id: row.cve_ids.first().cloned(),
                    osv_id: (row.source == "osv").then(|| row.primary_id.clone()),
                    detail: Some(
                        serde_json::json!({
                            "status": &row.affected.status,
                            "confidence": &row.affected.confidence,
                            "purl": &row.package.purl,
                            "fixed_versions": &row.fixed_versions,
                        })
                        .to_string(),
                    ),
                });
                row.evidence_status = "available".to_owned();
            }
        } else {
            for row in &mut rows {
                row.evidence.clear();
            }
        }
        Ok(rows)
    }

    pub async fn cve_risk_summaries(
        &self,
        ids: &[String],
    ) -> Result<Vec<CveRiskSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT c.cve_id,c.title,c.published_at,c.updated_at,c.state, k.cve_id IS NOT NULL kev_listed,k.date_added kev_date_added,k.due_date kev_due_date,k.known_ransomware_campaign_use kev_known_ransomware_campaign_use,e.epss,e.percentile epss_percentile,e.score_date epss_score_date,e.model_version epss_model_version,(SELECT MAX(v.base_score) FROM cve_cvss v WHERE v.cve_db_id=c.id) max_cvss_score,(SELECT v.base_severity FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_severity,(SELECT v.version FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_version FROM json_each(?) j JOIN cve c ON c.cve_id=j.value LEFT JOIN kev_entries k ON k.cve_id=c.cve_id LEFT JOIN epss_current e ON e.cve_id=c.cve_id ORDER BY CAST(j.key AS INTEGER)").bind(ids_json).fetch_all(connection).await?;
            rows.iter().map(risk_summary).collect()
        })).await
    }

    pub async fn search_cve_risk_by_epss(
        &self,
        min_score: Option<f64>,
        min_percentile: Option<f64>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveRiskSummary>, sqlx::Error> {
        let include = include_rejected(scope);
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT c.cve_id,c.title,c.published_at,c.updated_at,c.state,k.cve_id IS NOT NULL kev_listed,k.date_added kev_date_added,k.due_date kev_due_date,k.known_ransomware_campaign_use kev_known_ransomware_campaign_use,e.epss,e.percentile epss_percentile,e.score_date epss_score_date,e.model_version epss_model_version,(SELECT MAX(v.base_score) FROM cve_cvss v WHERE v.cve_db_id=c.id) max_cvss_score,(SELECT v.base_severity FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_severity,(SELECT v.version FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_version FROM epss_current e JOIN cve c ON c.cve_id=e.cve_id LEFT JOIN kev_entries k ON k.cve_id=c.cve_id WHERE (? OR c.state=0) AND (? IS NULL OR e.epss>=?) AND (? IS NULL OR e.percentile>=?) ORDER BY e.epss DESC,e.percentile DESC,c.cve_id LIMIT ? OFFSET ?")
                .bind(include).bind(min_score).bind(min_score).bind(min_percentile).bind(min_percentile).bind(limit as i64).bind(offset as i64).fetch_all(connection).await?;
            rows.iter().map(risk_summary).collect()
        })).await
    }

    pub async fn kev_entries_count(&self) -> Result<u64, sqlx::Error> {
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kev_entries")
                        .fetch_one(c)
                        .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn search_cve_summaries_by_reference_text(
        &self,
        query: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_reference_text(
                query,
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
    pub async fn search_cve_summaries_by_date_range(
        &self,
        published_from: Option<&str>,
        published_to: Option<&str>,
        updated_from: Option<&str>,
        updated_to: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let filters = SqlxCveSearch {
            published_since: published_from.map(str::to_owned),
            published_until: published_to.map(str::to_owned),
            updated_since: updated_from.map(str::to_owned),
            updated_until: updated_to.map(str::to_owned),
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

    pub async fn list_recent_updates(
        &self,
        since: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_dates(
                None,
                since.map(str::to_owned),
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }
}
