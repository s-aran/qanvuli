//! KEV public query APIs.

use super::super::*;

impl CveDatabase {
    /// Returns KEV entries, optionally narrowed to one CVE ID.
    pub async fn kev_entries(&self, cve_id: Option<&str>) -> Result<Vec<KevInfo>, DbErr> {
        if let Some(cve_id) = cve_id {
            return Ok(super::read::load_kev(&self.db, cve_id)
                .await?
                .into_iter()
                .collect());
        }
        self.kev_entries_paged(i64::MAX as u64, 0).await
    }

    /// Returns paged KEV entries ordered by date added.
    pub async fn kev_entries_paged(&self, limit: u64, offset: u64) -> Result<Vec<KevInfo>, DbErr> {
        KevInfo::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                r#"
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                   short_description, required_action, due_date,
                   known_ransomware_campaign_use, notes, fetched_at
            FROM kev_entries
            ORDER BY date_added DESC, cve_id
            LIMIT {limit} OFFSET {offset}
            "#
            ),
        ))
        .all(&self.db)
        .await
    }

    /// Counts locally stored KEV entries.
    pub async fn kev_entries_count(&self) -> Result<u64, DbErr> {
        self.count_by_sql("SELECT COUNT(*) AS count FROM kev_entries".to_owned())
            .await
    }
}
