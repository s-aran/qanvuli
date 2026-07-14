//! KEV lookup helpers.

use super::super::*;

pub(crate) async fn load_kev<C>(db: &C, cve_id: &str) -> Result<Option<KevInfo>, DbErr>
where
    C: ConnectionTrait,
{
    KevInfo::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, fetched_at FROM kev_entries WHERE cve_id = ?",
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .one(db)
    .await
}

pub(crate) async fn load_kev_many<C>(db: &C, cve_ids: &[String]) -> Result<Vec<KevInfo>, DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() {
        return Ok(Vec::new());
    }
    KevInfo::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, fetched_at FROM kev_entries WHERE cve_id IN ({})",
            sql_string_list(cve_ids)
        ),
    ))
    .all(db)
    .await
}
