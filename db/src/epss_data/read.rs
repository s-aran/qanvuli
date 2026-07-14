//! EPSS lookup helpers.

use super::super::*;

pub(crate) async fn load_epss<C>(db: &C, cve_id: &str) -> Result<Option<EpssInfo>, DbErr>
where
    C: ConnectionTrait,
{
    EpssInfo::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT cve_id, epss, percentile, score_date, model_version, fetched_at FROM epss_current WHERE cve_id = ?",
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .one(db)
    .await
}

pub(crate) async fn load_epss_many<C>(db: &C, cve_ids: &[String]) -> Result<Vec<EpssInfo>, DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() {
        return Ok(Vec::new());
    }
    EpssInfo::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            "SELECT cve_id, epss, percentile, score_date, model_version, fetched_at FROM epss_current WHERE cve_id IN ({})",
            sql_string_list(cve_ids)
        ),
    ))
    .all(db)
    .await
}
