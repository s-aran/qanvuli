use super::*;
use qanvuli_models::ssvc::{SsvcAssessment, assessments_from_cve};
use std::str::FromStr;

pub(super) type SsvcRow = (
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

pub(super) async fn replace_ssvc_for_cves(
    transaction: &mut sqlx::SqliteConnection,
    records: &[(CveParentInput, Value)],
    insert_only: bool,
) -> Result<(), sqlx::Error> {
    let assessments = records
        .iter()
        .map(|(_, value)| assessments_from_cve(value).map_err(sqlx::Error::Protocol))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<SsvcAssessment>>();

    if !insert_only {
        for chunk in records.chunks(900) {
            let mut query =
                QueryBuilder::<Sqlite>::new("DELETE FROM ssvc_assessments WHERE cve_id IN (");
            let mut separated = query.separated(", ");
            for (parent, _) in chunk {
                separated.push_bind(&parent.cve_id);
            }
            query.push(")");
            query.build().execute(&mut *transaction).await?;
        }
    }

    let fetched_at = chrono::Utc::now().to_rfc3339();
    for rows in assessments.chunks(80) {
        let mut query = QueryBuilder::<Sqlite>::new(
            "INSERT INTO ssvc_assessments (cve_id, provider, role, version, assessed_at, exploitation, automatable, technical_impact, fetched_at, raw_json) ",
        );
        query.push_values(rows, |mut row, assessment| {
            row.push_bind(&assessment.cve_id)
                .push_bind(&assessment.provider)
                .push_bind(&assessment.role)
                .push_bind(&assessment.version)
                .push_bind(&assessment.assessed_at)
                .push_bind(assessment.exploitation.map(|value| value.as_str()))
                .push_bind(assessment.automatable.map(|value| value.as_str()))
                .push_bind(assessment.technical_impact.map(|value| value.as_str()))
                .push_bind(&fetched_at)
                .push_bind(&assessment.raw_json);
        });
        query.push(" ON CONFLICT(cve_id, provider, role) DO UPDATE SET version=excluded.version, assessed_at=excluded.assessed_at, exploitation=excluded.exploitation, automatable=excluded.automatable, technical_impact=excluded.technical_impact, fetched_at=excluded.fetched_at, raw_json=excluded.raw_json WHERE excluded.assessed_at >= ssvc_assessments.assessed_at");
        query.build().execute(&mut *transaction).await?;
    }
    Ok(())
}

impl SqlxDatabase {
    pub async fn ssvc_assessments(&self, cve_id: &str) -> Result<Vec<SsvcInfo>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows: Vec<SsvcRow> = sqlx::query_as("SELECT cve_id, provider, role, version, assessed_at, exploitation, automatable, technical_impact, fetched_at FROM ssvc_assessments WHERE cve_id=? ORDER BY provider, role")
                        .bind(cve_id)
                        .fetch_all(connection)
                        .await?;
                    rows.into_iter().map(ssvc_info).collect()
                })
            })
            .await
    }

    pub async fn ssvc_assessment_count(&self) -> Result<u64, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ssvc_assessments")
                        .fetch_one(connection)
                        .await?;
                    Ok(count.max(0) as u64)
                })
            })
            .await
    }
}

pub(super) fn ssvc_info(row: SsvcRow) -> Result<SsvcInfo, sqlx::Error> {
    let (
        cve_id,
        provider,
        role,
        version,
        assessed_at,
        exploitation,
        automatable,
        technical_impact,
        fetched_at,
    ) = row;
    Ok(SsvcInfo {
        cve_id,
        provider,
        role,
        version,
        assessed_at,
        exploitation: parse_optional(exploitation)?,
        automatable: parse_optional(automatable)?,
        technical_impact: parse_optional(technical_impact)?,
        fetched_at,
    })
}

fn parse_optional<T: FromStr<Err = String>>(
    value: Option<String>,
) -> Result<Option<T>, sqlx::Error> {
    value
        .map(|value| value.parse().map_err(sqlx::Error::Protocol))
        .transpose()
}
