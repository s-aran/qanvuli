//! CVE parent-row writes and bulk insertion orchestration.

use super::super::*;

pub(crate) async fn upsert_cve_on<C>(db: &C, model: cve::ActiveModel) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    cve::Entity::insert(model)
        .on_conflict(cve_upsert_conflict())
        .exec(db)
        .await?;

    Ok(())
}

pub(crate) async fn upsert_cve_model_batch(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    let mut cve_ids = Vec::with_capacity(models.len());
    let mut cve_rows = Vec::with_capacity(models.len());

    for model in &models {
        cve_ids.push(model.cve_id.clone());
        cve_rows.push(model.cve.clone());
    }

    let inserted = cve_rows.len();
    let cve_db_ids = upsert_cve_rows_returning(txn, cve_rows).await?;
    let (cvss_rows, affected_rows, cwe_master_rows, cwe_rows) =
        child_rows_with_cve_db_ids(models, &cve_db_ids)?;
    let cve_db_id_values = cve_ids
        .iter()
        .filter_map(|cve_id| cve_db_ids.get(cve_id).copied())
        .collect::<Vec<_>>();

    cve_cvss::Entity::delete_many()
        .filter(cve_cvss::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;
    cve_affected::Entity::delete_many()
        .filter(cve_affected::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;
    cve_cwe::Entity::delete_many()
        .filter(cve_cwe::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;

    for chunk in take_chunks(cvss_rows, CVSS_CHUNK_SIZE) {
        cve_cvss::Entity::insert_many(chunk).exec(txn).await?;
    }
    for chunk in take_chunks(affected_rows, AFFECTED_CHUNK_SIZE) {
        cve_affected::Entity::insert_many(chunk).exec(txn).await?;
    }
    for chunk in take_chunks(cwe_master_rows, CWE_MASTER_CHUNK_SIZE) {
        cwe::Entity::insert_many(chunk)
            .on_conflict(cwe_upsert_conflict())
            .exec(txn)
            .await?;
    }
    for chunk in take_chunks(cwe_rows, CWE_CHUNK_SIZE) {
        cve_cwe::Entity::insert_many(chunk).exec(txn).await?;
    }
    upsert_cve_summary_index_rows(txn, &cve_ids).await?;

    Ok(inserted)
}

pub(crate) async fn insert_cve_models_on(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
    update_search_index: bool,
) -> Result<usize, DbErr> {
    let mut inserted = 0usize;
    let mut batch = Vec::with_capacity(CVE_CHUNK_SIZE);

    for models in models {
        batch.push(models);
        if batch.len() == CVE_CHUNK_SIZE {
            inserted +=
                insert_cve_model_batch(txn, std::mem::take(&mut batch), update_search_index)
                    .await?;
            batch = Vec::with_capacity(CVE_CHUNK_SIZE);
        }
    }

    if !batch.is_empty() {
        inserted += insert_cve_model_batch(txn, batch, update_search_index).await?;
    }

    Ok(inserted)
}

async fn insert_cve_model_batch(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
    update_search_index: bool,
) -> Result<usize, DbErr> {
    let mut cve_rows = Vec::with_capacity(models.len());
    let mut cve_ids = Vec::with_capacity(models.len());

    for model in &models {
        cve_ids.push(model.cve_id.clone());
        cve_rows.push(model.cve.clone());
    }

    let inserted = cve_rows.len();
    let cve_db_ids = insert_cve_rows_returning(txn, cve_rows).await?;
    let (cvss_rows, affected_rows, cwe_master_rows, cwe_rows) =
        child_rows_with_cve_db_ids(models, &cve_db_ids)?;

    for chunk in take_chunks(cvss_rows, CVSS_CHUNK_SIZE) {
        insert_cvss_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(affected_rows, AFFECTED_CHUNK_SIZE) {
        insert_affected_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(cwe_master_rows, CWE_MASTER_CHUNK_SIZE) {
        upsert_cwe_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(cwe_rows, CWE_CHUNK_SIZE) {
        insert_cwe_rows(txn, chunk).await?;
    }
    if update_search_index {
        upsert_cve_summary_index_rows(txn, &cve_ids).await?;
    }

    Ok(inserted)
}
