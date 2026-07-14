//! CWE catalog import operations.

use super::super::*;

pub(crate) async fn upsert_cwe_catalog_on(
    txn: &DatabaseTransaction,
    catalog: &WeaknessCatalog,
) -> Result<usize, DbErr> {
    let mut rows = Vec::new();

    if let Some(weaknesses) = &catalog.weaknesses {
        for weakness in &weaknesses.weakness {
            rows.push(cwe_catalog_row(
                weakness.id,
                weakness.description.clone(),
                Some(&weakness.status),
                cwe_parent_id(&weakness.related_weaknesses)?,
            )?);
        }
    }
    if let Some(categories) = &catalog.categories {
        for category in &categories.category {
            rows.push(cwe_catalog_row(
                category.id,
                category.name.clone(),
                Some(&category.status),
                None,
            )?);
        }
    }
    if let Some(views) = &catalog.views {
        for view in &views.view {
            rows.push(cwe_catalog_row(
                view.id,
                view.name.clone(),
                Some(&view.status),
                None,
            )?);
        }
    }

    let count = rows.len();
    for chunk in take_chunks(rows, CWE_MASTER_CHUNK_SIZE) {
        upsert_cwe_rows(txn, chunk).await?;
    }
    Ok(count)
}

fn cwe_catalog_row(
    id: i64,
    description: String,
    status: Option<&qanvuli_models::cwe::enumeration::Status>,
    parent_id: Option<i32>,
) -> Result<cwe::ActiveModel, DbErr> {
    Ok(cwe::ActiveModel {
        id: Set(i32::try_from(id)
            .map_err(|err| DbErr::Custom(format!("CWE ID {id} does not fit in i32: {err}")))?),
        description: Set(Some(description)),
        status: Set(status.map(|status| status.as_ref().to_owned())),
        parent_id: Set(parent_id),
    })
}

fn cwe_parent_id(
    related_weaknesses: &Option<qanvuli_models::cwe::common::RelatedWeaknesses>,
) -> Result<Option<i32>, DbErr> {
    let Some(related_weaknesses) = related_weaknesses else {
        return Ok(None);
    };
    related_weaknesses
        .related_weakness
        .iter()
        .find(|related| matches!(related.nature, RelatedNature::ChildOf))
        .map(|related| {
            i32::try_from(related.cwe_id).map_err(|err| {
                DbErr::Custom(format!(
                    "parent CWE ID {} does not fit in i32: {err}",
                    related.cwe_id
                ))
            })
        })
        .transpose()
}
