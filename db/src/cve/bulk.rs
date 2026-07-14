//! Streaming CVE bulk-replacement session operations.

use super::super::*;

/// Transaction-backed session for streaming a full CVE replacement import.
pub struct CveBulkReplaceSession {
    pub(crate) txn: DatabaseTransaction,
}

impl CveBulkReplaceSession {
    pub async fn insert_cve_records(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.insert_cve_models(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

    pub async fn insert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        insert_cve_models_on(&self.txn, models, false).await
    }

    pub async fn insert_cve_raw_json_strings(&self, values: Vec<String>) -> Result<usize, DbErr> {
        self.insert_cve_models(
            values
                .into_iter()
                .map(CveActiveModels::from_raw_json_string)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
    }

    pub async fn mark_json_files_read(
        &self,
        files: Vec<ReadJsonFileRecord>,
    ) -> Result<usize, DbErr> {
        mark_json_files_read_on(&self.txn, files, false).await
    }

    pub async fn finish(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_on(&db.db).await
    }

    pub async fn finish_storage_only(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_storage_on(&db.db).await
    }

    pub async fn finish_storage_with_text_search(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_storage_with_text_search_on(&db.db).await
    }
}
