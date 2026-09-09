pub(crate) mod tools;

use crate::db::DbProvider;
use rmcp::{ServiceExt, transport::stdio};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

const MAX_UPDATE_JOB_HISTORY: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UpdateJobSnapshot {
    pub(crate) job_id: String,
    pub(crate) status: String,
    pub(crate) stage: String,
    pub(crate) completed_steps: u8,
    pub(crate) total_steps: u8,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) finished_at_unix_ms: Option<u64>,
    pub(crate) error: Option<String>,
}

pub(crate) struct UpdateJobs {
    next_id: AtomicU64,
    records: RwLock<BTreeMap<u64, UpdateJobSnapshot>>,
}

impl UpdateJobs {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) async fn create(&self) -> Result<UpdateJobSnapshot, rmcp::ErrorData> {
        let mut records = self.records.write().await;
        if let Some(job) = records.values().find(|job| job.status == "running") {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "update already running; poll get_update_status for {}",
                    job.job_id
                ),
                None,
            ));
        }
        while records.len() >= MAX_UPDATE_JOB_HISTORY {
            records.pop_first();
        }
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = unix_ms();
        let snapshot = UpdateJobSnapshot {
            job_id: format!("update-{now}-{sequence}"),
            status: "running".to_owned(),
            stage: "waiting_for_update_writer".to_owned(),
            completed_steps: 0,
            total_steps: 2,
            created_at_unix_ms: now,
            finished_at_unix_ms: None,
            error: None,
        };
        records.insert(sequence, snapshot.clone());
        Ok(snapshot)
    }

    pub(crate) async fn set_updating(&self, job_id: &str) {
        if let Some(job) = self
            .records
            .write()
            .await
            .values_mut()
            .find(|job| job.job_id == job_id)
        {
            job.stage = "applying_updates_and_refreshing_sources".to_owned();
            job.completed_steps = 1;
        }
    }

    pub(crate) async fn finish(&self, job_id: &str, error: Option<String>) {
        if let Some(job) = self
            .records
            .write()
            .await
            .values_mut()
            .find(|job| job.job_id == job_id)
        {
            job.status = if error.is_some() { "failed" } else { "success" }.to_owned();
            job.stage = if error.is_some() {
                "failed"
            } else {
                "completed"
            }
            .to_owned();
            job.completed_steps = 2;
            job.finished_at_unix_ms = Some(unix_ms());
            job.error = error;
        }
    }

    pub(crate) async fn get(&self, job_id: &str) -> Option<UpdateJobSnapshot> {
        self.records
            .read()
            .await
            .values()
            .find(|job| job.job_id == job_id)
            .cloned()
    }
}

fn unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub(crate) struct CveSearchServer {
    pub(crate) db: DbProvider,
    pub(crate) update_jobs: Arc<UpdateJobs>,
}

impl CveSearchServer {
    pub(crate) fn new(db_url: String) -> Self {
        Self {
            db: DbProvider::new(db_url),
            update_jobs: Arc::new(UpdateJobs::new()),
        }
    }
}

pub(crate) async fn serve(db_url: String) -> Result<(), String> {
    let service = CveSearchServer::new(db_url)
        .serve(stdio())
        .await
        .map_err(|err| format!("failed to serve MCP over stdio: {err}"))?;
    service
        .waiting()
        .await
        .map_err(|err| format!("MCP server failed: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_jobs_report_running_success_and_failure() {
        let jobs = UpdateJobs::new();
        let running = jobs.create().await.unwrap();
        assert_eq!(running.status, "running");
        assert_eq!(running.completed_steps, 0);

        jobs.set_updating(&running.job_id).await;
        let updating = jobs.get(&running.job_id).await.unwrap();
        assert_eq!(updating.stage, "applying_updates_and_refreshing_sources");
        assert_eq!(updating.completed_steps, 1);

        jobs.finish(&running.job_id, None).await;
        let success = jobs.get(&running.job_id).await.unwrap();
        assert_eq!(success.status, "success");
        assert_eq!(success.completed_steps, success.total_steps);

        let failed = jobs.create().await.unwrap();
        jobs.finish(&failed.job_id, Some("fixture failure".to_owned()))
            .await;
        let failed = jobs.get(&failed.job_id).await.unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.error.as_deref(), Some("fixture failure"));
    }

    #[tokio::test]
    async fn update_job_snapshots_are_supported_by_the_mcp_json_encoder() {
        let snapshot = UpdateJobs::new().create().await.unwrap();

        simd_json::serde::to_owned_value(snapshot)
            .expect("update job timestamps must use JSON-compatible integers");
    }

    #[tokio::test]
    async fn concurrent_updates_are_rejected_and_history_is_bounded() {
        let jobs = UpdateJobs::new();
        let (first, second) = tokio::join!(jobs.create(), jobs.create());
        assert_ne!(first.is_ok(), second.is_ok());
        let running = first.or(second).unwrap();
        jobs.finish(&running.job_id, None).await;
        for _ in 0..MAX_UPDATE_JOB_HISTORY + 2 {
            let job = jobs.create().await.unwrap();
            jobs.finish(&job.job_id, None).await;
        }
        assert_eq!(jobs.records.read().await.len(), MAX_UPDATE_JOB_HISTORY);
        assert!(jobs.get(&running.job_id).await.is_none());
        let records = jobs.records.read().await;
        assert_eq!(*records.first_key_value().unwrap().0, 4);
        assert_eq!(*records.last_key_value().unwrap().0, 67);
    }
}
