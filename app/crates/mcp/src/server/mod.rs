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

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UpdateJobSnapshot {
    pub(crate) job_id: String,
    pub(crate) status: String,
    pub(crate) stage: String,
    pub(crate) completed_steps: u8,
    pub(crate) total_steps: u8,
    pub(crate) created_at_unix_ms: u128,
    pub(crate) finished_at_unix_ms: Option<u128>,
    pub(crate) error: Option<String>,
}

pub(crate) struct UpdateJobs {
    next_id: AtomicU64,
    records: RwLock<BTreeMap<String, UpdateJobSnapshot>>,
}

impl UpdateJobs {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            records: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) async fn create(&self) -> UpdateJobSnapshot {
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = unix_ms();
        let snapshot = UpdateJobSnapshot {
            job_id: format!("update-{now}-{sequence}"),
            status: "running".to_owned(),
            stage: "waiting_for_exclusive_database".to_owned(),
            completed_steps: 0,
            total_steps: 2,
            created_at_unix_ms: now,
            finished_at_unix_ms: None,
            error: None,
        };
        self.records
            .write()
            .await
            .insert(snapshot.job_id.clone(), snapshot.clone());
        snapshot
    }

    pub(crate) async fn set_updating(&self, job_id: &str) {
        if let Some(job) = self.records.write().await.get_mut(job_id) {
            job.stage = "applying_updates_and_refreshing_sources".to_owned();
            job.completed_steps = 1;
        }
    }

    pub(crate) async fn finish(&self, job_id: &str, error: Option<String>) {
        if let Some(job) = self.records.write().await.get_mut(job_id) {
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
        self.records.read().await.get(job_id).cloned()
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
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
        let running = jobs.create().await;
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

        let failed = jobs.create().await;
        jobs.finish(&failed.job_id, Some("fixture failure".to_owned()))
            .await;
        let failed = jobs.get(&failed.job_id).await.unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.error.as_deref(), Some("fixture failure"));
    }
}
