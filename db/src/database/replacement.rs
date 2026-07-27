//! Same-directory, rollback-capable SQLite database replacement.

use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

const SQLITE_SIDECAR_SUFFIXES: [&str; 3] = ["wal", "shm", "journal"];

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}-{suffix}", path.display()))
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn sibling_path(target: &Path, marker: &str, suffix: &str) -> Result<PathBuf, ReplacementError> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ReplacementError::InvalidPath {
            path: target.to_path_buf(),
            reason: "database file name is not valid UTF-8".to_owned(),
        })?;
    Ok(parent.join(format!("{file_name}.{marker}-{suffix}")))
}

/// Creates a unique candidate path beside `target`, keeping later renames on one filesystem.
pub fn candidate_database_path(target: &Path) -> Result<PathBuf, ReplacementError> {
    sibling_path(target, "qanvuli-new", &unique_suffix())
}

/// Removes a SQLite main file and all sidecars owned by that file.
pub fn remove_sqlite_database_files(path: &Path) -> std::io::Result<()> {
    remove_if_present(path)?;
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        remove_if_present(&sidecar(path, suffix))?;
    }
    Ok(())
}

/// Removes unfinished replacement candidates for `target` and their SQLite sidecars.
///
/// Callers must obtain explicit user confirmation before using this: a candidate may
/// belong to an initialization process that is still running.
pub fn remove_interrupted_replacement_candidates(
    target: &Path,
) -> Result<Vec<PathBuf>, ReplacementError> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ReplacementError::InvalidPath {
            path: target.to_path_buf(),
            reason: "database file name is not valid UTF-8".to_owned(),
        })?;
    let candidate_prefix = format!("{file_name}.qanvuli-new-");
    let mut candidates = Vec::new();
    let entries = std::fs::read_dir(parent).map_err(|source| ReplacementError::Cleanup {
        source,
        path: parent.to_path_buf(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ReplacementError::Cleanup {
            source,
            path: parent.to_path_buf(),
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&candidate_prefix)
            && !SQLITE_SIDECAR_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(&format!("-{suffix}")))
        {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    for candidate in &candidates {
        remove_sqlite_database_files(candidate).map_err(|source| ReplacementError::Cleanup {
            source,
            path: candidate.clone(),
        })?;
    }
    Ok(candidates)
}

#[derive(Debug, thiserror::Error)]
pub enum ReplacementError {
    #[error("invalid database path {path}: {reason}")]
    InvalidPath { path: PathBuf, reason: String },
    #[error("replacement path {candidate} must be in the same directory as target {target}")]
    DifferentFilesystem { target: PathBuf, candidate: PathBuf },
    #[error("replacement path already exists: {path}")]
    PathConflict { path: PathBuf },
    #[error("replacement database is not closed: sidecar still exists at {path}")]
    CandidateNotClosed { path: PathBuf },
    #[error("replacement database does not exist: {path}")]
    CandidateMissing { path: PathBuf },
    #[error(
        "refused to replace active database {path} because its WAL could not be checkpointed safely: {source}"
    )]
    TargetCheckpointFailed {
        #[source]
        source: sqlx::Error,
        path: PathBuf,
    },
    #[error(
        "refused to replace active database {path} because WAL checkpointing reported it is busy (busy={busy}, log_frames={log_frames}, checkpointed_frames={checkpointed_frames}); close other SQLite users and retry"
    )]
    TargetCheckpointBusy {
        path: PathBuf,
        busy: i64,
        log_frames: i64,
        checkpointed_frames: i64,
    },
    #[error(
        "refused to replace active database {path} because the checkpoint connection could not be closed safely: {source}"
    )]
    TargetCloseFailed {
        #[source]
        source: sqlx::Error,
        path: PathBuf,
    },
    #[error(
        "refused to replace active database {path} to avoid losing WAL or journal data; SQLite sidecars remain after checkpoint and close: {sidecars:?}. Close other SQLite users and inspect these files before retrying"
    )]
    TargetNotClosed {
        path: PathBuf,
        sidecars: Vec<PathBuf>,
    },
    #[error("failed to move active database {target} to backup {backup}: {source}")]
    BackupRename {
        #[source]
        source: std::io::Error,
        target: PathBuf,
        backup: PathBuf,
    },
    #[error("failed to install replacement {candidate} as {target}: {source}")]
    CandidateInstall {
        #[source]
        source: std::io::Error,
        candidate: PathBuf,
        target: PathBuf,
    },
    #[error(
        "failed to install replacement {candidate} as {target}: {install}; restoration also failed: {restore}. Backup: {backup}. Candidate: {candidate}. Manual recovery: move {backup} back to {target} after preserving and inspecting both files"
    )]
    InstallAndRestore {
        #[source]
        install: std::io::Error,
        restore: std::io::Error,
        candidate: PathBuf,
        target: PathBuf,
        backup: PathBuf,
    },
    #[error("failed to restore backup {backup} to {target}: {source}")]
    Restore {
        #[source]
        source: std::io::Error,
        target: PathBuf,
        backup: PathBuf,
    },
    #[error("failed to clean up SQLite file {path}: {source}")]
    Cleanup {
        #[source]
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("ambiguous interrupted replacement state for {target}; inspect manually: {paths:?}")]
    AmbiguousState {
        target: PathBuf,
        paths: Vec<PathBuf>,
    },
    #[error(
        "replacement candidate {candidate} exists while inspecting {target}; it was not promoted or deleted because another initialization may still own it. Inspect it manually"
    )]
    CandidateRequiresInspection { target: PathBuf, candidate: PathBuf },
    #[error("database replacement operation is invalid in state {state}")]
    InvalidState { state: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplacementState {
    Ready,
    BackedUp,
    Installed,
    Committed,
}

/// Installs a closed, schema-validated replacement database.
#[derive(Debug)]
pub struct DatabaseReplacement {
    target: PathBuf,
    candidate: PathBuf,
    backup: PathBuf,
    state: ReplacementState,
    had_target: bool,
    #[cfg(test)]
    fail_candidate_install: bool,
    #[cfg(test)]
    fail_restore: bool,
    #[cfg(test)]
    fail_backup_cleanup: bool,
}

impl DatabaseReplacement {
    pub fn new(target: PathBuf, candidate: PathBuf) -> Result<Self, ReplacementError> {
        if target.parent() != candidate.parent() {
            return Err(ReplacementError::DifferentFilesystem { target, candidate });
        }
        let backup = sibling_path(&target, "qanvuli-old", &unique_suffix())?;
        if backup.exists() {
            return Err(ReplacementError::PathConflict { path: backup });
        }
        Ok(Self {
            target,
            candidate,
            backup,
            state: ReplacementState::Ready,
            had_target: false,
            #[cfg(test)]
            fail_candidate_install: false,
            #[cfg(test)]
            fail_restore: false,
            #[cfg(test)]
            fail_backup_cleanup: false,
        })
    }

    pub fn backup_path(&self) -> &Path {
        &self.backup
    }

    pub async fn install(&mut self) -> Result<(), ReplacementError> {
        if self.state != ReplacementState::Ready {
            return Err(ReplacementError::InvalidState { state: "not ready" });
        }
        if !self.candidate.is_file() {
            return Err(ReplacementError::CandidateMissing {
                path: self.candidate.clone(),
            });
        }
        for suffix in SQLITE_SIDECAR_SUFFIXES {
            let path = sidecar(&self.candidate, suffix);
            if path.exists() {
                return Err(ReplacementError::CandidateNotClosed { path });
            }
        }

        self.had_target = self.target.exists();
        if self.had_target {
            checkpoint_and_close_target(&self.target).await?;
        }
        ensure_target_has_no_sidecars(&self.target)?;

        if self.had_target {
            std::fs::rename(&self.target, &self.backup).map_err(|source| {
                ReplacementError::BackupRename {
                    source,
                    target: self.target.clone(),
                    backup: self.backup.clone(),
                }
            })?;
            self.state = ReplacementState::BackedUp;
        }

        let install_result = {
            #[cfg(test)]
            if self.fail_candidate_install {
                Err(std::io::Error::other("injected candidate install failure"))
            } else {
                std::fs::rename(&self.candidate, &self.target)
            }
            #[cfg(not(test))]
            std::fs::rename(&self.candidate, &self.target)
        };
        if let Err(source) = install_result {
            if self.had_target {
                return match self.rollback() {
                    Ok(()) => Err(ReplacementError::CandidateInstall {
                        source,
                        candidate: self.candidate.clone(),
                        target: self.target.clone(),
                    }),
                    Err(ReplacementError::Restore {
                        source: restore, ..
                    }) => Err(ReplacementError::InstallAndRestore {
                        install: source,
                        restore,
                        candidate: self.candidate.clone(),
                        target: self.target.clone(),
                        backup: self.backup.clone(),
                    }),
                    Err(error) => Err(error),
                };
            }
            return Err(ReplacementError::CandidateInstall {
                source,
                candidate: self.candidate.clone(),
                target: self.target.clone(),
            });
        }
        self.state = ReplacementState::Installed;
        Ok(())
    }

    /// Restores the previous database after its main file has been moved aside.
    pub fn rollback(&mut self) -> Result<(), ReplacementError> {
        if self.state != ReplacementState::BackedUp {
            return Err(ReplacementError::InvalidState {
                state: "backup is not pending",
            });
        }
        let restore_result = {
            #[cfg(test)]
            if self.fail_restore {
                Err(std::io::Error::other("injected backup restore failure"))
            } else {
                std::fs::rename(&self.backup, &self.target)
            }
            #[cfg(not(test))]
            std::fs::rename(&self.backup, &self.target)
        };
        restore_result.map_err(|source| ReplacementError::Restore {
            source,
            target: self.target.clone(),
            backup: self.backup.clone(),
        })?;
        self.state = ReplacementState::Ready;
        Ok(())
    }

    /// Commits the install without rolling back for cleanup errors.
    pub fn commit(&mut self) -> Result<(), ReplacementError> {
        if self.state != ReplacementState::Installed {
            return Err(ReplacementError::InvalidState {
                state: "replacement is not installed",
            });
        }
        if self.had_target {
            let cleanup_result = {
                #[cfg(test)]
                if self.fail_backup_cleanup {
                    Err(std::io::Error::other("injected backup cleanup failure"))
                } else {
                    remove_if_present(&self.backup)
                }
                #[cfg(not(test))]
                remove_if_present(&self.backup)
            };
            cleanup_result.map_err(|source| ReplacementError::Cleanup {
                source,
                path: self.backup.clone(),
            })?;
        }
        self.state = ReplacementState::Committed;
        Ok(())
    }
}

async fn checkpoint_and_close_target(path: &Path) -> Result<(), ReplacementError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|source| ReplacementError::TargetCheckpointFailed {
            source,
            path: path.to_path_buf(),
        })?;
    let checkpoint = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&mut connection)
        .await
        .map_err(|source| ReplacementError::TargetCheckpointFailed {
            source,
            path: path.to_path_buf(),
        });
    let checkpoint = match checkpoint {
        Ok(row) => {
            let values = (
                row.try_get::<i64, _>(0),
                row.try_get::<i64, _>(1),
                row.try_get::<i64, _>(2),
            );
            match values {
                (Ok(busy), Ok(log_frames), Ok(checkpointed_frames)) => {
                    Ok((busy, log_frames, checkpointed_frames))
                }
                _ => Err(ReplacementError::TargetCheckpointFailed {
                    source: sqlx::Error::Protocol(
                        "SQLite returned an invalid wal_checkpoint result".to_owned(),
                    ),
                    path: path.to_path_buf(),
                }),
            }
        }
        Err(error) => Err(error),
    };
    let close = connection
        .close()
        .await
        .map_err(|source| ReplacementError::TargetCloseFailed {
            source,
            path: path.to_path_buf(),
        });
    let (busy, log_frames, checkpointed_frames) = checkpoint?;
    close?;
    if busy != 0 {
        return Err(ReplacementError::TargetCheckpointBusy {
            path: path.to_path_buf(),
            busy,
            log_frames,
            checkpointed_frames,
        });
    }
    Ok(())
}

fn ensure_target_has_no_sidecars(path: &Path) -> Result<(), ReplacementError> {
    let sidecars = SQLITE_SIDECAR_SUFFIXES
        .iter()
        .map(|suffix| sidecar(path, suffix))
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if sidecars.is_empty() {
        Ok(())
    } else {
        Err(ReplacementError::TargetNotClosed {
            path: path.to_path_buf(),
            sidecars,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    RestoredBackup(PathBuf),
    StaleBackup(PathBuf),
}

/// Inspects only qanvuli-named siblings and applies the bounded, unambiguous recovery policy.
pub fn recover_interrupted_replacement(
    target: &Path,
) -> Result<Vec<RecoveryAction>, ReplacementError> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ReplacementError::InvalidPath {
            path: target.to_path_buf(),
            reason: "database file name is not valid UTF-8".to_owned(),
        })?;
    let candidate_prefix = format!("{file_name}.qanvuli-new-");
    let backup_prefix = format!("{file_name}.qanvuli-old-");
    let mut candidates = Vec::new();
    let mut backups = Vec::new();
    let entries = std::fs::read_dir(parent).map_err(|source| ReplacementError::Cleanup {
        source,
        path: parent.to_path_buf(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ReplacementError::Cleanup {
            source,
            path: parent.to_path_buf(),
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if SQLITE_SIDECAR_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(&format!("-{suffix}")))
        {
            continue;
        }
        if name.starts_with(&candidate_prefix) {
            candidates.push(entry.path());
        } else if name.starts_with(&backup_prefix) {
            backups.push(entry.path());
        }
    }
    candidates.sort();
    backups.sort();
    if candidates.len() > 1 || backups.len() > 1 || (!candidates.is_empty() && !backups.is_empty())
    {
        let mut paths = backups;
        paths.extend(candidates);
        paths.sort();
        return Err(ReplacementError::AmbiguousState {
            target: target.to_path_buf(),
            paths,
        });
    }

    let mut actions = Vec::new();
    if let Some(backup) = backups.pop() {
        if target.exists() {
            actions.push(RecoveryAction::StaleBackup(backup));
        } else {
            std::fs::rename(&backup, target).map_err(|source| ReplacementError::Restore {
                source,
                target: target.to_path_buf(),
                backup: backup.clone(),
            })?;
            actions.push(RecoveryAction::RestoredBackup(backup));
        }
    } else if let Some(candidate) = candidates.pop() {
        return Err(ReplacementError::CandidateRequiresInspection {
            target: target.to_path_buf(),
            candidate,
        });
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-replace-{label}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    async fn create_database(path: &Path, value: &str) {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("CREATE TABLE marker (value TEXT NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO marker (value) VALUES (?)")
            .bind(value)
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
    }

    async fn create_uncheckpointed_wal_database(path: &Path, value: &str) {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA wal_autocheckpoint = 0")
            .execute(&mut connection)
            .await
            .unwrap();
        {
            let mut handle = connection.lock_handle().await.unwrap();
            let mut enabled = 0;
            // SAFETY: the SQLx handle is locked for this call and SQLite documents this
            // configuration as accepting an integer flag plus an integer result pointer.
            let result = unsafe {
                libsqlite3_sys::sqlite3_db_config(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                    1,
                    &mut enabled,
                )
            };
            assert_eq!(result, libsqlite3_sys::SQLITE_OK);
            assert_eq!(enabled, 1);
        }
        sqlx::query("CREATE TABLE marker (value TEXT NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO marker (value) VALUES (?)")
            .bind(value)
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        assert!(std::fs::metadata(sidecar(path, "wal")).unwrap().len() > 32);
    }

    async fn read_marker(path: &Path) -> String {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        let value = sqlx::query_scalar("SELECT value FROM marker")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        value
    }

    #[tokio::test]
    async fn installs_and_commits_closed_replacement() {
        let directory = directory("success");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_uncheckpointed_wal_database(&target, "old").await;
        create_database(&candidate, "new").await;
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        replacement.install().await.unwrap();
        assert_eq!(read_marker(&target).await, "new");
        assert!(!sidecar(&target, "wal").exists());
        assert!(replacement.backup_path().exists());
        replacement.commit().unwrap();
        assert!(!replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn missing_candidate_does_not_touch_target_or_create_backup() {
        let directory = directory("missing");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&target, "old").await;
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::CandidateMissing { .. })
        ));
        assert_eq!(read_marker(&target).await, "old");
        assert!(!replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn refuses_real_candidate_sidecars_without_touching_target() {
        let directory = directory("sidecar");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&target, "old").await;
        let options = SqliteConnectOptions::new()
            .filename(&candidate)
            .create_if_missing(true);
        let mut candidate_connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&mut candidate_connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE marker (value TEXT NOT NULL)")
            .execute(&mut candidate_connection)
            .await
            .unwrap();
        assert!(sidecar(&candidate, "wal").exists());
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::CandidateNotClosed { .. })
        ));
        assert_eq!(read_marker(&target).await, "old");
        candidate_connection.close().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn refuses_active_wal_target_without_deleting_real_sidecars() {
        let directory = directory("active-target");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&candidate, "new").await;

        let options = SqliteConnectOptions::new()
            .filename(&target)
            .create_if_missing(true);
        let mut active = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&mut active)
            .await
            .unwrap();
        sqlx::query("PRAGMA wal_autocheckpoint = 0")
            .execute(&mut active)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE marker (value TEXT NOT NULL)")
            .execute(&mut active)
            .await
            .unwrap();
        sqlx::query("INSERT INTO marker (value) VALUES ('committed')")
            .execute(&mut active)
            .await
            .unwrap();
        assert!(sidecar(&target, "wal").exists());

        let mut replacement = DatabaseReplacement::new(target.clone(), candidate.clone()).unwrap();
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::TargetNotClosed { .. })
        ));
        assert!(target.exists());
        assert!(candidate.exists());
        assert!(!replacement.backup_path().exists());
        assert!(sidecar(&target, "wal").exists());

        active.close().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn refuses_active_rollback_journal_without_deleting_it() {
        let directory = directory("active-journal");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&target, "old").await;
        create_database(&candidate, "new").await;

        let options = SqliteConnectOptions::new()
            .filename(&target)
            .create_if_missing(false);
        let mut active = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA journal_mode = DELETE")
            .execute(&mut active)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut active)
            .await
            .unwrap();
        sqlx::query("UPDATE marker SET value = 'uncommitted'")
            .execute(&mut active)
            .await
            .unwrap();
        let journal = sidecar(&target, "journal");
        assert!(journal.exists());

        let mut replacement = DatabaseReplacement::new(target.clone(), candidate.clone()).unwrap();
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::TargetNotClosed { .. })
                | Err(ReplacementError::TargetCheckpointFailed { .. })
                | Err(ReplacementError::TargetCheckpointBusy { .. })
        ));
        assert!(target.exists());
        assert!(candidate.exists());
        assert!(!replacement.backup_path().exists());
        assert!(journal.exists());

        sqlx::query("ROLLBACK").execute(&mut active).await.unwrap();
        active.close().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn failed_install_restores_real_sqlite_target_and_preserves_candidate() {
        let directory = directory("rollback");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_uncheckpointed_wal_database(&target, "committed old data").await;
        create_database(&candidate, "new").await;

        let mut replacement = DatabaseReplacement::new(target.clone(), candidate.clone()).unwrap();
        replacement.fail_candidate_install = true;
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::CandidateInstall { .. })
        ));
        assert_eq!(read_marker(&target).await, "committed old data");
        assert!(candidate.exists());
        assert!(!replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn reports_install_and_restore_failure_with_all_recovery_files_preserved() {
        let directory = directory("double-failure");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&target, "old").await;
        create_database(&candidate, "new").await;

        let mut replacement = DatabaseReplacement::new(target.clone(), candidate.clone()).unwrap();
        replacement.fail_candidate_install = true;
        replacement.fail_restore = true;
        let backup = replacement.backup_path().to_path_buf();
        assert!(matches!(
            replacement.install().await,
            Err(ReplacementError::InstallAndRestore { .. })
        ));
        assert!(!target.exists());
        assert!(candidate.exists());
        assert!(backup.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn backup_cleanup_failure_keeps_active_replacement_and_backup() {
        let directory = directory("cleanup-failure");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        create_database(&target, "old").await;
        create_database(&candidate, "new").await;

        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        replacement.install().await.unwrap();
        replacement.fail_backup_cleanup = true;
        assert!(matches!(
            replacement.commit(),
            Err(ReplacementError::Cleanup { .. })
        ));
        assert_eq!(read_marker(&target).await, "new");
        assert!(replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restores_single_backup_and_never_promotes_or_deletes_candidate() {
        let directory = directory("recovery");
        let target = directory.join("database.sqlite");
        let backup = sibling_path(&target, "qanvuli-old", "1-1").unwrap();
        std::fs::write(&backup, "old").unwrap();
        assert_eq!(
            recover_interrupted_replacement(&target).unwrap(),
            vec![RecoveryAction::RestoredBackup(backup)]
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");

        std::fs::remove_file(&target).unwrap();
        let candidate = sibling_path(&target, "qanvuli-new", "1-2").unwrap();
        std::fs::write(&candidate, "incomplete").unwrap();
        assert!(matches!(
            recover_interrupted_replacement(&target),
            Err(ReplacementError::CandidateRequiresInspection { .. })
        ));
        assert!(candidate.exists());
        assert!(!target.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_ambiguous_recovery_state() {
        let directory = directory("ambiguous");
        let target = directory.join("database.sqlite");
        for suffix in ["1-1", "1-2"] {
            std::fs::write(sibling_path(&target, "qanvuli-old", suffix).unwrap(), "old").unwrap();
        }
        assert!(matches!(
            recover_interrupted_replacement(&target),
            Err(ReplacementError::AmbiguousState { .. })
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn explicitly_removes_all_interrupted_candidates_and_sidecars() {
        let directory = directory("discard-candidates");
        let target = directory.join("database.sqlite");
        let first = sibling_path(&target, "qanvuli-new", "1-1").unwrap();
        let second = sibling_path(&target, "qanvuli-new", "1-2").unwrap();
        std::fs::write(&first, "incomplete").unwrap();
        std::fs::write(sidecar(&first, "wal"), "wal").unwrap();
        std::fs::write(&second, "incomplete").unwrap();

        assert_eq!(
            remove_interrupted_replacement_candidates(&target).unwrap(),
            vec![first.clone(), second.clone()]
        );
        assert!(!first.exists());
        assert!(!sidecar(&first, "wal").exists());
        assert!(!second.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
