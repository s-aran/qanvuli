//! Same-directory, rollback-capable SQLite database replacement.

use std::path::{Path, PathBuf};

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

/// Explicit state machine for installing a fully closed and validated database.
#[derive(Debug)]
pub struct DatabaseReplacement {
    target: PathBuf,
    candidate: PathBuf,
    backup: PathBuf,
    state: ReplacementState,
    had_target: bool,
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
        })
    }

    pub fn backup_path(&self) -> &Path {
        &self.backup
    }

    pub fn install(&mut self) -> Result<(), ReplacementError> {
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
            std::fs::rename(&self.target, &self.backup).map_err(|source| {
                ReplacementError::BackupRename {
                    source,
                    target: self.target.clone(),
                    backup: self.backup.clone(),
                }
            })?;
            self.state = ReplacementState::BackedUp;
        }

        // Old sidecars must never become associated with the newly installed main file. This is
        // deliberately done after the backup rename, so a backup-rename failure leaves the target
        // set untouched, and before candidate installation, so interruption cannot expose a new
        // main file beside stale WAL contents.
        for suffix in SQLITE_SIDECAR_SUFFIXES {
            let path = sidecar(&self.target, suffix);
            if let Err(source) = remove_if_present(&path) {
                if self.had_target
                    && let Err(ReplacementError::Restore {
                        source: restore, ..
                    }) = self.rollback()
                {
                    return Err(ReplacementError::InstallAndRestore {
                        install: source,
                        restore,
                        candidate: self.candidate.clone(),
                        target: self.target.clone(),
                        backup: self.backup.clone(),
                    });
                }
                return Err(ReplacementError::Cleanup { source, path });
            }
        }

        if let Err(source) = std::fs::rename(&self.candidate, &self.target) {
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
        std::fs::rename(&self.backup, &self.target).map_err(|source| {
            ReplacementError::Restore {
                source,
                target: self.target.clone(),
                backup: self.backup.clone(),
            }
        })?;
        self.state = ReplacementState::Ready;
        Ok(())
    }

    /// Finalizes a successful install. Cleanup errors never roll back the new database.
    pub fn commit(&mut self) -> Result<(), ReplacementError> {
        if self.state != ReplacementState::Installed {
            return Err(ReplacementError::InvalidState {
                state: "replacement is not installed",
            });
        }
        if self.had_target {
            remove_sqlite_database_files(&self.backup).map_err(|source| {
                ReplacementError::Cleanup {
                    source,
                    path: self.backup.clone(),
                }
            })?;
        }
        self.state = ReplacementState::Committed;
        Ok(())
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

    #[test]
    fn installs_and_commits_closed_replacement() {
        let directory = directory("success");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        std::fs::write(&target, "old").unwrap();
        std::fs::write(sidecar(&target, "wal"), "old wal").unwrap();
        std::fs::write(&candidate, "new").unwrap();
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        replacement.install().unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert!(!sidecar(&target, "wal").exists());
        assert!(replacement.backup_path().exists());
        replacement.commit().unwrap();
        assert!(!replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_candidate_does_not_touch_target_or_create_backup() {
        let directory = directory("missing");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        std::fs::write(&target, "old").unwrap();
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        assert!(matches!(
            replacement.install(),
            Err(ReplacementError::CandidateMissing { .. })
        ));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
        assert!(!replacement.backup_path().exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refuses_candidate_sidecars_without_touching_target() {
        let directory = directory("sidecar");
        let target = directory.join("database.sqlite");
        let candidate = candidate_database_path(&target).unwrap();
        std::fs::write(&target, "old").unwrap();
        std::fs::write(&candidate, "new").unwrap();
        std::fs::write(sidecar(&candidate, "journal"), "open").unwrap();
        let mut replacement = DatabaseReplacement::new(target.clone(), candidate).unwrap();
        assert!(matches!(
            replacement.install(),
            Err(ReplacementError::CandidateNotClosed { .. })
        ));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
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
}
