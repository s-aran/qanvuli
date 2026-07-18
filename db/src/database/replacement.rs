//! Same-directory atomic SQLite database replacement.

use std::path::{Path, PathBuf};

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}-{suffix}", path.display()))
}

fn rename_if_present(from: &Path, to: &Path) -> std::io::Result<bool> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Replaces `target` with a fully closed, validated temporary database.
///
/// The caller builds and validates `replacement` before calling this function.
pub fn install_closed_database(replacement: &Path, target: &Path) -> std::io::Result<()> {
    let backup = sidecar(target, "backup");
    remove_if_present(&backup)?;
    for suffix in ["wal", "shm"] {
        remove_if_present(&sidecar(&backup, suffix))?;
    }
    for suffix in ["wal", "shm"] {
        if sidecar(replacement, suffix).exists() {
            return Err(std::io::Error::other(format!(
                "replacement database is not closed: {} exists",
                sidecar(replacement, suffix).display()
            )));
        }
    }
    let had_target = target.exists();
    if had_target {
        std::fs::rename(target, &backup)?;
        let mut moved_sidecars = Vec::new();
        for suffix in ["wal", "shm"] {
            match rename_if_present(&sidecar(target, suffix), &sidecar(&backup, suffix)) {
                Ok(true) => moved_sidecars.push(suffix),
                Ok(false) => {}
                Err(error) => {
                    for moved in moved_sidecars.into_iter().rev() {
                        let _ =
                            rename_if_present(&sidecar(&backup, moved), &sidecar(target, moved));
                    }
                    let _ = std::fs::rename(&backup, target);
                    return Err(error);
                }
            }
        }
    }
    match std::fs::rename(replacement, target) {
        Ok(()) => {
            if had_target {
                remove_if_present(&backup)?;
                for suffix in ["wal", "shm"] {
                    remove_if_present(&sidecar(&backup, suffix))?;
                }
            }
            Ok(())
        }
        Err(error) => {
            if had_target {
                let restore = std::fs::rename(&backup, target);
                for suffix in ["wal", "shm"] {
                    let _ = rename_if_present(&sidecar(&backup, suffix), &sidecar(target, suffix));
                }
                restore?;
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_only_the_closed_replacement_file() {
        let directory =
            std::env::temp_dir().join(format!("qanvuli-replace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("database.sqlite");
        let replacement = directory.join("database.sqlite.new");
        std::fs::write(&target, "old").unwrap();
        std::fs::write(&replacement, "new").unwrap();
        install_closed_database(&replacement, &target).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn failed_install_keeps_the_previous_database() {
        let directory =
            std::env::temp_dir().join(format!("qanvuli-replace-failure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("database.sqlite");
        let missing_replacement = directory.join("missing.sqlite.new");
        std::fs::write(&target, "old").unwrap();
        assert!(install_closed_database(&missing_replacement, &target).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn replacement_refuses_an_open_wal_database_without_touching_target() {
        let directory =
            std::env::temp_dir().join(format!("qanvuli-replace-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("database.sqlite");
        let replacement = directory.join("database.sqlite.new");
        std::fs::write(&target, "old").unwrap();
        std::fs::write(&replacement, "new").unwrap();
        std::fs::write(sidecar(&replacement, "wal"), "uncheckpointed").unwrap();
        assert!(install_closed_database(&replacement, &target).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
        let _ = std::fs::remove_dir_all(directory);
    }
}
