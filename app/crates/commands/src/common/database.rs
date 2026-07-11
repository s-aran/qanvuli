//! Database connection, SQLite-path, and JSON-output helpers shared by commands.

use qanvuli_core::database::CveDatabase;
use serde::Serialize;
use std::path::PathBuf;
use url::Url;

/// Connects to the configured CVE database and converts database errors for CLI output.
pub async fn connect_db(db_url: &str) -> Result<CveDatabase, String> {
    CveDatabase::connect(db_url).await.map_err(|err| {
        format!(
            "failed to connect database `{}`: {err}",
            redact_database_url(db_url)
        )
    })
}

/// Redacts database credentials before a connection string is shown to a user.
pub fn redact_database_url(db_url: &str) -> String {
    let Ok(mut url) = Url::parse(db_url) else {
        return db_url.to_owned();
    };

    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("REDACTED");
        let _ = url.set_password(None);
    }
    url.to_string()
}

/// Closes a command database connection and converts errors for CLI output.
pub async fn close_db(db: CveDatabase) -> Result<(), String> {
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))
}

/// Builds the default SQLite URL beside the `qanvuli` executable.
pub fn default_db_connection_string() -> Result<String, String> {
    let executable = std::env::current_exe()
        .map_err(|err| format!("failed to locate qanvuli executable: {err}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| format!("qanvuli executable has no parent: {}", executable.display()))?;
    let file_url = Url::from_file_path(directory.join("db.sqlite"))
        .map_err(|_| "failed to create DB URL beside qanvuli executable".to_owned())?;
    let path = file_url
        .as_str()
        .strip_prefix("file:")
        .ok_or_else(|| "failed to convert DB file URL to SQLite URL".to_owned())?;
    Ok(format!("sqlite:{path}?mode=rwc"))
}

/// Removes SQLite database, WAL, and SHM files before a full initialization.
pub fn reset_sqlite_database_files(db_url: &str) -> Result<(), String> {
    let Some(path) = sqlite_file_path(db_url) else {
        return Ok(());
    };

    for path in [
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => eprintln!("init: removed {}", path.display()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("failed to remove {}: {err}", path.display())),
        }
    }
    Ok(())
}

pub(crate) fn sqlite_file_path(db_url: &str) -> Option<PathBuf> {
    if let Some(value) = db_url.strip_prefix("sqlite:") {
        let file_url = Url::parse(&format!("file:{value}")).ok()?;
        if let Ok(path) = file_url.to_file_path() {
            return Some(path);
        }
    }
    let value = db_url.strip_prefix("sqlite://")?;
    let path = value.split_once('?').map_or(value, |(path, _)| path);
    (!path.is_empty() && path != ":memory:").then(|| PathBuf::from(path))
}

/// Prints a value as JSON, honoring the global `--pretty` flag.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = if std::env::args_os().any(|arg| arg == "--pretty") {
        simd_json::to_string_pretty(value)
    } else {
        simd_json::to_string(value)
    }
    .map_err(|err| format!("failed to encode JSON: {err}"))?;
    println!("{text}");
    Ok(())
}
