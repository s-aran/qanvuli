//! Database connection, SQLite-path, and JSON-output helpers shared by commands.

use qanvuli_core::database::SqlxDatabase;
use serde::Serialize;
use std::path::PathBuf;
use url::Url;

/// Connects to the destructive SQLx schema used by new database files.
pub async fn connect_sqlx_db(db_url: &str) -> Result<SqlxDatabase, String> {
    SqlxDatabase::connect(db_url).await.map_err(|err| {
        format!(
            "failed to connect SQLx database `{}`: {err}",
            redact_database_url(db_url)
        )
    })
}

/// Connects to the SQLx-backed database through the legacy command helper name.
pub async fn connect_db(db_url: &str) -> Result<SqlxDatabase, String> {
    connect_sqlx_db(db_url).await
}

/// Closes the SQLx-backed database through the legacy command helper name.
pub async fn close_db(db: SqlxDatabase) -> Result<(), String> {
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))
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

/// Creates a same-directory SQLite URL for a candidate full replacement database.
///
/// The caller must close every connection to this URL before installing it over the target.
pub(crate) fn replacement_sqlite_database_url(db_url: &str) -> Result<(PathBuf, String), String> {
    let target = sqlite_file_path(db_url).ok_or_else(|| {
        "full database replacement requires a file-backed SQLite database".to_owned()
    })?;
    let parent = target
        .parent()
        .ok_or_else(|| format!("database path has no parent: {}", target.display()))?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("database path has no UTF-8 file name: {}", target.display()))?;
    let candidate = parent.join(format!(
        ".{file_name}.building-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    Ok((
        candidate.clone(),
        format!("sqlite://{}?mode=rwc", candidate.display()),
    ))
}

/// Removes a closed candidate database and its SQLite sidecars after a failed replacement.
pub(crate) fn remove_sqlite_database_files(path: &std::path::Path) -> Result<(), String> {
    for path in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to remove {}: {error}", path.display())),
        }
    }
    Ok(())
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
