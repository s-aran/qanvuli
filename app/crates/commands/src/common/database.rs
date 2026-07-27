//! Database and JSON helpers shared by commands.

use qanvuli_core::database::SqlxDatabase;
use serde::Serialize;
use std::path::PathBuf;
use url::Url;

/// Opens the configured database.
pub async fn connect_database(db_url: &str) -> Result<SqlxDatabase, String> {
    SqlxDatabase::connect(db_url).await.map_err(|err| {
        format!(
            "failed to connect to database `{}`: {err}",
            redact_database_url(db_url)
        )
    })
}

/// Closes the database.
pub async fn close_database(db: SqlxDatabase) -> Result<(), String> {
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))
}

/// Redacts credentials in a database URL.
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

/// Returns the default SQLite URL for the current directory.
pub fn default_db_connection_string() -> Result<String, String> {
    let directory = std::env::current_dir()
        .map_err(|err| format!("failed to resolve current working directory: {err}"))?;
    let file_url = Url::from_file_path(directory.join("db.sqlite"))
        .map_err(|_| "failed to create DB URL in current working directory".to_owned())?;
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
