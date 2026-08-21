use super::{binary_temporary_directory, temporary_zip_file_path, temporary_zip_file_path_in};
use qanvuli_core::{
    database::SqlxDatabase,
    ingest::{CapecCatalogFile, CweCatalogFile},
    model::{read_capec_catalog_xml, read_cwe_catalog_zip},
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const CWE_ETAG_METADATA_KEY: &str = "cwe_catalog:etag";
const CWE_LAST_MODIFIED_METADATA_KEY: &str = "cwe_catalog:last_modified";
const CWE_STORAGE_VERSION_METADATA_KEY: &str = "cwe_catalog:storage_version";
const CWE_STORAGE_VERSION: &str = "2";
const CAPEC_ETAG_METADATA_KEY: &str = "capec_catalog:etag";
const CAPEC_LAST_MODIFIED_METADATA_KEY: &str = "capec_catalog:last_modified";
const CAPEC_HASH_METADATA_KEY: &str = "capec_catalog:sha256";
const CAPEC_STORAGE_VERSION_METADATA_KEY: &str = "capec_catalog:storage_version";
const CAPEC_STORAGE_VERSION: &str = "1";

pub async fn download_latest_cwe_catalog() -> Result<PathBuf, String> {
    let catalog = CweCatalogFile::default();
    eprintln!("cwe: downloading {}", catalog.url);
    let path = temporary_zip_file_path(&catalog.name, None).map_err(|err| {
        format!(
            "failed to prepare temporary download path for {}: {err}",
            catalog.name
        )
    })?;
    catalog
        .download_to(&path)
        .await
        .map_err(|err| format!("failed to download {}: {err}", catalog.name))?;
    eprintln!("cwe: ready {}", path.display());
    Ok(path)
}

/// Synchronizes the CWE catalog.
pub async fn sync_cwe_catalog(db: SqlxDatabase) -> Result<(), String> {
    #[cfg(test)]
    if let Some(path) = local_test_cwe_catalog_path() {
        eprintln!("cwe: using local {}", path.display());
        let count = import_cwe_catalog(db, &path).await?;
        eprintln!("cwe: upserted {count} CWE master rows");
        return Ok(());
    }

    let catalog_file = CweCatalogFile::default();
    let storage_is_current = db
        .metadata_value(CWE_STORAGE_VERSION_METADATA_KEY)
        .await
        .map_err(|error| format!("failed to read CWE storage metadata: {error}"))?
        .as_deref()
        == Some(CWE_STORAGE_VERSION);
    let (etag, last_modified) = if storage_is_current {
        let etag = db
            .metadata_value(CWE_ETAG_METADATA_KEY)
            .await
            .map_err(|error| format!("failed to read CWE ETag metadata: {error}"))?;
        let last_modified = db
            .metadata_value(CWE_LAST_MODIFIED_METADATA_KEY)
            .await
            .map_err(|error| format!("failed to read CWE Last-Modified metadata: {error}"))?;
        (etag, last_modified)
    } else {
        eprintln!("cwe: rebuilding catalog metadata for SQLx storage v{CWE_STORAGE_VERSION}");
        (None, None)
    };
    eprintln!("cwe: checking {}", catalog_file.url);
    let path = temporary_zip_file_path(&catalog_file.name, None).map_err(|error| {
        format!(
            "failed to prepare temporary download path for {}: {error}",
            catalog_file.name
        )
    })?;
    let mut candidates = vec![path];
    if let Ok(fallback) =
        temporary_zip_file_path_in(binary_temporary_directory(), &catalog_file.name)
        && !candidates.contains(&fallback)
    {
        candidates.push(fallback);
    }
    let mut download = None;
    let mut download_errors = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if index > 0 {
            eprintln!("cwe: retrying download in {}", candidate.display());
        }
        match catalog_file
            .download_if_changed_to(candidate, etag.as_deref(), last_modified.as_deref())
            .await
        {
            Ok(result) => {
                download = Some(result);
                break;
            }
            Err(error) => {
                let _ = std::fs::remove_file(candidate);
                download_errors.push(format!("{}: {error}", candidate.display()));
            }
        }
    }
    let download = match download {
        Some(download) => download,
        None => {
            let errors = download_errors.join("; ");
            if let Some(path) = local_cwe_catalog_path(&catalog_file.name) {
                eprintln!(
                    "cwe: remote update unavailable ({errors}); loading existing local catalog {}",
                    path.display()
                );
                let count = import_cwe_catalog(db, &path).await?;
                eprintln!("cwe: loaded {count} CWE master rows from local catalog");
                return Ok(());
            }
            return Err(format!("failed to update {}: {errors}", catalog_file.name));
        }
    };
    let Some(path) = download.path else {
        eprintln!("cwe: catalog unchanged");
        return Ok(());
    };
    let count = import_cwe_catalog(db.clone(), &path).await?;
    let _ = std::fs::remove_file(&path);
    if let Some(etag) = download.etag {
        db.set_metadata_value(CWE_ETAG_METADATA_KEY, &etag)
            .await
            .map_err(|error| format!("failed to write CWE ETag metadata: {error}"))?;
    }
    if let Some(last_modified) = download.last_modified {
        db.set_metadata_value(CWE_LAST_MODIFIED_METADATA_KEY, &last_modified)
            .await
            .map_err(|error| format!("failed to write CWE Last-Modified metadata: {error}"))?;
    }
    eprintln!("cwe: upserted {count} CWE master rows");
    Ok(())
}

async fn import_cwe_catalog(db: SqlxDatabase, path: &Path) -> Result<usize, String> {
    let catalog = read_cwe_catalog_zip(path)
        .map_err(|error| format!("failed to read CWE catalog {}: {error}", path.display()))?;
    let count = db
        .upsert_cwe_catalog(&catalog)
        .await
        .map_err(|error| format!("failed to write CWE catalog: {error}"))?;
    db.set_metadata_value(CWE_STORAGE_VERSION_METADATA_KEY, CWE_STORAGE_VERSION)
        .await
        .map_err(|error| format!("failed to write CWE storage metadata: {error}"))?;
    Ok(count)
}

fn local_cwe_catalog_path(filename: &str) -> Option<PathBuf> {
    let current_dir_path = PathBuf::from(filename);
    if current_dir_path.exists() {
        return Some(current_dir_path);
    }

    let executable_path = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(filename)));
    executable_path.filter(|path| path.exists())
}

pub async fn sync_capec_catalog(db: SqlxDatabase) -> Result<(), String> {
    #[cfg(test)]
    if let Some(path) = local_test_capec_catalog_path() {
        let count = import_capec_catalog(db, &path).await?;
        eprintln!("capec: replaced {count} attack patterns");
        return Ok(());
    }

    let catalog = CapecCatalogFile::default();
    let storage_is_current = db
        .metadata_value(CAPEC_STORAGE_VERSION_METADATA_KEY)
        .await
        .map_err(|error| format!("failed to read CAPEC storage metadata: {error}"))?
        .as_deref()
        == Some(CAPEC_STORAGE_VERSION);
    let (etag, last_modified, previous_hash) = if storage_is_current {
        (
            db.metadata_value(CAPEC_ETAG_METADATA_KEY)
                .await
                .map_err(|error| format!("failed to read CAPEC ETag: {error}"))?,
            db.metadata_value(CAPEC_LAST_MODIFIED_METADATA_KEY)
                .await
                .map_err(|error| format!("failed to read CAPEC Last-Modified: {error}"))?,
            db.metadata_value(CAPEC_HASH_METADATA_KEY)
                .await
                .map_err(|error| format!("failed to read CAPEC hash: {error}"))?,
        )
    } else {
        (None, None, None)
    };

    let path = temporary_zip_file_path(&catalog.name, None)?;
    eprintln!("capec: checking {}", catalog.url);
    let download = match catalog
        .download_if_changed_as(&path, etag.as_deref(), last_modified.as_deref())
        .await
    {
        Ok(download) => download,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            if let Some(local) = local_catalog_path(&catalog.name) {
                eprintln!(
                    "capec: remote update unavailable ({error}); loading {}",
                    local.display()
                );
                let count = import_capec_catalog(db, &local).await?;
                eprintln!("capec: replaced {count} attack patterns");
                return Ok(());
            }
            return Err(format!("failed to update {}: {error}", catalog.name));
        }
    };
    let Some(path) = download.path else {
        eprintln!("capec: catalog unchanged");
        return Ok(());
    };

    let bytes = std::fs::read(&path)
        .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(hash, "{byte:02x}").expect("writing SHA-256 to a String cannot fail");
    }
    if previous_hash.as_deref() == Some(hash.as_str()) {
        let _ = std::fs::remove_file(&path);
        store_capec_download_metadata(&db, download.etag, download.last_modified, &hash).await?;
        eprintln!("capec: downloaded content is unchanged");
        return Ok(());
    }

    let count = import_capec_catalog(db.clone(), &path).await?;
    let _ = std::fs::remove_file(&path);
    store_capec_download_metadata(&db, download.etag, download.last_modified, &hash).await?;
    db.set_metadata_value(CAPEC_STORAGE_VERSION_METADATA_KEY, CAPEC_STORAGE_VERSION)
        .await
        .map_err(|error| format!("failed to write CAPEC storage metadata: {error}"))?;
    eprintln!("capec: replaced {count} attack patterns");
    Ok(())
}

async fn import_capec_catalog(db: SqlxDatabase, path: &Path) -> Result<usize, String> {
    let catalog = read_capec_catalog_xml(path)
        .map_err(|error| format!("failed to read CAPEC catalog {}: {error}", path.display()))?;
    db.replace_capec_catalog(&catalog)
        .await
        .map_err(|error| format!("failed to write CAPEC catalog: {error}"))
}

async fn store_capec_download_metadata(
    db: &SqlxDatabase,
    etag: Option<String>,
    last_modified: Option<String>,
    hash: &str,
) -> Result<(), String> {
    if let Some(etag) = etag {
        db.set_metadata_value(CAPEC_ETAG_METADATA_KEY, &etag)
            .await
            .map_err(|error| format!("failed to write CAPEC ETag: {error}"))?;
    }
    if let Some(last_modified) = last_modified {
        db.set_metadata_value(CAPEC_LAST_MODIFIED_METADATA_KEY, &last_modified)
            .await
            .map_err(|error| format!("failed to write CAPEC Last-Modified: {error}"))?;
    }
    db.set_metadata_value(CAPEC_HASH_METADATA_KEY, hash)
        .await
        .map_err(|error| format!("failed to write CAPEC hash: {error}"))
}

fn local_catalog_path(filename: &str) -> Option<PathBuf> {
    let current = PathBuf::from(filename);
    if current.exists() {
        return Some(current);
    }
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(filename)))
        .filter(|path| path.exists())
}

#[cfg(test)]
fn local_test_capec_catalog_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("capec_latest.xml");
    path.exists().then_some(path)
}

#[cfg(test)]
fn local_test_cwe_catalog_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("cwec_latest.xml.zip");
    path.exists().then_some(path)
}
