use chrono::{DateTime, FixedOffset};
use clap::ValueEnum;
use qanvuli_collector::providers::{cve::CveRelease, cwe::CweCatalogFile};
use qanvuli_db::{CveDatabase, ReadJsonFileRecord};
use qanvuli_models::{CveStatusData, RawCveRecord, cwe::read_cwe_catalog_zip, parse_json_with_raw};
use qanvuli_utils::loader::{self, FileStorageTrait};
use rayon::prelude::*;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_DB_CONNECTION_STRING: &str = "sqlite://./db.sqlite?mode=rwc";
pub const DEFAULT_LIMIT: u64 = 25;

const INGEST_CHUNK_SIZE: usize = 10000;
const REPLACE_ALL_INGEST_CHUNK_SIZE: usize = 20000;
const CWE_ETAG_METADATA_KEY: &str = "cwe_catalog:etag";
const CWE_LAST_MODIFIED_METADATA_KEY: &str = "cwe_catalog:last_modified";

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ReleaseAssetKind {
    All,
    Delta,
    DeltaMidnight,
}

impl std::fmt::Display for ReleaseAssetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Delta => write!(f, "delta"),
            Self::DeltaMidnight => write!(f, "delta-midnight"),
        }
    }
}

#[derive(Debug, Default)]
pub struct DateFilter {
    pub published_since: Option<String>,
    pub updated_since: Option<String>,
}

impl DateFilter {
    pub fn new(published_since: Option<&str>, updated_since: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            published_since: published_since.map(normalize_timestamp).transpose()?,
            updated_since: updated_since.map(normalize_timestamp).transpose()?,
        })
    }
}

pub async fn connect_db(db_url: &str) -> Result<CveDatabase, String> {
    CveDatabase::connect(db_url)
        .await
        .map_err(|err| format!("failed to connect database `{db_url}`: {err}"))
}

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
            Err(err) => {
                return Err(format!("failed to remove {}: {err}", path.display()));
            }
        }
    }

    Ok(())
}

fn sqlite_file_path(db_url: &str) -> Option<PathBuf> {
    let value = db_url.strip_prefix("sqlite://")?;
    let path = value.split_once('?').map_or(value, |(path, _)| path);
    (!path.is_empty() && path != ":memory:").then(|| PathBuf::from(path))
}

pub fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        simd_json::to_string_pretty(value)
            .map_err(|err| format!("failed to encode JSON: {err}"))?
    );
    Ok(())
}

pub async fn download_latest_asset(kind: ReleaseAssetKind) -> Result<PathBuf, String> {
    eprintln!("{kind}: fetching GitHub release metadata");
    let asset = match latest_asset(kind).await {
        Ok(asset) => asset,
        Err(err) => {
            if let Some(path) = latest_local_asset(kind) {
                eprintln!(
                    "{kind}: failed to fetch GitHub release metadata ({err}); using local {}",
                    path.display()
                );
                return Ok(path);
            }
            return Err(err);
        }
    };
    eprintln!("{kind}: downloading {} ({} bytes)", asset.name, asset.size);
    asset
        .async_download_as_file()
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    eprintln!("{kind}: ready {}", asset.name);
    Ok(PathBuf::from(asset.name))
}

fn latest_local_asset(kind: ReleaseAssetKind) -> Option<PathBuf> {
    let needle = match kind {
        ReleaseAssetKind::All => "_all_",
        ReleaseAssetKind::Delta => "_delta_",
        ReleaseAssetKind::DeltaMidnight => "_at_end_of_day",
    };
    let mut candidates = std::fs::read_dir(".")
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(filename) = path.file_name().and_then(|value| value.to_str()) else {
                return false;
            };
            filename.contains(needle)
                && filename.ends_with(".zip")
                && !filename.ends_with(".inner.zip")
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

pub async fn download_latest_cwe_catalog() -> Result<PathBuf, String> {
    let catalog = CweCatalogFile::default();
    eprintln!("cwe: downloading {}", catalog.url);
    let path = catalog
        .async_download_as_file()
        .await
        .map_err(|err| format!("failed to download {}: {err}", catalog.name))?;
    eprintln!("cwe: ready {}", path.display());
    Ok(path)
}

pub async fn sync_cwe_catalog(db: &CveDatabase) -> Result<(), String> {
    let catalog_file = CweCatalogFile::default();
    let etag = db
        .get_metadata(CWE_ETAG_METADATA_KEY)
        .await
        .map_err(|err| format!("failed to read CWE ETag metadata: {err}"))?;
    let last_modified = db
        .get_metadata(CWE_LAST_MODIFIED_METADATA_KEY)
        .await
        .map_err(|err| format!("failed to read CWE Last-Modified metadata: {err}"))?;

    eprintln!("cwe: checking {}", catalog_file.url);
    let download = catalog_file
        .async_download_if_changed(etag.as_deref(), last_modified.as_deref())
        .await
        .map_err(|err| format!("failed to update {}: {err}", catalog_file.name))?;
    let Some(path) = download.path else {
        eprintln!("cwe: catalog unchanged");
        return Ok(());
    };

    let catalog = read_cwe_catalog_zip(&path)
        .map_err(|err| format!("failed to read CWE catalog {}: {err}", path.display()))?;
    let count = db
        .upsert_cwe_catalog(&catalog)
        .await
        .map_err(|err| format!("failed to write CWE catalog: {err}"))?;
    if let Some(etag) = download.etag {
        db.set_metadata(CWE_ETAG_METADATA_KEY, &etag)
            .await
            .map_err(|err| format!("failed to write CWE ETag metadata: {err}"))?;
    }
    if let Some(last_modified) = download.last_modified {
        db.set_metadata(CWE_LAST_MODIFIED_METADATA_KEY, &last_modified)
            .await
            .map_err(|err| format!("failed to write CWE Last-Modified metadata: {err}"))?;
    }
    eprintln!("cwe: upserted {count} CWE master rows");
    Ok(())
}

pub async fn apply_delta_updates(
    db: &CveDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
) -> Result<Vec<PathBuf>, String> {
    if let Some(zip) = zip {
        ingest_zip(db, "delta", &zip, IngestMode::Upsert, max_chunks).await;
        return Ok(vec![zip]);
    }

    let assets = delta_assets_oldest_first().await?;
    let mut applied = Vec::new();
    for asset in assets {
        if db
            .is_cve_asset_applied(&asset.name)
            .await
            .map_err(|err| format!("failed to read CVE asset metadata: {err}"))?
        {
            continue;
        }

        eprintln!("delta: downloading {} ({} bytes)", asset.name, asset.size);
        asset
            .async_download_as_file()
            .await
            .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
        let asset_path = PathBuf::from(&asset.name);
        ingest_zip(db, "delta", &asset_path, IngestMode::Upsert, max_chunks).await;
        if max_chunks.is_none() {
            db.mark_cve_asset_applied(&asset.name, &asset.url)
                .await
                .map_err(|err| format!("failed to mark CVE asset applied: {err}"))?;
        }
        applied.push(asset_path);
    }
    Ok(applied)
}

pub async fn latest_asset(
    kind: ReleaseAssetKind,
) -> Result<qanvuli_utils::github::GitHubReleaseFile, String> {
    let mut cve = CveRelease::new();
    cve.async_get()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;

    let asset = match kind {
        ReleaseAssetKind::All => cve.get_latest_all_file(),
        ReleaseAssetKind::Delta => cve.get_latest_delta_file(),
        ReleaseAssetKind::DeltaMidnight => cve.get_latest_delta_midnight_file(),
    };

    asset
        .cloned()
        .ok_or_else(|| format!("no {kind} CVE zip asset found"))
}

pub async fn delta_assets_oldest_first()
-> Result<Vec<qanvuli_utils::github::GitHubReleaseFile>, String> {
    let mut cve = CveRelease::new();
    cve.async_get_all()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;
    Ok(cve.get_delta_files_oldest_first())
}

pub async fn ingest_zip(
    db: &CveDatabase,
    label: &str,
    asset_path: &Path,
    mode: IngestMode,
    max_chunks: Option<usize>,
) {
    let total_start = Instant::now();
    eprintln!("{label}: opening zip {}", asset_path.display());
    let mut storage = loader::ZipStorage::new(asset_path.to_string_lossy().to_string());
    eprintln!("{label}: enumerating CVE JSON entries");
    let json_paths = storage.enum_json_list().collect::<Vec<String>>();
    eprintln!(
        "{label}: asset={}, json_count={}",
        asset_path.display(),
        json_paths.len()
    );
    if matches!(mode, IngestMode::ReplaceAll) {
        let rebuild_start = Instant::now();
        if let Err(err) = db.rebuild_schema().await {
            panic!("{label}: failed to rebuild schema: {err}");
        }
        eprintln!("{label}: rebuilt schema in {:?}", rebuild_start.elapsed());

        let compact_start = Instant::now();
        if let Err(err) = db.compact_storage().await {
            eprintln!("{label}: failed to compact empty database: {err}");
        } else {
            eprintln!(
                "{label}: compacted empty database in {:?}",
                compact_start.elapsed()
            );
        }
    }

    if let Err(err) = sync_cwe_catalog(db).await {
        panic!("{label}: {err}");
    }

    if matches!(mode, IngestMode::ReplaceAll) {
        let prepare_start = Instant::now();
        if let Err(err) = db.prepare_bulk_replace_all().await {
            panic!("{label}: failed to prepare bulk load: {err}");
        }
        eprintln!(
            "{label}: prepared bulk load in {:?}",
            prepare_start.elapsed()
        );
    }

    let mut inserted = 0usize;
    let mut failed = 0usize;
    let mut timings = IngestTimings::default();

    let ingest_chunk_size = match mode {
        IngestMode::ReplaceAll => REPLACE_ALL_INGEST_CHUNK_SIZE,
        IngestMode::Upsert => INGEST_CHUNK_SIZE,
    };

    for (chunk_index, chunk) in json_paths.chunks(ingest_chunk_size).enumerate() {
        if max_chunks.is_some_and(|max_chunks| chunk_index >= max_chunks) {
            eprintln!("{label}: stopped after {chunk_index} chunks for profiling");
            break;
        }

        let chunk_start = Instant::now();
        let mut jsons = Vec::with_capacity(chunk.len());
        let mut read_failed = 0usize;

        let read_start = Instant::now();
        for json_path in chunk {
            match storage.get_json(json_path) {
                Ok(json) => jsons.push((json_path.clone(), json)),
                Err(err) => {
                    read_failed += 1;
                    eprintln!("{label}: failed to read {json_path}: {err}");
                }
            }
        }
        let read_elapsed = read_start.elapsed();
        timings.read += read_elapsed;

        let hash_start = Instant::now();
        let jsons = jsons
            .into_par_iter()
            .map(|(json_path, json)| {
                let read_file =
                    ReadJsonFileRecord::from_content(json_path.clone(), json.as_bytes());
                (json_path, json, read_file)
            })
            .collect::<Vec<_>>();
        let hash_elapsed = hash_start.elapsed();
        timings.hash += hash_elapsed;

        let parse_start = Instant::now();
        let parsed = jsons
            .into_par_iter()
            .map(|(json_path, json, read_file)| {
                let raw_record = parse_json_with_raw(json)
                    .map_err(|err| format!("{label}: failed to parse {json_path}: {err}"))?;
                if cve_id_from_record(&raw_record).is_none() {
                    return Err(format!("{label}: missing cveMetadata.cveId in {json_path}"));
                }
                Ok((raw_record, read_file))
            })
            .collect::<Vec<Result<(RawCveRecord<CveStatusData>, ReadJsonFileRecord), String>>>();
        let parse_elapsed = parse_start.elapsed();
        timings.parse += parse_elapsed;

        let mut models = Vec::new();
        let mut read_files = Vec::new();
        let mut parse_failed = 0usize;
        for result in parsed {
            match result {
                Ok((model, read_file)) => {
                    models.push(model);
                    read_files.push(read_file);
                }
                Err(err) => {
                    parse_failed += 1;
                    eprintln!("{err}");
                }
            }
        }

        failed += read_failed + parse_failed;

        let db_write_start = Instant::now();
        let result = match mode {
            IngestMode::ReplaceAll => db.insert_cve_records_bulk(models).await,
            IngestMode::Upsert => db.upsert_cve_records(models).await,
        };

        match result {
            Ok(count) => {
                inserted += count;
                let db_write_elapsed = db_write_start.elapsed();
                timings.db_write += db_write_elapsed;

                let mark_start = Instant::now();
                if let Err(err) = db.mark_json_files_read(read_files).await {
                    eprintln!(
                        "{label}: failed to mark read json files in chunk {chunk_index}: {err}"
                    );
                }
                let mark_elapsed = mark_start.elapsed();
                timings.mark_read += mark_elapsed;

                let chunk_elapsed = chunk_start.elapsed();
                eprintln!(
                    "{label}: timings chunk={} read={:?}, hash={:?}, parse={:?}, db_write={:?}, mark_read={:?}, total={:?}",
                    chunk_index,
                    read_elapsed,
                    hash_elapsed,
                    parse_elapsed,
                    db_write_elapsed,
                    mark_elapsed,
                    chunk_elapsed
                );
            }
            Err(err) => {
                timings.db_write += db_write_start.elapsed();
                failed += chunk.len();
                eprintln!("{label}: failed to write chunk {chunk_index}: {err}");
            }
        }

        eprintln!(
            "{label}: progress chunk={}, inserted={}, failed={}",
            chunk_index, inserted, failed
        );
    }

    eprintln!(
        "{label}: inserted={inserted}, failed={failed}, elapsed={:?}, read={:?}, hash={:?}, parse={:?}, db_write={:?}, mark_read={:?}",
        total_start.elapsed(),
        timings.read,
        timings.hash,
        timings.parse,
        timings.db_write,
        timings.mark_read
    );

    if matches!(mode, IngestMode::ReplaceAll) {
        let finish_start = Instant::now();
        if let Err(err) = db.finish_bulk_replace_all().await {
            panic!("{label}: failed to finish bulk load: {err}");
        }
        eprintln!(
            "{label}: rebuilt search indexes and FTS in {:?}",
            finish_start.elapsed()
        );
    }
}

#[derive(Copy, Clone)]
pub enum IngestMode {
    ReplaceAll,
    Upsert,
}

#[derive(Default)]
struct IngestTimings {
    read: Duration,
    hash: Duration,
    parse: Duration,
    db_write: Duration,
    mark_read: Duration,
}

fn normalize_timestamp(value: &str) -> Result<String, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt: DateTime<FixedOffset>| dt.to_utc().to_rfc3339())
        .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))
}

fn cve_id_from_record(record: &RawCveRecord<CveStatusData>) -> Option<&str> {
    record
        .raw_json()
        .pointer("/cveMetadata/cveId")
        .and_then(serde_json::Value::as_str)
        .filter(|cve_id| !cve_id.is_empty())
}
