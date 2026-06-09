use chrono::{DateTime, FixedOffset};
use clap::ValueEnum;
use qanvuli_collector::providers::cve::CveRelease;
use qanvuli_db::{CveActiveModels, CveDatabase, ReadJsonFileRecord};
use qanvuli_models::parse_json_with_raw;
use qanvuli_utils::loader::{self, FileStorageTrait};
use rayon::prelude::*;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_DB_CONNECTION_STRING: &str = "sqlite://./db.sqlite?mode=rwc";
pub const DEFAULT_LIMIT: u64 = 25;

const INGEST_CHUNK_SIZE: usize = 10000;

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

pub fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value)
            .map_err(|err| format!("failed to encode JSON: {err}"))?
    );
    Ok(())
}

pub async fn download_latest_asset(kind: ReleaseAssetKind) -> Result<PathBuf, String> {
    eprintln!("{kind}: fetching GitHub release metadata");
    let asset = latest_asset(kind).await?;
    eprintln!("{kind}: downloading {} ({} bytes)", asset.name, asset.size);
    asset
        .async_download_as_file()
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    eprintln!("{kind}: ready {}", asset.name);
    Ok(PathBuf::from(asset.name))
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
    println!(
        "{label}: asset={}, json_count={}",
        asset_path.display(),
        json_paths.len()
    );
    if matches!(mode, IngestMode::ReplaceAll) {
        let rebuild_start = Instant::now();
        if let Err(err) = db.rebuild_schema().await {
            panic!("{label}: failed to rebuild schema: {err}");
        }
        println!("{label}: rebuilt schema in {:?}", rebuild_start.elapsed());
    }

    let mut inserted = 0usize;
    let mut failed = 0usize;
    let mut timings = IngestTimings::default();

    for (chunk_index, chunk) in json_paths.chunks(INGEST_CHUNK_SIZE).enumerate() {
        if max_chunks.is_some_and(|max_chunks| chunk_index >= max_chunks) {
            println!("{label}: stopped after {chunk_index} chunks for profiling");
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
                let models = CveActiveModels::from(raw_record);
                if models.cve_id.is_empty() {
                    return Err(format!("{label}: missing cveMetadata.cveId in {json_path}"));
                }
                Ok((models, read_file))
            })
            .collect::<Vec<Result<(CveActiveModels, ReadJsonFileRecord), String>>>();
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
            IngestMode::ReplaceAll => db.insert_cve_models(models).await,
            IngestMode::Upsert => db.upsert_cve_models(models).await,
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
                println!(
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

        println!(
            "{label}: progress chunk={}, inserted={}, failed={}",
            chunk_index, inserted, failed
        );
    }

    println!(
        "{label}: inserted={inserted}, failed={failed}, elapsed={:?}, read={:?}, hash={:?}, parse={:?}, db_write={:?}, mark_read={:?}",
        total_start.elapsed(),
        timings.read,
        timings.hash,
        timings.parse,
        timings.db_write,
        timings.mark_read
    );
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
