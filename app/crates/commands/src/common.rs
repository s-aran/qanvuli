use chrono::{DateTime, Duration as ChronoDuration, FixedOffset, NaiveDate, TimeZone, Utc};
use clap::ValueEnum;
use qanvuli_collector::providers::{cve::CveRelease, cwe::CweCatalogFile};
use qanvuli_db::{CveActiveModels, CveDatabase, CveZipFileRecord, ReadJsonFileRecord};
use qanvuli_models::cwe::read_cwe_catalog_zip;
use qanvuli_utils::loader::{self, FileStorageTrait, JsonEntry};
use rayon::prelude::*;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

pub const DEFAULT_LIMIT: u64 = 25;

const INGEST_CHUNK_SIZE: usize = 10000;
const REPLACE_ALL_INGEST_CHUNK_SIZE: usize = 20000;
const READ_PARSE_PIPELINE_BATCH_SIZE: usize = 512;
const CWE_ETAG_METADATA_KEY: &str = "cwe_catalog:etag";
const CWE_LAST_MODIFIED_METADATA_KEY: &str = "cwe_catalog:last_modified";
const CVE_ZIP_TYPE_ALL_MIDNIGHT: i32 = 0;
const CVE_ZIP_TYPE_DELTA_HOURLY: i32 = 1;
const CVE_ZIP_TYPE_DELTA_END_OF_DAY: i32 = 2;

pub type IngestProgressCallback = Arc<dyn Fn(IngestProgress) + Send + Sync>;

#[derive(Clone, Debug)]
pub struct IngestProgress {
    pub label: String,
    pub asset: String,
    pub phase: String,
    pub total_files: usize,
    pub written_files: usize,
    pub failed_files: usize,
}

#[derive(Clone, Debug)]
struct CveZipAsset {
    path_or_name: String,
    zip_datetime: String,
    zip_type: i32,
}

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

pub fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        simd_json::to_string_pretty(value)
            .map_err(|err| format!("failed to encode JSON: {err}"))?
    );
    Ok(())
}

pub async fn download_latest_asset(kind: ReleaseAssetKind) -> Result<PathBuf, String> {
    download_latest_asset_with_source(kind)
        .await
        .map(|asset| asset.path)
}

#[derive(Clone, Debug)]
pub struct DownloadedAsset {
    pub path: PathBuf,
    pub downloaded: bool,
}

pub async fn download_latest_asset_with_source(
    kind: ReleaseAssetKind,
) -> Result<DownloadedAsset, String> {
    eprintln!("{kind}: fetching GitHub release metadata");
    let asset = match latest_asset(kind).await {
        Ok(asset) => asset,
        Err(err) => {
            if let Some(path) = latest_local_asset(kind) {
                eprintln!(
                    "{kind}: failed to fetch GitHub release metadata ({err}); using local {}",
                    path.display()
                );
                return Ok(DownloadedAsset {
                    path,
                    downloaded: false,
                });
            }
            return Err(err);
        }
    };
    eprintln!("{kind}: downloading {} ({} bytes)", asset.name, asset.size);
    let filename = asset
        .safe_file_name()
        .map_err(|err| format!("unsafe asset name {}: {err}", asset.name))?
        .to_owned();
    asset
        .async_download_as_file()
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    eprintln!("{kind}: ready {}", asset.name);
    Ok(DownloadedAsset {
        path: PathBuf::from(filename),
        downloaded: true,
    })
}

pub fn remove_downloaded_zip(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            eprintln!("removed downloaded zip {}", path.display());
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to remove downloaded zip {}: {err}",
            path.display()
        )),
    }
}

fn latest_local_asset(kind: ReleaseAssetKind) -> Option<PathBuf> {
    let mut candidates = local_assets(kind);
    candidates.pop()
}

fn local_assets(kind: ReleaseAssetKind) -> Vec<PathBuf> {
    let needle = match kind {
        ReleaseAssetKind::All => "_all_",
        ReleaseAssetKind::Delta => "_delta_",
        ReleaseAssetKind::DeltaMidnight => "_at_end_of_day",
    };
    let Ok(entries) = std::fs::read_dir(".") else {
        return Vec::new();
    };
    let mut candidates = entries
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
    candidates
}

fn cve_zip_asset_from_path(path: &Path) -> Option<CveZipAsset> {
    let filename = path.file_name()?.to_str()?;
    cve_zip_asset_from_filename(filename)
}

fn cve_zip_asset_from_filename(filename: &str) -> Option<CveZipAsset> {
    let date = filename.get(0..10)?;
    let date = NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;

    if filename.contains("_all_CVEs_at_midnight") {
        let datetime = date.and_hms_opt(0, 0, 0)?;
        return Some(CveZipAsset {
            path_or_name: filename.to_owned(),
            zip_datetime: Utc.from_utc_datetime(&datetime).to_rfc3339(),
            zip_type: CVE_ZIP_TYPE_ALL_MIDNIGHT,
        });
    }

    if filename.contains("_at_end_of_day") {
        let datetime = date.and_hms_opt(23, 59, 59)?;
        return Some(CveZipAsset {
            path_or_name: filename.to_owned(),
            zip_datetime: Utc.from_utc_datetime(&datetime).to_rfc3339(),
            zip_type: CVE_ZIP_TYPE_DELTA_END_OF_DAY,
        });
    }

    let (_, time) = filename.split_once("_delta_CVEs_at_")?;
    let time = time.get(0..5)?;
    let hour = time.get(0..2)?.parse::<u32>().ok()?;
    let minute = time.get(2..4)?.parse::<u32>().ok()?;
    if time.get(4..5)? != "Z" {
        return None;
    }
    let datetime = date.and_hms_opt(hour, minute, 0)?;
    Some(CveZipAsset {
        path_or_name: filename.to_owned(),
        zip_datetime: Utc.from_utc_datetime(&datetime).to_rfc3339(),
        zip_type: CVE_ZIP_TYPE_DELTA_HOURLY,
    })
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
    #[cfg(test)]
    if let Some(path) = local_test_cwe_catalog_path() {
        eprintln!("cwe: using local {}", path.display());
        let count = upsert_cwe_catalog_file(db, &path).await?;
        eprintln!("cwe: upserted {count} CWE master rows");
        return Ok(());
    }

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
    let download = match catalog_file
        .async_download_if_changed(etag.as_deref(), last_modified.as_deref())
        .await
    {
        Ok(download) => download,
        Err(err) => {
            if let Some(path) = local_cwe_catalog_path(&catalog_file.name) {
                eprintln!(
                    "cwe: failed to update {} ({err}); using local {}",
                    catalog_file.name,
                    path.display()
                );
                let count = upsert_cwe_catalog_file(db, &path).await?;
                eprintln!("cwe: upserted {count} CWE master rows");
                return Ok(());
            }
            return Err(format!("failed to update {}: {err}", catalog_file.name));
        }
    };
    let Some(path) = download.path else {
        eprintln!("cwe: catalog unchanged");
        return Ok(());
    };

    let count = upsert_cwe_catalog_file(db, &path).await?;
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

async fn upsert_cwe_catalog_file(db: &CveDatabase, path: &Path) -> Result<usize, String> {
    let catalog = read_cwe_catalog_zip(path)
        .map_err(|err| format!("failed to read CWE catalog {}: {err}", path.display()))?;
    db.upsert_cwe_catalog(&catalog)
        .await
        .map_err(|err| format!("failed to write CWE catalog: {err}"))
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

#[cfg(test)]
fn local_test_cwe_catalog_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("cwec_latest.xml.zip");
    path.exists().then_some(path)
}

pub async fn apply_delta_updates(
    db: &CveDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
) -> Result<Vec<PathBuf>, String> {
    apply_delta_updates_with_progress(db, zip, max_chunks, false, None).await
}

pub async fn apply_delta_updates_with_progress(
    db: &CveDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
    keep_downloads: bool,
    progress: Option<IngestProgressCallback>,
) -> Result<Vec<PathBuf>, String> {
    emit_general_progress(&progress, "update", "syncing cwe");
    sync_cwe_catalog(db).await?;
    emit_general_progress(&progress, "update", "checking updates");

    if let Some(zip) = zip {
        ingest_zip_with_progress(
            db,
            "delta",
            &zip,
            IngestMode::Upsert,
            max_chunks,
            true,
            progress,
        )
        .await;
        return Ok(vec![zip]);
    }

    let Some(anchor) = latest_update_anchor(db).await? else {
        eprintln!("update: no previous CVE zip history; importing latest all midnight archive");
        return apply_latest_all_midnight(db, max_chunks, keep_downloads, progress).await;
    };
    let anchor_datetime = parse_anchor_datetime(&anchor)?;
    let elapsed = Utc::now().signed_duration_since(anchor_datetime);
    if elapsed >= ChronoDuration::weeks(1) {
        eprintln!(
            "update: latest CVE zip is older than 1 week ({anchor}); importing latest all midnight archive"
        );
        return apply_latest_all_midnight(db, max_chunks, keep_downloads, progress).await;
    }

    let assets = match update_delta_assets_since(&anchor, elapsed).await {
        Ok(assets) => assets,
        Err(err) => {
            if let Some(path) = latest_local_asset(ReleaseAssetKind::Delta) {
                eprintln!(
                    "delta: failed to fetch GitHub release metadata ({err}); using latest local {}",
                    path.display()
                );
                return apply_local_delta_updates(db, vec![path], max_chunks, progress).await;
            }
            return Err(err);
        }
    };

    let assets = if assets.is_empty() {
        if let Some(path) = latest_local_asset(ReleaseAssetKind::Delta) {
            eprintln!(
                "delta: no GitHub delta asset found; using latest local {}",
                path.display()
            );
            return apply_local_delta_updates(db, vec![path], max_chunks, progress).await;
        }
        assets
    } else {
        assets
    };

    let mut applied = Vec::new();
    for asset in assets {
        let Some(zip_asset) = cve_zip_asset_from_filename(&asset.name) else {
            eprintln!("delta: skipping unsupported CVE zip asset {}", asset.name);
            continue;
        };
        if cve_zip_asset_is_not_newer(db, &zip_asset).await? {
            continue;
        }

        eprintln!("delta: downloading {} ({} bytes)", asset.name, asset.size);
        let filename = asset
            .safe_file_name()
            .map_err(|err| format!("unsafe asset name {}: {err}", asset.name))?
            .to_owned();
        asset
            .async_download_as_file()
            .await
            .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
        let asset_path = PathBuf::from(filename);
        ingest_zip_with_progress(
            db,
            "delta",
            &asset_path,
            IngestMode::Upsert,
            max_chunks,
            true,
            progress.clone(),
        )
        .await;
        if max_chunks.is_none() {
            db.mark_cve_asset_applied(&asset.name, &asset.url)
                .await
                .map_err(|err| format!("failed to mark CVE asset applied: {err}"))?;
        }
        if !keep_downloads {
            remove_downloaded_zip(&asset_path)?;
        }
        applied.push(asset_path);
    }
    Ok(applied)
}

fn emit_general_progress(progress: &Option<IngestProgressCallback>, label: &str, phase: &str) {
    if let Some(progress) = progress {
        progress(IngestProgress {
            label: label.to_owned(),
            asset: String::new(),
            phase: phase.to_owned(),
            total_files: 0,
            written_files: 0,
            failed_files: 0,
        });
    }
}

async fn apply_latest_all_midnight(
    db: &CveDatabase,
    max_chunks: Option<usize>,
    keep_downloads: bool,
    progress: Option<IngestProgressCallback>,
) -> Result<Vec<PathBuf>, String> {
    let asset = download_latest_asset_with_source(ReleaseAssetKind::All).await?;
    let path = asset.path;
    ingest_zip_with_progress(
        db,
        "all",
        &path,
        IngestMode::ReplaceAll,
        max_chunks,
        true,
        progress,
    )
    .await;
    if asset.downloaded && !keep_downloads {
        remove_downloaded_zip(&path)?;
    }
    Ok(vec![path])
}

async fn apply_local_delta_updates(
    db: &CveDatabase,
    assets: Vec<PathBuf>,
    max_chunks: Option<usize>,
    progress: Option<IngestProgressCallback>,
) -> Result<Vec<PathBuf>, String> {
    let anchor = latest_update_anchor(db).await?;
    let mut applied = Vec::new();
    for asset_path in assets {
        let asset_name = asset_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned();
        let Some(zip_asset) = cve_zip_asset_from_filename(&asset_name) else {
            eprintln!(
                "delta: skipping unsupported local CVE zip asset {}",
                asset_path.display()
            );
            continue;
        };
        if anchor
            .as_deref()
            .is_some_and(|anchor| zip_asset.zip_datetime.as_str() <= anchor)
        {
            continue;
        }

        ingest_zip_with_progress(
            db,
            "delta",
            &asset_path,
            IngestMode::Upsert,
            max_chunks,
            true,
            progress.clone(),
        )
        .await;
        if max_chunks.is_none() && !asset_name.is_empty() {
            db.mark_cve_asset_applied(&asset_name, "local")
                .await
                .map_err(|err| format!("failed to mark CVE asset applied: {err}"))?;
        }
        applied.push(asset_path);
    }
    Ok(applied)
}

async fn latest_update_anchor(db: &CveDatabase) -> Result<Option<String>, String> {
    if let Some(zip_datetime) = db
        .latest_cve_zip_datetime()
        .await
        .map_err(|err| format!("failed to read CVE zip history: {err}"))?
    {
        return Ok(Some(zip_datetime));
    }

    db.latest_cve_updated_at()
        .await
        .map_err(|err| format!("failed to read latest CVE updated_at: {err}"))
}

fn parse_anchor_datetime(anchor: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(anchor)
        .map(|datetime| datetime.with_timezone(&Utc))
        .map_err(|err| format!("invalid CVE update anchor `{anchor}`: {err}"))
}

async fn cve_zip_asset_is_not_newer(db: &CveDatabase, asset: &CveZipAsset) -> Result<bool, String> {
    let Some(anchor) = latest_update_anchor(db).await? else {
        return Ok(false);
    };
    Ok(asset.zip_datetime <= anchor)
}

async fn update_delta_assets_since(
    since: &str,
    elapsed: ChronoDuration,
) -> Result<Vec<qanvuli_utils::github::GitHubReleaseFile>, String> {
    let mut cve = CveRelease::new();
    cve.async_get_all()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;

    let mut candidates = cve
        .get_all_and_delta_files_oldest_first()
        .into_iter()
        .filter_map(|asset| cve_zip_asset_from_filename(&asset.name).map(|parsed| (asset, parsed)))
        .filter(|(_, parsed)| {
            parsed.zip_datetime.as_str() > since && parsed.zip_type != CVE_ZIP_TYPE_ALL_MIDNIGHT
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|(_, left), (_, right)| {
        left.zip_datetime
            .cmp(&right.zip_datetime)
            .then(left.zip_type.cmp(&right.zip_type))
            .then(left.path_or_name.cmp(&right.path_or_name))
    });

    let mut latest_end_of_day = None;
    for index in 0..candidates.len() {
        if candidates[index].1.zip_type == CVE_ZIP_TYPE_DELTA_END_OF_DAY {
            latest_end_of_day = Some(index);
        }
    }

    let selected = if elapsed < ChronoDuration::hours(24) {
        if let Some(end_of_day_index) = latest_end_of_day {
            let end_of_day_datetime = candidates[end_of_day_index].1.zip_datetime.clone();
            candidates
                .into_iter()
                .skip(end_of_day_index)
                .filter(|(_, parsed)| {
                    parsed.zip_type == CVE_ZIP_TYPE_DELTA_END_OF_DAY
                        || (parsed.zip_type == CVE_ZIP_TYPE_DELTA_HOURLY
                            && parsed.zip_datetime.as_str() > end_of_day_datetime.as_str())
                })
                .map(|(asset, _)| asset)
                .collect()
        } else {
            candidates
                .into_iter()
                .filter(|(_, parsed)| parsed.zip_type == CVE_ZIP_TYPE_DELTA_HOURLY)
                .map(|(asset, _)| asset)
                .collect()
        }
    } else if let Some(end_of_day_index) = latest_end_of_day {
        let latest_end_of_day_datetime = candidates[end_of_day_index].1.zip_datetime.clone();
        candidates
            .into_iter()
            .filter(|(_, parsed)| {
                parsed.zip_type == CVE_ZIP_TYPE_DELTA_END_OF_DAY
                    || (parsed.zip_type == CVE_ZIP_TYPE_DELTA_HOURLY
                        && parsed.zip_datetime.as_str() > latest_end_of_day_datetime.as_str())
            })
            .map(|(asset, _)| asset)
            .collect()
    } else {
        candidates
            .into_iter()
            .filter(|(_, parsed)| parsed.zip_type == CVE_ZIP_TYPE_DELTA_HOURLY)
            .map(|(asset, _)| asset)
            .collect()
    };

    Ok(selected)
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
    cwe_synced: bool,
) {
    ingest_zip_with_progress(db, label, asset_path, mode, max_chunks, cwe_synced, None).await;
}

pub async fn ingest_zip_with_progress(
    db: &CveDatabase,
    label: &str,
    asset_path: &Path,
    mode: IngestMode,
    max_chunks: Option<usize>,
    cwe_synced: bool,
    progress: Option<IngestProgressCallback>,
) {
    let total_start = Instant::now();
    eprintln!("{label}: opening zip {}", asset_path.display());
    let mut storage = loader::ZipStorage::new(asset_path.to_string_lossy().to_string());
    eprintln!("{label}: enumerating CVE JSON entries");
    let json_entries = storage.enum_json_entries();
    eprintln!(
        "{label}: asset={}, json_count={}",
        asset_path.display(),
        json_entries.len()
    );
    emit_ingest_progress(
        &progress,
        label,
        asset_path,
        "enumerated",
        json_entries.len(),
        0,
        0,
    );
    if matches!(mode, IngestMode::ReplaceAll) {
        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "rebuilding",
            json_entries.len(),
            0,
            0,
        );
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

    if !cwe_synced {
        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "syncing cwe",
            json_entries.len(),
            0,
            0,
        );
        if let Err(err) = sync_cwe_catalog(db).await {
            panic!("{label}: {err}");
        }
    }

    let mut bulk_replace = None;
    if matches!(mode, IngestMode::ReplaceAll) {
        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "preparing",
            json_entries.len(),
            0,
            0,
        );
        let prepare_start = Instant::now();
        let session = db
            .begin_bulk_replace_all()
            .await
            .unwrap_or_else(|err| panic!("{label}: failed to begin bulk load: {err}"));
        eprintln!(
            "{label}: prepared bulk load in {:?}",
            prepare_start.elapsed()
        );
        bulk_replace = Some(session);
    }

    let mut inserted = 0usize;
    let mut failed = 0usize;
    let mut timings = IngestTimings::default();

    let ingest_chunk_size = match mode {
        IngestMode::ReplaceAll => REPLACE_ALL_INGEST_CHUNK_SIZE,
        IngestMode::Upsert => INGEST_CHUNK_SIZE,
    };

    for (chunk_index, chunk) in json_entries.chunks(ingest_chunk_size).enumerate() {
        if max_chunks.is_some_and(|max_chunks| chunk_index >= max_chunks) {
            eprintln!("{label}: stopped after {chunk_index} chunks for profiling");
            break;
        }

        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "reading",
            json_entries.len(),
            inserted,
            failed,
        );
        let chunk_start = Instant::now();
        let mut read_failed = 0usize;

        let (parsed, read_elapsed, parse_elapsed) =
            if chunk.iter().all(|entry| entry.filesystem_path.is_some()) {
                read_and_parse_extracted_chunk(label, chunk, &mut read_failed)
            } else {
                read_and_parse_zip_chunk(label, chunk, &mut storage, &mut read_failed)
        };
        timings.read += read_elapsed;
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

        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "writing",
            json_entries.len(),
            inserted,
            failed,
        );
        let db_write_start = Instant::now();
        let result = match mode {
            IngestMode::ReplaceAll => {
                bulk_replace
                    .as_ref()
                    .expect("bulk replace session must exist in replace-all mode")
                    .insert_cve_models(models)
                    .await
            }
            IngestMode::Upsert => db.upsert_cve_models(models).await,
        };

        match result {
            Ok(count) => {
                inserted += count;
                let db_write_elapsed = db_write_start.elapsed();
                timings.db_write += db_write_elapsed;

                let mark_start = Instant::now();
                let mark_result = match mode {
                    IngestMode::ReplaceAll => {
                        bulk_replace
                            .as_ref()
                            .expect("bulk replace session must exist in replace-all mode")
                            .mark_json_files_read(read_files)
                            .await
                    }
                    IngestMode::Upsert => db.mark_json_files_read(read_files).await,
                };
                if let Err(err) = mark_result {
                    eprintln!(
                        "{label}: failed to mark read json files in chunk {chunk_index}: {err}"
                    );
                }
                let mark_elapsed = mark_start.elapsed();
                timings.mark_read += mark_elapsed;

                let chunk_elapsed = chunk_start.elapsed();
                eprintln!(
                    "{label}: timings chunk={} read={:?}, parse={:?}, db_write={:?}, mark_read={:?}, total={:?}",
                    chunk_index,
                    read_elapsed,
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
        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "writing",
            json_entries.len(),
            inserted,
            failed,
        );
    }

    eprintln!(
        "{label}: inserted={inserted}, failed={failed}, elapsed={:?}, read={:?}, parse={:?}, db_write={:?}, mark_read={:?}",
        total_start.elapsed(),
        timings.read,
        timings.parse,
        timings.db_write,
        timings.mark_read
    );

    if matches!(mode, IngestMode::ReplaceAll) {
        emit_ingest_progress(
            &progress,
            label,
            asset_path,
            "indexing",
            json_entries.len(),
            inserted,
            failed,
        );
        let finish_start = Instant::now();
        let session = bulk_replace
            .take()
            .expect("bulk replace session must exist in replace-all mode");
        if let Err(err) = session.finish(db).await {
            panic!("{label}: failed to finish bulk load: {err}");
        }
        eprintln!(
            "{label}: rebuilt search indexes and FTS in {:?}",
            finish_start.elapsed()
        );
    }

    if max_chunks.is_none() {
        if let Some(zip_asset) = cve_zip_asset_from_path(asset_path) {
            if let Err(err) = db
                .mark_cve_zip_file_applied(CveZipFileRecord {
                    zip_filename: zip_asset.path_or_name,
                    zip_datetime: zip_asset.zip_datetime,
                    zip_type: zip_asset.zip_type,
                })
                .await
            {
                eprintln!(
                    "{label}: failed to mark CVE zip history for {}: {err}",
                    asset_path.display()
                );
            }
        } else {
            eprintln!(
                "{label}: skipped CVE zip history for unsupported filename {}",
                asset_path.display()
            );
        }
    }
    emit_ingest_progress(
        &progress,
        label,
        asset_path,
        "done",
        json_entries.len(),
        inserted,
        failed,
    );
}

fn parse_json_batch(
    label: &str,
    batch: Vec<(String, Vec<u8>)>,
) -> Vec<Result<(CveActiveModels, ReadJsonFileRecord), String>> {
    batch
        .into_iter()
        .map(|(json_path, json)| parse_json(label, json_path, json))
        .collect()
}

fn read_and_parse_extracted_chunk(
    label: &str,
    chunk: &[JsonEntry],
    read_failed: &mut usize,
) -> (
    Vec<Result<(CveActiveModels, ReadJsonFileRecord), String>>,
    Duration,
    Duration,
) {
    let total_start = Instant::now();
    let results = chunk
        .par_iter()
        .map(|entry| {
            let filesystem_path = entry
                .filesystem_path
                .as_ref()
                .expect("extracted entry must have a filesystem path");
            match std::fs::read(filesystem_path) {
                Ok(json) => Ok(parse_json(label, entry.path.clone(), json)),
                Err(err) => Err(format!(
                    "{label}: failed to read {} from {}: {err}",
                    entry.path,
                    filesystem_path.display()
                )),
            }
        })
        .collect::<Vec<_>>();
    let elapsed = total_start.elapsed();

    let mut parsed = Vec::with_capacity(chunk.len());
    for result in results {
        match result {
            Ok(parse_result) => parsed.push(parse_result),
            Err(err) => {
                *read_failed += 1;
                eprintln!("{err}");
            }
        }
    }

    (parsed, elapsed, Duration::ZERO)
}

fn read_and_parse_zip_chunk(
    label: &str,
    chunk: &[JsonEntry],
    storage: &mut loader::ZipStorage,
    read_failed: &mut usize,
) -> (
    Vec<Result<(CveActiveModels, ReadJsonFileRecord), String>>,
    Duration,
    Duration,
) {
    let read_start = Instant::now();
    let parsed_batches = std::sync::Mutex::new(Vec::new());
    let mut read_elapsed = Duration::ZERO;
    rayon::scope(|scope| {
        let mut batch = Vec::with_capacity(READ_PARSE_PIPELINE_BATCH_SIZE);
        for entry in chunk {
            match storage.get_json_entry_bytes(entry) {
                Ok(json) => batch.push((entry.path.clone(), json)),
                Err(err) => {
                    *read_failed += 1;
                    eprintln!("{label}: failed to read {}: {err}", entry.path);
                }
            }

            if batch.len() == READ_PARSE_PIPELINE_BATCH_SIZE {
                let batch = std::mem::take(&mut batch);
                let parsed_batches = &parsed_batches;
                scope.spawn(move |_| {
                    let parsed = parse_json_batch(label, batch);
                    parsed_batches
                        .lock()
                        .expect("parsed batch mutex poisoned")
                        .push(parsed);
                });
            }
        }

        if !batch.is_empty() {
            let parsed_batches = &parsed_batches;
            scope.spawn(move |_| {
                let parsed = parse_json_batch(label, batch);
                parsed_batches
                    .lock()
                    .expect("parsed batch mutex poisoned")
                    .push(parsed);
            });
        }

        read_elapsed = read_start.elapsed();
    });
    let parse_elapsed = read_start.elapsed().saturating_sub(read_elapsed);
    let parsed = parsed_batches
        .into_inner()
        .expect("parsed batch mutex poisoned")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    (parsed, read_elapsed, parse_elapsed)
}

fn parse_json(
    label: &str,
    json_path: String,
    json: Vec<u8>,
) -> Result<(CveActiveModels, ReadJsonFileRecord), String> {
    let read_file = ReadJsonFileRecord::from_content(json_path.clone(), &json);
    let raw_json = String::from_utf8(json)
        .map_err(|err| format!("{label}: invalid UTF-8 in {json_path}: {err}"))?;
    let model = CveActiveModels::from_raw_json_string(raw_json)
        .map_err(|err| format!("{label}: failed to parse {json_path}: {err}"))?;
    if model.cve_id.is_empty() {
        return Err(format!("{label}: missing cveMetadata.cveId in {json_path}"));
    }
    Ok((model, read_file))
}

fn emit_ingest_progress(
    progress: &Option<IngestProgressCallback>,
    label: &str,
    asset_path: &Path,
    phase: &str,
    total_files: usize,
    written_files: usize,
    failed_files: usize,
) {
    if let Some(progress) = progress {
        progress(IngestProgress {
            label: label.to_owned(),
            asset: asset_path.display().to_string(),
            phase: phase.to_owned(),
            total_files,
            written_files,
            failed_files,
        });
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
    parse: Duration,
    db_write: Duration,
    mark_read: Duration,
}

fn normalize_timestamp(value: &str) -> Result<String, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt: DateTime<FixedOffset>| dt.to_utc().to_rfc3339())
        .map_err(|err| format!("invalid RFC3339 timestamp `{value}`: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_database_is_beside_executable() {
        let db_url = default_db_connection_string().unwrap();
        let db_path = sqlite_file_path(&db_url).unwrap();
        let executable = std::env::current_exe().unwrap();

        assert_eq!(db_path, executable.parent().unwrap().join("db.sqlite"));
    }

    #[tokio::test]
    async fn replace_all_ingest_initializes_from_local_archives() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let db_path = std::env::temp_dir().join(format!(
            "qanvuli-init-ingest-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        reset_sqlite_database_files(&db_url).unwrap();

        let db = connect_db(&db_url).await.unwrap();
        ingest_zip_with_progress(
            &db,
            "test-init",
            &repo_root.join("test/2026-06-04_delta_CVEs_at_0500Z.zip"),
            IngestMode::ReplaceAll,
            Some(1),
            false,
            None,
        )
        .await;

        let status = db.database_status().await.unwrap();
        assert!(status.cve_count > 0);
        assert!(status.cwe_count > 0);
        db.close().await.unwrap();

        reset_sqlite_database_files(&db_url).unwrap();
    }
}
