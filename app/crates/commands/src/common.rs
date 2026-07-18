use ahash::AHashSet;
use chrono::{DateTime, FixedOffset, Utc};
use clap::ValueEnum;
use qanvuli_core::ingest::OsvModifiedId;
use qanvuli_core::model::OSV_DATABASE_SOURCE_PREFIXES;
use qanvuli_core::{
    database::{OsvRawRecord, SqlxDatabase},
    ingest::{
        CveRelease, CweCatalogFile, FileStorageTrait, GitHubReleaseFile, OSV_ALL_ZIP, OsvGcsSource,
        ZipStorage, download_epss_current_csv, download_kev_json, parse_modified_id_csv,
    },
    model::{is_known_osv_database_prefix, read_cwe_catalog_zip},
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub mod database;
pub use database::{
    close_db, connect_db, connect_sqlx_db, default_db_connection_string, print_json,
    redact_database_url,
};
pub(crate) use database::{remove_sqlite_database_files, replacement_sqlite_database_url};

/// Default row limit used by CLI search commands.
pub const DEFAULT_LIMIT: u64 = 25;

/// Help text for dynamic OSV source prefix flags such as `--osv-ghsa`.
pub const OSV_SOURCE_PREFIX_HELP: &str = r#"OSV source DB prefix flags:
  Any official OSV source DB prefix can be selected with repeatable --osv-{prefix} flags.
  Prefix matching is case-insensitive. Use hyphens as shown below.

  --osv-alba --osv-alea --osv-alpine --osv-alsa --osv-asb-a --osv-bell --osv-bit
  --osv-cga --osv-cleanstart --osv-curl --osv-cve --osv-debian --osv-dhi --osv-dla
  --osv-drupal --osv-dsa --osv-dtsa --osv-echo --osv-eef --osv-ela --osv-ghsa
  --osv-go --osv-gsd --osv-hsec --osv-jlsec --osv-kube --osv-lbsec --osv-lsn
  --osv-mal --osv-mgasa --osv-mini --osv-oesa --osv-opensuse-su --osv-osec
  --osv-osv --osv-phsa --osv-psf --osv-pub-a --osv-pysec --osv-rhba --osv-rhea
  --osv-rhsa --osv-rlsa --osv-root --osv-rsec --osv-rustsec --osv-rxsa
  --osv-suse-fu --osv-suse-ou --osv-suse-ru --osv-suse-su --osv-ubuntu --osv-usn --osv-v8

Examples:
  qanvuli init --osv-ghsa --osv-pysec
  qanvuli update --osv-rustsec --osv-go
"#;

const INGEST_CHUNK_SIZE: usize = 30000;
const OSV_IMPORT_BATCH_SIZE: usize = 6000;
const CWE_ETAG_METADATA_KEY: &str = "cwe_catalog:etag";
const CWE_LAST_MODIFIED_METADATA_KEY: &str = "cwe_catalog:last_modified";
const CWE_STORAGE_VERSION_METADATA_KEY: &str = "cwe_catalog:storage_version";
const CWE_STORAGE_VERSION: &str = "2";
pub(crate) const OSV_IMPORT_ID_PREFIXES_METADATA_KEY: &str = "osv_import_id_prefixes";

/// Callback used by long-running import commands to report progress to the TUI.
pub type IngestProgressCallback = Arc<dyn Fn(IngestProgress) + Send + Sync>;
/// Progress snapshot emitted by CVE import and update operations.
#[derive(Clone, Debug)]
pub struct IngestProgress {
    pub label: String,
    pub asset: String,
    pub phase: String,
    pub total_files: usize,
    pub written_files: usize,
    pub failed_files: usize,
}

#[derive(Debug)]
struct OsvImportBatch {
    records: Vec<OsvRawRecord>,
}

/// CVE release archive kind accepted by download and ingest commands.
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

/// Normalized date filters shared by CLI search commands.
#[derive(Clone, Debug, Default)]
pub struct DateFilter {
    pub published_since: Option<String>,
    pub updated_since: Option<String>,
}

impl DateFilter {
    /// Parses optional publication and update timestamps into normalized strings.
    pub fn new(published_since: Option<&str>, updated_since: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            published_since: published_since.map(normalize_timestamp).transpose()?,
            updated_since: updated_since.map(normalize_timestamp).transpose()?,
        })
    }
}

/// Formats a duration for progress and maintenance logs.
pub fn format_elapsed(duration: Duration) -> String {
    format!("{duration:.2?}")
}

/// Selects which OSV source prefixes should be imported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsvImportSelection {
    all: bool,
    id_prefixes: BTreeSet<String>,
}

impl OsvImportSelection {
    /// Selects all OSV records.
    pub fn all() -> Self {
        Self {
            all: true,
            id_prefixes: BTreeSet::new(),
        }
    }

    /// Builds the default OSV import selection for `init`.
    pub fn default_init(include_all: bool, prefixes: &[String]) -> Self {
        if include_all {
            return Self::all();
        }
        let mut id_prefixes = required_osv_import_prefixes();
        id_prefixes.extend(prefixes.iter().map(|prefix| normalize_osv_prefix(prefix)));
        Self {
            all: false,
            id_prefixes,
        }
    }

    /// Builds optional OSV import additions for `update`.
    pub fn update_additions(include_all: bool, prefixes: &[String]) -> Option<Self> {
        if include_all {
            return Some(Self::all());
        }
        let id_prefixes = prefixes
            .iter()
            .map(|prefix| normalize_osv_prefix(prefix))
            .collect::<BTreeSet<_>>();
        (!id_prefixes.is_empty()).then_some(Self {
            all: false,
            id_prefixes,
        })
    }

    /// Returns a selection containing records selected by either side.
    pub fn merged_with(&self, other: &Self) -> Self {
        if self.all || other.all {
            return Self::all();
        }
        let mut id_prefixes = self.id_prefixes.clone();
        id_prefixes.extend(other.id_prefixes.iter().cloned());
        Self {
            all: false,
            id_prefixes,
        }
    }

    /// Restores an OSV import selection from metadata stored in the database.
    pub fn from_metadata(value: Option<&str>) -> Option<Self> {
        let value = value?.trim();
        if value.eq_ignore_ascii_case("ALL") {
            return Some(Self::all());
        }
        let mut id_prefixes = value
            .split(',')
            .map(str::trim)
            .filter(|prefix| !prefix.is_empty())
            .map(normalize_osv_prefix)
            .collect::<BTreeSet<_>>();
        id_prefixes.extend(required_osv_import_prefixes());
        (!id_prefixes.is_empty()).then_some(Self {
            all: false,
            id_prefixes,
        })
    }

    /// Encodes this selection for storage in database metadata.
    pub fn as_metadata_value(&self) -> String {
        if self.all {
            "ALL".to_owned()
        } else {
            self.id_prefixes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    /// Returns whether this selection includes the given OSV advisory ID.
    pub fn matches_id(&self, id: &str) -> bool {
        let id = id.to_ascii_uppercase();
        self.all
            || self
                .id_prefixes
                .iter()
                .any(|prefix| id.starts_with(&format!("{prefix}-")))
    }

    /// Human-readable description used in import logs.
    pub fn description(&self) -> String {
        if self.all {
            "all OSV records".to_owned()
        } else {
            self.id_prefixes
                .iter()
                .map(|prefix| match prefix.as_str() {
                    "OSV" => "OSV (OSS-Fuzz)".to_owned(),
                    "PYSEC" => "PYSEC".to_owned(),
                    "GHSA" => "GHSA".to_owned(),
                    other => other.to_owned(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    fn validate_known_prefixes(&self) -> Result<(), String> {
        if self.all {
            return Ok(());
        }
        let unknown = self
            .id_prefixes
            .iter()
            .filter(|prefix| !is_known_osv_database_prefix(prefix))
            .cloned()
            .collect::<Vec<_>>();
        if unknown.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "unknown OSV source DB prefix(es): {}",
                unknown.join(", ")
            ))
        }
    }
}

fn required_osv_import_prefixes() -> BTreeSet<String> {
    BTreeSet::from(["GHSA".to_owned(), "OSV".to_owned()])
}

#[cfg(test)]
fn metadata_includes_required_osv_prefixes(value: &str) -> bool {
    if value.trim().eq_ignore_ascii_case("ALL") {
        return true;
    }
    let prefixes = value
        .split(',')
        .map(normalize_osv_prefix)
        .collect::<BTreeSet<_>>();
    required_osv_import_prefixes().is_subset(&prefixes)
}

fn normalize_osv_prefix(prefix: &str) -> String {
    prefix.trim().trim_end_matches('-').to_ascii_uppercase()
}

fn osv_database_dirs_for_selection(
    selection: &OsvImportSelection,
    modified_rows: &[OsvModifiedId],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut database_dirs = BTreeMap::new();
    for row in modified_rows {
        let Some((database_dir, _)) = row.object_path.split_once('/') else {
            continue;
        };
        if is_empty_osv_database_dir(database_dir) {
            continue;
        }
        let osv_id = osv_id_from_path(&row.object_path);
        if !selection.matches_id(&osv_id) {
            continue;
        }
        database_dirs
            .entry(database_dir.to_owned())
            .or_insert_with(BTreeSet::new)
            .insert(osv_source_prefix(&osv_id));
    }
    database_dirs
}

fn is_empty_osv_database_dir(database_dir: &str) -> bool {
    let database_dir = database_dir.trim();
    database_dir.is_empty() || database_dir.eq_ignore_ascii_case("empty")
}

/// Synchronizes KEV and EPSS snapshots through the SQLx-only schema.
pub async fn sync_kev_epss_snapshots_sqlx(db: SqlxDatabase, label: &str) -> Result<(), String> {
    let label = label.to_owned();
    let kev = download_kev_json()
        .await
        .map_err(|error| format!("{label}: failed to download CISA KEV: {error}"))?;
    db.import_kev_json(kev)
        .await
        .map_err(|error| format!("{label}: failed to import CISA KEV: {error}"))?;
    let epss = download_epss_current_csv()
        .await
        .map_err(|error| format!("{label}: failed to download FIRST EPSS: {error}"))?;
    db.import_epss_csv(epss)
        .await
        .map_err(|error| format!("{label}: failed to import FIRST EPSS: {error}"))?;
    db.check()
        .await
        .map_err(|error| format!("{label}: enrichment database check failed: {error}"))
}

/// Downloads the selected public OSV snapshot and imports it through the SQLx writer.
pub async fn sync_osv_selection_from_gcs_sqlx(
    db: SqlxDatabase,
    label: &str,
    selection: OsvImportSelection,
) -> Result<usize, String> {
    let label = label.to_owned();
    let started = Instant::now();
    eprintln!(
        "{label}: syncing OSV records from Google Cloud Storage ({})",
        selection.description()
    );
    selection
        .validate_known_prefixes()
        .map_err(|error| format!("{label}: {error}"))?;
    let source = OsvGcsSource::new_public().map_err(|error| format!("{label}: {error}"))?;
    eprintln!("{label}: downloading OSV modified_id.csv");
    let modified = source
        .modified_id_csv()
        .await
        .map_err(|error| format!("{label}: failed to download OSV modified_id.csv: {error}"))?;
    let modified_rows = parse_modified_id_csv(&modified);
    let cursor = modified_rows
        .first()
        .map(|row| row.modified_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let object_paths = if selection.all {
        vec![OSV_ALL_ZIP.to_owned()]
    } else {
        let database_dirs = osv_database_dirs_for_selection(&selection, &modified_rows);
        if database_dirs.is_empty() {
            eprintln!(
                "{label}: OSV modified_id.csv did not contain records for {}; skipping OSV ZIP download",
                selection.description()
            );
        }
        database_dirs
            .into_keys()
            .map(|database_dir| format!("{database_dir}/{OSV_ALL_ZIP}"))
            .collect()
    };
    if !object_paths.is_empty() {
        eprintln!(
            "{label}: resolved OSV database ZIP(s): {}",
            object_paths.join(", ")
        );
    }
    let mut zip_paths = Vec::with_capacity(object_paths.len());
    for object_path in &object_paths {
        let download_started = Instant::now();
        eprintln!("{label}: downloading OSV {object_path}");
        match download_osv_zip_to_temp(&source, object_path, &label).await {
            Ok(path) => {
                let bytes = std::fs::metadata(&path)
                    .map(|metadata| metadata.len())
                    .unwrap_or(0);
                eprintln!(
                    "{label}: downloaded OSV {object_path} ({bytes} bytes) in {:?}",
                    download_started.elapsed()
                );
                zip_paths.push(path);
            }
            Err(error) => {
                for path in zip_paths {
                    let _ = std::fs::remove_file(path);
                }
                return Err(error);
            }
        }
    }
    let result = import_osv_zip_files_sqlx_with_mode(
        db.clone(),
        &zip_paths,
        Some(&selection),
        &cursor,
        true,
    )
    .await;
    for path in zip_paths {
        let _ = std::fs::remove_file(path);
    }
    let imported = result?;
    db.set_metadata_value(
        OSV_IMPORT_ID_PREFIXES_METADATA_KEY,
        &selection.as_metadata_value(),
    )
    .await
    .map_err(|error| format!("{label}: failed to save OSV selection: {error}"))?;
    eprintln!(
        "{label}: imported {imported} OSV records in {:?}",
        started.elapsed()
    );
    Ok(imported)
}

/// Imports an OSV ZIP through the SQLx writer and advances the cursor only after every batch,
/// FTS rebuild, and integrity check has succeeded.
pub async fn import_osv_zip_file_sqlx(
    db: SqlxDatabase,
    path: &Path,
    selection: Option<&OsvImportSelection>,
    completion_cursor: &str,
) -> Result<usize, String> {
    let paths = [path.to_path_buf()];
    import_osv_zip_files_sqlx_with_mode(db, &paths, selection, completion_cursor, false).await
}

async fn import_osv_zip_files_sqlx_with_mode(
    db: SqlxDatabase,
    paths: &[PathBuf],
    selection: Option<&OsvImportSelection>,
    completion_cursor: &str,
    bulk_load: bool,
) -> Result<usize, String> {
    let completion_cursor = completion_cursor.to_owned();
    db.begin_osv_sync()
        .await
        .map_err(|error| format!("failed to begin OSV sync: {error}"))?;
    if bulk_load {
        db.prepare_osv_bulk_load()
            .await
            .map_err(|error| format!("failed to prepare OSV bulk load: {error}"))?;
    }
    let mut imported = 0usize;
    let mut import_error = None;
    let mut seen_osv_ids = AHashSet::new();
    for path in paths {
        let (sender, mut receiver) = mpsc::channel(8);
        let path = path.clone();
        let selection = selection.cloned();
        let skip_osv_ids = seen_osv_ids.clone();
        let reader = tokio::task::spawn_blocking(move || {
            read_osv_zip_batches(&path, None, selection.as_ref(), Some(&skip_osv_ids), sender)
        });
        while let Some(batch) = receiver.recv().await {
            let batch = match batch {
                Ok(batch) => batch,
                Err(error) => {
                    import_error = Some(error);
                    break;
                }
            };
            let batch_started = Instant::now();
            let import_result = if bulk_load {
                db.import_osv_records_bulk_init(batch.records).await
            } else {
                db.import_osv_records_deferred_search(batch.records).await
            };
            match import_result {
                Ok(count) => {
                    imported += count;
                    eprintln!(
                        "osv: imported {imported} records (batch {count} in {:?})",
                        batch_started.elapsed()
                    );
                }
                Err(error) => {
                    import_error = Some(format!("failed to import OSV batch: {error}"));
                    break;
                }
            }
        }
        // Dropping the receiver first unblocks a reader waiting on bounded backpressure.
        drop(receiver);
        let reader_result = reader
            .await
            .map_err(|_| "OSV zip reader task panicked".to_owned());
        if import_error.is_none() {
            match reader_result {
                Ok(Ok(read_osv_ids)) => seen_osv_ids.extend(read_osv_ids),
                Ok(Err(error)) | Err(error) => import_error = Some(error),
            }
        }
        if import_error.is_some() {
            break;
        }
    }
    let result = async {
        if let Some(error) = import_error {
            return Err(error);
        }
        eprintln!("osv: rebuilding deferred indexes and search data");
        if bulk_load {
            db.finish_osv_bulk_load()
                .await
                .map_err(|error| format!("failed to finish OSV bulk load: {error}"))?;
        } else {
            db.rebuild_osv_search()
                .await
                .map_err(|error| format!("failed to rebuild OSV FTS: {error}"))?;
        }
        db.check()
            .await
            .map_err(|error| format!("failed OSV database check: {error}"))?;
        db.complete_osv_sync(&completion_cursor)
            .await
            .map_err(|error| format!("failed to advance OSV cursor: {error}"))?;
        Ok::<(), String>(())
    }
    .await;
    if let Err(error) = result {
        if bulk_load {
            let _ = db.finish_osv_bulk_load().await;
        }
        let _ = db.fail_osv_sync(&error).await;
        return Err(error);
    }
    Ok(imported)
}

fn read_osv_zip_batches(
    path: &Path,
    target_paths: Option<&AHashSet<String>>,
    selection: Option<&OsvImportSelection>,
    skip_osv_ids: Option<&AHashSet<String>>,
    batch_tx: mpsc::Sender<Result<OsvImportBatch, String>>,
) -> Result<AHashSet<String>, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|err| format!("failed to read OSV zip: {err}"))?;
    let mut records = Vec::with_capacity(OSV_IMPORT_BATCH_SIZE);
    let mut seen_osv_ids = AHashSet::new();

    for index in 0..archive.len() {
        let read_started = Instant::now();
        let mut entry = archive
            .by_index(index)
            .map_err(|err| format!("failed to read OSV zip entry {index}: {err}"))?;
        let name = entry.name().to_owned();
        if !name.ends_with(".json") {
            continue;
        }
        if let Some(target_paths) = target_paths
            && !target_paths.contains(&name)
        {
            continue;
        }
        let osv_id = osv_id_from_path(&name);
        if let Some(selection) = selection
            && !selection.matches_id(&osv_id)
        {
            continue;
        }
        if skip_osv_ids.is_some_and(|ids| ids.contains(&osv_id)) || seen_osv_ids.contains(&osv_id) {
            continue;
        }
        let mut raw_json = String::new();
        entry
            .read_to_string(&mut raw_json)
            .map_err(|err| format!("failed to read {name}: {err}"))?;
        let _ = read_started;
        records.push(OsvRawRecord {
            source_path: Some(format!("gs://osv-vulnerabilities/{name}")),
            raw_json,
        });
        seen_osv_ids.insert(osv_id);

        if records.len() >= OSV_IMPORT_BATCH_SIZE {
            send_osv_import_batch(&batch_tx, &mut records)?;
        }
    }

    if !records.is_empty() {
        send_osv_import_batch(&batch_tx, &mut records)?;
    }

    Ok(seen_osv_ids)
}

fn send_osv_import_batch(
    batch_tx: &mpsc::Sender<Result<OsvImportBatch, String>>,
    records: &mut Vec<OsvRawRecord>,
) -> Result<(), String> {
    let batch_records = std::mem::replace(records, Vec::with_capacity(OSV_IMPORT_BATCH_SIZE));
    let batch = OsvImportBatch {
        records: batch_records,
    };
    batch_tx
        .blocking_send(Ok(batch))
        .map_err(|_| "OSV import pipeline stopped before zip reader completed".to_owned())
}

fn osv_id_from_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_ascii_uppercase()
}

fn osv_source_prefix(osv_id: &str) -> String {
    OSV_DATABASE_SOURCE_PREFIXES
        .iter()
        .filter(|prefix| osv_id.starts_with(&format!("{prefix}-")))
        .max_by_key(|prefix| prefix.len())
        .copied()
        .unwrap_or_else(|| osv_id.split_once('-').map_or(osv_id, |(prefix, _)| prefix))
        .to_owned()
}

async fn download_osv_zip_to_temp(
    osv: &OsvGcsSource,
    object_path: &str,
    label: &str,
) -> Result<PathBuf, String> {
    let object_filename = object_path.replace('/', "-");
    let filename = format!(
        "qanvuli-osv-{object_filename}-{}-{}.zip",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let primary = temporary_zip_file_path(&filename, None)
        .map_err(|err| format!("{label}: failed to prepare temporary OSV zip path: {err}"))?;
    match download_osv_zip_object(osv, object_path, &primary).await {
        Ok(()) => Ok(primary),
        Err(err) => {
            let fallback = temporary_zip_file_path_in(binary_temporary_directory(), &filename)
                .map_err(|fallback_err| {
                    format!(
                        "{label}: failed to download OSV {object_path} to {} ({err}); also failed to prepare fallback path: {fallback_err}",
                        primary.display()
                    )
                })?;
            if fallback == primary {
                return Err(format!(
                    "{label}: failed to download OSV {object_path} to {}: {err}",
                    primary.display()
                ));
            }
            eprintln!(
                "{label}: failed to download OSV {object_path} to {} ({err}); retrying {}",
                primary.display(),
                fallback.display()
            );
            let _ = std::fs::remove_file(&primary);
            download_osv_zip_object(osv, object_path, &fallback)
                .await
                .map_err(|fallback_err| {
                    format!(
                        "{label}: failed to download OSV {object_path} to fallback {}: {fallback_err}",
                        fallback.display()
                    )
                })?;
            Ok(fallback)
        }
    }
}

async fn download_osv_zip_object(
    osv: &OsvGcsSource,
    object_path: &str,
    output: &Path,
) -> Result<(), String> {
    let result = if object_path == OSV_ALL_ZIP {
        osv.download_all_zip_to_file(output).await
    } else {
        let Some((source_prefix, filename)) = object_path.split_once('/') else {
            return osv
                .download_all_zip_to_file(output)
                .await
                .map_err(|err| err.to_string());
        };
        if filename == OSV_ALL_ZIP {
            osv.download_source_zip_to_file(source_prefix, output).await
        } else {
            osv.download_all_zip_to_file(output).await
        }
    };
    result.map_err(|err| err.to_string())
}

fn temporary_zip_file_path(filename: &str, required_bytes: Option<u64>) -> Result<PathBuf, String> {
    let system_temp_root = std::env::temp_dir();
    let temp_root = system_temp_root.join("qanvuli");
    if required_bytes.is_some_and(|required| {
        available_storage_bytes(&system_temp_root).is_some_and(|available| available < required)
    }) {
        return temporary_zip_file_path_in(binary_temporary_directory(), filename);
    }
    temporary_zip_file_path_in(temp_root, filename)
        .or_else(|_| temporary_zip_file_path_in(binary_temporary_directory(), filename))
}

fn temporary_zip_file_path_in(dir: PathBuf, filename: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    Ok(dir.join(filename))
}

fn binary_temporary_directory() -> PathBuf {
    binary_directory().join("tmp")
}

fn binary_directory() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(target_os = "linux")]
fn available_storage_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_ulong};

    #[repr(C)]
    struct Statvfs {
        f_bsize: c_ulong,
        f_frsize: c_ulong,
        f_blocks: c_ulong,
        f_bfree: c_ulong,
        f_bavail: c_ulong,
        f_files: c_ulong,
        f_ffree: c_ulong,
        f_favail: c_ulong,
        f_fsid: c_ulong,
        f_flag: c_ulong,
        f_namemax: c_ulong,
        __f_spare: [c_int; 6],
    }

    unsafe extern "C" {
        fn statvfs(path: *const c_char, buf: *mut Statvfs) -> c_int;
    }

    let path = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<Statvfs>::uninit();
    let rc = unsafe { statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    Some(stats.f_bavail.saturating_mul(stats.f_frsize))
}

#[cfg(not(target_os = "linux"))]
fn available_storage_bytes(_path: &Path) -> Option<u64> {
    None
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
    let output_path = temporary_zip_file_path(&filename, Some(asset.size)).map_err(|err| {
        format!("failed to prepare temporary download path for {filename}: {err}")
    })?;
    asset
        .async_download_as(&output_path)
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    eprintln!("{kind}: ready {}", output_path.display());
    Ok(DownloadedAsset {
        path: output_path,
        downloaded: true,
    })
}

pub fn remove_processed_zip(path: &Path) -> Result<(), String> {
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
        .async_download_as(&path)
        .await
        .map_err(|err| format!("failed to download {}: {err}", catalog.name))?;
    eprintln!("cwe: ready {}", path.display());
    Ok(path)
}

/// Synchronizes the CWE catalog into the SQLx schema.
pub async fn sync_cwe_catalog_sqlx(db: SqlxDatabase) -> Result<(), String> {
    #[cfg(test)]
    if let Some(path) = local_test_cwe_catalog_path() {
        eprintln!("cwe: using local {}", path.display());
        let count = upsert_cwe_catalog_file_sqlx(db, &path).await?;
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
    let download = match catalog_file
        .async_download_if_changed_as(&path, etag.as_deref(), last_modified.as_deref())
        .await
    {
        Ok(download) => download,
        Err(error) => {
            if let Some(path) = local_cwe_catalog_path(&catalog_file.name) {
                eprintln!(
                    "cwe: failed to update {} ({error}); using local {}",
                    catalog_file.name,
                    path.display()
                );
                let count = upsert_cwe_catalog_file_sqlx(db, &path).await?;
                eprintln!("cwe: upserted {count} CWE master rows");
                return Ok(());
            }
            return Err(format!("failed to update {}: {error}", catalog_file.name));
        }
    };
    let Some(path) = download.path else {
        eprintln!("cwe: catalog unchanged");
        return Ok(());
    };
    let count = upsert_cwe_catalog_file_sqlx(db.clone(), &path).await?;
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

async fn upsert_cwe_catalog_file_sqlx(db: SqlxDatabase, path: &Path) -> Result<usize, String> {
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

#[cfg(test)]
fn local_test_cwe_catalog_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("cwec_latest.xml.zip");
    path.exists().then_some(path)
}

pub async fn latest_asset(kind: ReleaseAssetKind) -> Result<GitHubReleaseFile, String> {
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

pub async fn delta_assets_oldest_first() -> Result<Vec<GitHubReleaseFile>, String> {
    let mut cve = CveRelease::new();
    cve.async_get_all()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;
    Ok(cve.get_delta_files_oldest_first())
}

/// Applies local or downloaded CVE delta archives through the SQLx writer.
pub async fn apply_delta_updates(
    db: &SqlxDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
) -> Result<Vec<PathBuf>, String> {
    let paths = if let Some(path) = zip {
        vec![path]
    } else {
        let mut paths = Vec::new();
        for asset in delta_assets_oldest_first().await? {
            let filename = asset
                .safe_file_name()
                .map_err(|error| format!("unsafe asset name {}: {error}", asset.name))?;
            let path = temporary_zip_file_path(filename, Some(asset.size))
                .map_err(|error| format!("failed to prepare delta archive {filename}: {error}"))?;
            asset
                .async_download_as(&path)
                .await
                .map_err(|error| format!("failed to download {}: {error}", asset.name))?;
            paths.push(path);
        }
        paths
    };
    for path in &paths {
        ingest_zip_sqlx(db.clone(), "update", path, max_chunks).await?;
    }
    Ok(paths)
}

/// Refreshes devel's enrichment sources using the SQLx-only import paths.
pub async fn sync_all_enrichment_sources_after_update(
    db: &SqlxDatabase,
    label: &str,
    requested_osv_additions: Option<&OsvImportSelection>,
) -> Result<(), String> {
    let stored = db
        .metadata_value(OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
        .await
        .map_err(|error| format!("{label}: failed to read OSV import selection: {error}"))?;
    let current = OsvImportSelection::from_metadata(stored.as_deref())
        .unwrap_or_else(|| OsvImportSelection::default_init(false, &[]));
    let selection =
        requested_osv_additions.map_or(current.clone(), |additions| current.merged_with(additions));
    sync_osv_selection_from_gcs_sqlx(db.clone(), label, selection).await?;
    sync_kev_epss_snapshots_sqlx(db.clone(), label).await?;
    db.rebuild_identifier_graph()
        .await
        .map_err(|error| format!("{label}: failed to rebuild identifier graph: {error}"))
}

/// Imports raw CVE JSON into the SQLx schema.
pub async fn ingest_zip_sqlx(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
) -> Result<usize, String> {
    ingest_zip_sqlx_with_mode(db, label, asset_path, max_chunks, false).await
}

/// Imports a full replacement archive with devel's deferred-index bulk-load policy.
pub async fn ingest_zip_sqlx_bulk(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
) -> Result<usize, String> {
    ingest_zip_sqlx_with_mode(db, label, asset_path, max_chunks, true).await
}

async fn ingest_zip_sqlx_with_mode(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
    bulk_replace: bool,
) -> Result<usize, String> {
    let storage = ZipStorage::new(asset_path.to_string_lossy().to_string())
        .map_err(|error| format!("{label}: failed to open {}: {error}", asset_path.display()))?;
    let entries = storage.enum_json_entries();
    eprintln!("{label}: enumerated {} CVE JSON entries", entries.len());
    // Keep the already parsed central directory and archive handle for every chunk. Reopening a
    // 360k-entry ZIP in Rayon task initializers repeatedly dominates decompression time.
    let storage = Arc::new(std::sync::Mutex::new(storage));
    if bulk_replace {
        db.prepare_cve_bulk_load()
            .await
            .map_err(|error| format!("{label}: failed to prepare CVE bulk load: {error}"))?;
    }
    let mut imported = 0usize;
    for (chunk_index, chunk) in entries.chunks(INGEST_CHUNK_SIZE).enumerate() {
        if max_chunks.is_some_and(|maximum| chunk_index >= maximum) {
            break;
        }
        let storage = storage.clone();
        let chunk = chunk.to_vec();
        let label = label.to_owned();
        let reader_label = label.clone();
        let read_started = Instant::now();
        eprintln!(
            "{label}: reading/decompressing CVE chunk {chunk_index} ({} records)",
            chunk.len()
        );
        let records = tokio::task::spawn_blocking(move || {
            read_cve_zip_chunk(&storage, &chunk, &reader_label)
        })
        .await
        .map_err(|error| format!("{label}: CVE ZIP reader task panicked: {error}"))??;
        eprintln!(
            "{label}: decoded CVE chunk {chunk_index} in {:?}; writing database batch",
            read_started.elapsed()
        );
        let write_started = Instant::now();
        imported += db
            .import_cve_raw_jsons_deferred_search(records)
            .await
            .map_err(|error| {
                format!("{label}: failed to import CVE chunk {chunk_index}: {error}")
            })?;
        eprintln!(
            "{label}: committed CVE chunk {chunk_index} in {:?}",
            write_started.elapsed()
        );
    }
    let fts_started = Instant::now();
    eprintln!("{label}: rebuilding CVE/OSV search indexes");
    if bulk_replace {
        db.finish_cve_bulk_load()
            .await
            .map_err(|error| format!("{label}: failed to finish CVE bulk load: {error}"))?;
    } else {
        db.rebuild_search()
            .await
            .map_err(|error| format!("{label}: failed to rebuild FTS: {error}"))?;
    }
    eprintln!(
        "{label}: rebuilt search indexes in {:?}",
        fts_started.elapsed()
    );
    db.check()
        .await
        .map_err(|error| format!("{label}: database integrity check failed: {error}"))?;
    Ok(imported)
}

/// Reads one CVE ZIP chunk using the access strategy matching its backing store.
///
/// Disk-backed ZIPs are fastest through one sequential archive handle; repeatedly seeking the
/// same large archive from multiple workers defeats OS readahead. An in-memory inner archive has
/// no seek penalty, so it can use independent Rayon readers safely.
fn read_cve_zip_chunk(
    storage: &std::sync::Mutex<ZipStorage>,
    entries: &[qanvuli_core::ingest::JsonEntry],
    label: &str,
) -> Result<Vec<String>, String> {
    let mut storage = storage
        .lock()
        .map_err(|_| format!("{label}: CVE ZIP reader lock was poisoned"))?;
    entries
        .iter()
        .map(|entry| {
            let bytes = storage
                .get_json_entry_bytes(entry)
                .map_err(|error| format!("{label}: failed to read {}: {error}", entry.path))?;
            String::from_utf8(bytes)
                .map_err(|error| format!("{label}: invalid UTF-8 in {}: {error}", entry.path))
        })
        .collect()
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
        let db_path = database::sqlite_file_path(&db_url).unwrap();
        let executable = std::env::current_exe().unwrap();

        assert_eq!(db_path, executable.parent().unwrap().join("db.sqlite"));
    }

    #[test]
    fn redact_database_url_removes_embedded_credentials() {
        let redacted = redact_database_url("postgres://alice:super-secret@example.test/qanvuli");

        assert_eq!(redacted, "postgres://REDACTED@example.test/qanvuli");
        assert!(!redacted.contains("super-secret"));
        assert!(!redacted.contains("alice"));
    }

    #[test]
    fn remove_processed_zip_deletes_existing_file() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-processed-zip-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, b"zip").unwrap();

        remove_processed_zip(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn osv_selection_resolves_gcs_database_dirs_from_modified_paths() {
        let selection =
            OsvImportSelection::default_init(false, &["ghsa".to_owned(), "pysec".to_owned()]);
        let rows = vec![
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "PyPI/GHSA-73jc-5mrq-prw7.json".to_owned(),
            },
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "RubyGems/GHSA-8p34-64r3-mwg8.json".to_owned(),
            },
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "PyPI/PYSEC-2026-1.json".to_owned(),
            },
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "crates.io/RUSTSEC-2026-1.json".to_owned(),
            },
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "[EMPTY]/GHSA-empty.json".to_owned(),
            },
            OsvModifiedId {
                modified_at: "2026-07-07T00:00:00Z".to_owned(),
                object_path: "empty/GHSA-lowercase-empty.json".to_owned(),
            },
        ];

        let database_dirs = osv_database_dirs_for_selection(&selection, &rows);

        assert_eq!(
            database_dirs.get("PyPI"),
            Some(&BTreeSet::from(["GHSA".to_owned(), "PYSEC".to_owned()]))
        );
        assert_eq!(
            database_dirs.get("RubyGems"),
            Some(&BTreeSet::from(["GHSA".to_owned()]))
        );
        assert_eq!(
            database_dirs.get("[EMPTY]"),
            Some(&BTreeSet::from(["GHSA".to_owned()]))
        );
        assert!(!database_dirs.contains_key("crates.io"));
        assert!(!database_dirs.contains_key("empty"));
    }

    #[test]
    fn osv_and_ghsa_are_always_included_in_osv_selection() {
        let selection = OsvImportSelection::default_init(false, &["pysec".to_owned()]);
        assert!(selection.matches_id("OSV-2024-1"));
        assert!(selection.matches_id("GHSA-aaaa-bbbb-cccc"));
        assert!(selection.matches_id("PYSEC-2024-1"));

        let restored = OsvImportSelection::from_metadata(Some("OSV")).unwrap();
        assert!(restored.matches_id("GHSA-aaaa-bbbb-cccc"));

        assert!(!metadata_includes_required_osv_prefixes("OSV"));
        assert!(metadata_includes_required_osv_prefixes("OSV,GHSA"));
        assert!(metadata_includes_required_osv_prefixes("all"));
    }

    #[test]
    fn osv_zip_reader_skips_seen_and_duplicate_osv_ids() {
        use std::io::Write;

        let zip_path = std::env::temp_dir().join(format!(
            "qanvuli-osv-reader-dedupe-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        for (name, raw_json) in [
            ("GHSA-skip.json", r#"{"id":"GHSA-skip"}"#),
            ("GHSA-keep.json", r#"{"id":"GHSA-keep"}"#),
            ("nested/GHSA-keep.json", r#"{"id":"GHSA-keep"}"#),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(raw_json.as_bytes()).unwrap();
        }
        zip.finish().unwrap();

        let selection = OsvImportSelection::default_init(false, &["ghsa".to_owned()]);
        let skip_osv_ids = AHashSet::from(["GHSA-SKIP".to_owned()]);
        let (batch_tx, mut batch_rx) = mpsc::channel(8);
        read_osv_zip_batches(
            &zip_path,
            None,
            Some(&selection),
            Some(&skip_osv_ids),
            batch_tx,
        )
        .unwrap();
        let mut batches = Vec::new();
        while let Ok(batch) = batch_rx.try_recv() {
            batches.push(batch.unwrap());
        }

        assert_eq!(
            batches
                .iter()
                .map(|batch| batch.records.len())
                .sum::<usize>(),
            1
        );

        let _ = std::fs::remove_file(zip_path);
    }

    #[tokio::test]
    async fn sqlx_zip_ingest_imports_cve_and_builds_stable_search() {
        use qanvuli_core::database::SqlxDatabase;
        use std::io::Write;

        let zip_path = std::env::temp_dir().join(format!(
            "qanvuli-sqlx-ingest-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "CVE-2099-0001.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(br#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"SQLx fixture"}}}"#)
            .unwrap();
        zip.finish().unwrap();
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        assert_eq!(
            ingest_zip_sqlx(database.clone(), "test", &zip_path, None)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .search_cves("fixture", false, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        database.close().await.unwrap();
        let _ = std::fs::remove_file(zip_path);
    }

    #[tokio::test]
    async fn sqlx_osv_zip_ingest_advances_cursor_only_after_complete_validation() {
        use qanvuli_core::database::SqlxDatabase;
        use std::io::Write;

        let zip_path = std::env::temp_dir().join(format!(
            "qanvuli-sqlx-osv-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "GHSA-TEST-0001.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(include_bytes!(
            "../../../../fixtures/osv/GHSA-TEST-0001.json"
        ))
        .unwrap();
        zip.finish().unwrap();
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        assert_eq!(
            import_osv_zip_file_sqlx(database.clone(), &zip_path, None, "2099-01-02T00:00:00Z")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            database.begin_osv_sync().await.unwrap(),
            Some("2099-01-02T00:00:00Z".to_owned())
        );
        database.close().await.unwrap();
        let _ = std::fs::remove_file(zip_path);
    }

    #[tokio::test]
    async fn sqlx_osv_zip_failure_keeps_cursor_and_retry_is_idempotent() {
        use qanvuli_core::database::SqlxDatabase;
        use std::io::Write;

        let directory = std::env::temp_dir();
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let failing_zip = directory.join(format!("qanvuli-osv-failing-{nonce}.zip"));
        let retry_zip = directory.join(format!("qanvuli-osv-retry-{nonce}.zip"));
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&failing_zip).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        for index in 0..OSV_IMPORT_BATCH_SIZE {
            let id = format!("GHSA-2099-retry-{index:04}");
            zip.start_file(format!("{id}.json"), options).unwrap();
            zip.write_all(
                format!(
                    r#"{{"schema_version":"1.8.0","id":"{id}","modified":"2099-01-01T00:00:00Z"}}"#
                )
                .as_bytes(),
            )
            .unwrap();
        }
        zip.start_file("GHSA-2099-invalid.json", options).unwrap();
        zip.write_all(br#"{"schema_version":"1.7.3","id":"GHSA-2099-invalid"}"#)
            .unwrap();
        zip.finish().unwrap();

        let mut zip = zip::ZipWriter::new(std::fs::File::create(&retry_zip).unwrap());
        zip.start_file("GHSA-2099-retry-0000.json", options)
            .unwrap();
        zip.write_all(
            br#"{"schema_version":"1.8.0","id":"GHSA-2099-retry-0000","modified":"2099-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        zip.finish().unwrap();

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        assert!(
            import_osv_zip_file_sqlx(database.clone(), &failing_zip, None, "2099-01-02T00:00:00Z")
                .await
                .is_err()
        );
        let state = database.source_sync_states().await.unwrap().pop().unwrap();
        assert_eq!(state.status, "failed");
        assert_eq!(state.last_cursor, None);

        assert_eq!(
            import_osv_zip_file_sqlx(database.clone(), &retry_zip, None, "2099-01-02T00:00:00Z")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            database.begin_osv_sync().await.unwrap(),
            Some("2099-01-02T00:00:00Z".to_owned())
        );
        assert!(
            database
                .find_osv_summary("GHSA-2099-retry-0000")
                .await
                .unwrap()
                .is_some()
        );
        database.close().await.unwrap();
        let _ = std::fs::remove_file(failing_zip);
        let _ = std::fs::remove_file(retry_zip);
    }
}
