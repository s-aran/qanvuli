use chrono::{DateTime, Duration as ChronoDuration, FixedOffset, NaiveDate, TimeZone, Utc};
use clap::ValueEnum;
use qanvuli_collector::providers::{
    cve::CveRelease,
    cwe::CweCatalogFile,
    epss::download_epss_current_csv,
    kev::download_kev_json,
    osv::{OSV_ALL_ZIP, OsvGcsSource, OsvModifiedId, parse_modified_id_csv},
};
use qanvuli_db::{
    CveActiveModels, CveDatabase, CveZipFileRecord, OsvRawRecord, ReadJsonFileRecord,
};
use qanvuli_models::cwe::read_cwe_catalog_zip;
use qanvuli_models::osv::{OSV_DATABASE_SOURCE_PREFIXES, is_known_osv_database_prefix};
use qanvuli_utils::loader::{self, FileStorageTrait, JsonEntry};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use url::Url;

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

const INGEST_CHUNK_SIZE: usize = 10000;
const REPLACE_ALL_INGEST_CHUNK_SIZE: usize = 20000;
const OSV_IMPORT_BATCH_SIZE: usize = 5000;
const READ_PARSE_PIPELINE_BATCH_SIZE: usize = 512;
const CWE_ETAG_METADATA_KEY: &str = "cwe_catalog:etag";
const CWE_LAST_MODIFIED_METADATA_KEY: &str = "cwe_catalog:last_modified";
const CVE_ZIP_TYPE_ALL_MIDNIGHT: i32 = 0;
const CVE_ZIP_TYPE_DELTA_HOURLY: i32 = 1;
const CVE_ZIP_TYPE_DELTA_END_OF_DAY: i32 = 2;
pub(crate) const OSV_IMPORT_ID_PREFIXES_METADATA_KEY: &str = "osv_import_id_prefixes";

/// Callback used by long-running import commands to report progress to the TUI.
pub type IngestProgressCallback = Arc<dyn Fn(IngestProgress) + Send + Sync>;
type ParsedCveFile = Result<(CveActiveModels, ReadJsonFileRecord), String>;

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

#[derive(Clone, Debug)]
struct CveZipAsset {
    path_or_name: String,
    zip_datetime: String,
    zip_type: i32,
}

#[derive(Debug)]
struct OsvImportBatch {
    records: Vec<OsvRawRecord>,
    batch_count: usize,
    seen: usize,
    source_seen: BTreeMap<String, usize>,
    read_elapsed: Duration,
    send_wait_elapsed: Duration,
}

#[derive(Debug)]
struct OsvZipReadResult {
    matched_prefixes: BTreeSet<String>,
    seen_osv_ids: HashSet<String>,
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
#[derive(Debug, Default)]
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

/// Connects to the configured CVE database and converts database errors for CLI output.
pub async fn connect_db(db_url: &str) -> Result<CveDatabase, String> {
    CveDatabase::connect(db_url)
        .await
        .map_err(|err| format!("failed to connect database `{db_url}`: {err}"))
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
        let id_prefixes = if prefixes.is_empty() {
            BTreeSet::from(["OSV".to_owned()])
        } else {
            prefixes
                .iter()
                .map(|prefix| normalize_osv_prefix(prefix))
                .collect()
        };
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
        let id_prefixes = value
            .split(',')
            .map(str::trim)
            .filter(|prefix| !prefix.is_empty())
            .map(normalize_osv_prefix)
            .collect::<BTreeSet<_>>();
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

    fn prefixes(&self) -> &BTreeSet<String> {
        &self.id_prefixes
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

fn normalize_osv_prefix(prefix: &str) -> String {
    prefix.trim().trim_end_matches('-').to_ascii_uppercase()
}

/// Rebuilds the identifier graph and writes a compact timing message to stderr.
pub async fn rebuild_graph_and_report(db: &CveDatabase, label: &str) -> Result<(), String> {
    let started = Instant::now();
    let summary = db
        .rebuild_identifier_graph()
        .await
        .map_err(|err| format!("{label}: failed to rebuild identifier graph: {err}"))?;
    eprintln!(
        "{label}: rebuilt identifier graph ({} edge records) in {}",
        summary.record_count,
        format_elapsed(started.elapsed())
    );
    Ok(())
}

/// Writes source synchronization status for enrichment providers to stderr.
pub async fn report_enrichment_source_status(db: &CveDatabase, label: &str) -> Result<(), String> {
    let states = db
        .source_sync_states()
        .await
        .map_err(|err| format!("{label}: failed to read enrichment source status: {err}"))?;
    let sources = db
        .db_sources()
        .await
        .map_err(|err| format!("{label}: failed to read DB source registry: {err}"))?;
    for source in sources {
        if source.source == "CVE" {
            continue;
        }
        match states.iter().find(|state| state.source == source.source) {
            Some(state) if state.status == "success" => {
                eprintln!(
                    "{label}: {} ({}) last_success_at={} records={} file={}",
                    source.source,
                    source.display_name,
                    state.last_success_at.as_deref().unwrap_or("unknown"),
                    state.record_count,
                    source.default_filename
                );
            }
            Some(state) => {
                eprintln!(
                    "{label}: {} ({}) status={} last_attempt_at={} error={}",
                    source.source,
                    source.display_name,
                    state.status,
                    state.last_attempt_at.as_deref().unwrap_or("never"),
                    state.error_message.as_deref().unwrap_or("-")
                );
            }
            None => {
                if source.source == "OSV" {
                    eprintln!(
                        "{label}: OSV ({}) is not synced; run `qanvuli init` and add `--osv-<prefix>` or `--osv-all` as needed",
                        source.display_name
                    );
                } else {
                    eprintln!(
                        "{label}: {} ({}) is not synced; run `qanvuli init` to refresh all DB sources",
                        source.source, source.display_name
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn sync_all_enrichment_sources_after_init(
    db: &CveDatabase,
    label: &str,
    osv_selection: &OsvImportSelection,
) -> Result<(), String> {
    let started = Instant::now();
    sync_osv_selection_from_gcs_with_mode(db, label, osv_selection, true).await?;
    sync_kev_epss_snapshots(db, label).await?;
    eprintln!(
        "{label}: enrichment sync completed in {}",
        format_elapsed(started.elapsed())
    );
    Ok(())
}

pub async fn sync_all_enrichment_sources_after_update(
    db: &CveDatabase,
    label: &str,
    requested_osv_additions: Option<&OsvImportSelection>,
) -> Result<(), String> {
    let started = Instant::now();
    let osv_started = Instant::now();
    eprintln!("{label}: syncing OSV modified records from Google Cloud Storage");
    let osv = OsvGcsSource::new_public().map_err(|err| format!("{label}: {err}"))?;
    let modified_csv = osv
        .modified_id_csv()
        .await
        .map_err(|err| format!("{label}: failed to download OSV modified_id.csv: {err}"))?;
    let previous_cursor = db
        .source_sync_states()
        .await
        .map_err(|err| format!("{label}: failed to read source sync state: {err}"))?
        .into_iter()
        .find(|state| state.source == "OSV")
        .and_then(|state| state.last_cursor);
    let selection_metadata = db
        .metadata_value(OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
        .await
        .map_err(|err| format!("{label}: failed to read OSV import selection: {err}"))?;
    let selection = OsvImportSelection::from_metadata(selection_metadata.as_deref())
        .unwrap_or_else(|| OsvImportSelection::default_init(false, &[]));
    selection
        .validate_known_prefixes()
        .map_err(|err| format!("{label}: {err}"))?;
    if let Some(additions) = requested_osv_additions {
        let selection = selection.merged_with(additions);
        eprintln!(
            "{label}: OSV selection expanded to {}; seeding selected records",
            selection.description()
        );
        sync_osv_selection_from_gcs(db, label, &selection).await?;
        sync_kev_epss_snapshots(db, label).await?;
        eprintln!(
            "{label}: enrichment sync completed in {}",
            format_elapsed(started.elapsed())
        );
        return Ok(());
    }
    if previous_cursor.is_none() {
        eprintln!(
            "{label}: skipping OSV modified sync because no OSV cursor exists; run `qanvuli init` first"
        );
        eprintln!(
            "{label}: OSV modified sync completed in {}",
            format_elapsed(osv_started.elapsed())
        );
        sync_kev_epss_snapshots(db, label).await?;
        eprintln!(
            "{label}: enrichment sync completed in {}",
            format_elapsed(started.elapsed())
        );
        return Ok(());
    }
    let mut cursor = previous_cursor.clone();
    let mut saw_first_modified_row = false;
    let mut object_paths = HashSet::new();
    for row in parse_modified_id_csv(&modified_csv) {
        if !saw_first_modified_row {
            cursor = Some(row.modified_at.clone());
            saw_first_modified_row = true;
        }
        if previous_cursor
            .as_deref()
            .is_some_and(|previous| row.modified_at.as_str() <= previous)
        {
            break;
        }
        if !selection.matches_id(&osv_id_from_path(&row.object_path)) {
            continue;
        }
        object_paths.insert(row.object_path);
    }
    if object_paths.is_empty() {
        eprintln!("{label}: OSV modified_id.csv has no new records");
        eprintln!(
            "{label}: OSV modified sync completed in {}",
            format_elapsed(osv_started.elapsed())
        );
        sync_kev_epss_snapshots(db, label).await?;
        eprintln!(
            "{label}: enrichment sync completed in {}",
            format_elapsed(started.elapsed())
        );
        return Ok(());
    }
    let zip_path = download_osv_all_zip_to_temp(&osv, label).await?;
    let summary = import_osv_zip_file_in_batches(
        db,
        &zip_path,
        OsvZipImportOptions {
            target_paths: Some(&object_paths),
            selection: Some(&selection),
            seen_osv_ids: None,
            cursor: cursor.as_deref(),
            label,
            bulk_init: false,
        },
    )
    .await;
    let _ = std::fs::remove_file(&zip_path);
    let summary = summary?;
    eprintln!(
        "{label}: upserted OSV records={} skipped={} in {}",
        summary.imported,
        summary.skipped,
        format_elapsed(osv_started.elapsed())
    );
    sync_kev_epss_snapshots(db, label).await?;
    eprintln!(
        "{label}: enrichment sync completed in {}",
        format_elapsed(started.elapsed())
    );
    Ok(())
}

pub async fn sync_osv_selection_from_gcs(
    db: &CveDatabase,
    label: &str,
    selection: &OsvImportSelection,
) -> Result<(), String> {
    sync_osv_selection_from_gcs_with_mode(db, label, selection, false).await
}

async fn sync_osv_selection_from_gcs_with_mode(
    db: &CveDatabase,
    label: &str,
    selection: &OsvImportSelection,
    bulk_init: bool,
) -> Result<(), String> {
    let started = Instant::now();
    eprintln!(
        "{label}: syncing OSV records from Google Cloud Storage ({})",
        selection.description()
    );
    selection
        .validate_known_prefixes()
        .map_err(|err| format!("{label}: {err}"))?;
    let osv = OsvGcsSource::new_public().map_err(|err| format!("{label}: {err}"))?;
    let modified_csv = osv
        .modified_id_csv()
        .await
        .map_err(|err| format!("{label}: failed to download OSV modified_id.csv: {err}"))?;
    let modified_rows = parse_modified_id_csv(&modified_csv);
    let cursor = modified_rows.first().map(|row| row.modified_at.as_str());
    if bulk_init {
        db.prepare_bulk_osv_import()
            .await
            .map_err(|err| format!("{label}: failed to prepare OSV bulk import: {err}"))?;
    }
    let summary = import_osv_selection_zips_from_gcs(
        db,
        &osv,
        selection,
        &modified_rows,
        cursor,
        label,
        bulk_init,
    )
    .await;
    let finish_result = if bulk_init {
        let finish_started = Instant::now();
        let result = db
            .finish_bulk_osv_import_storage_only()
            .await
            .map_err(|err| format!("{label}: failed to finish OSV bulk import: {err}"));
        Some((finish_started.elapsed(), result))
    } else {
        None
    };
    let summary = summary?;
    if let Some((elapsed, result)) = finish_result {
        result?;
        eprintln!(
            "{label}: finalized OSV bulk import in {}",
            format_elapsed(elapsed)
        );
    }
    db.set_metadata_value(
        OSV_IMPORT_ID_PREFIXES_METADATA_KEY,
        &selection.as_metadata_value(),
    )
    .await
    .map_err(|err| format!("{label}: failed to save OSV import selection: {err}"))?;
    eprintln!(
        "{label}: OSV selection sync completed records={} imported={} skipped={} in {}",
        summary.record_count,
        summary.imported,
        summary.skipped,
        format_elapsed(started.elapsed())
    );
    Ok(())
}

async fn import_osv_selection_zips_from_gcs(
    db: &CveDatabase,
    osv: &OsvGcsSource,
    selection: &OsvImportSelection,
    modified_rows: &[OsvModifiedId],
    cursor: Option<&str>,
    label: &str,
    bulk_init: bool,
) -> Result<qanvuli_db::ImportSummary, String> {
    if selection.all {
        let zip_path = download_osv_zip_to_temp(osv, OSV_ALL_ZIP, label).await?;
        let summary = import_osv_zip_file_in_batches(
            db,
            &zip_path,
            OsvZipImportOptions {
                target_paths: None,
                selection: Some(selection),
                seen_osv_ids: None,
                cursor,
                label,
                bulk_init,
            },
        )
        .await;
        let _ = std::fs::remove_file(&zip_path);
        return summary;
    }

    let mut total = qanvuli_db::ImportSummary {
        source: "OSV".to_owned(),
        imported: 0,
        skipped: 0,
        record_count: 0,
        content_hash: None,
    };
    let database_dirs = osv_database_dirs_for_selection(selection, modified_rows);
    if database_dirs.is_empty() {
        eprintln!(
            "{label}: OSV modified_id.csv did not contain importable JSON records for prefix(es): {}; skipping OSV zip download",
            selection
                .prefixes()
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(total);
    }
    eprintln!(
        "{label}: resolved OSV database zip(s): {}",
        database_dirs.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    let mut imported_osv_ids = HashSet::new();
    for (database_dir, prefixes) in database_dirs {
        let single_selection = OsvImportSelection {
            all: false,
            id_prefixes: prefixes,
        };
        let object_path = format!("{database_dir}/{OSV_ALL_ZIP}");
        let zip_path = download_osv_zip_to_temp(osv, &object_path, label).await?;
        let summary = import_osv_zip_file_in_batches(
            db,
            &zip_path,
            OsvZipImportOptions {
                target_paths: None,
                selection: Some(&single_selection),
                seen_osv_ids: Some(&mut imported_osv_ids),
                cursor,
                label,
                bulk_init,
            },
        )
        .await;
        let _ = std::fs::remove_file(&zip_path);
        let summary = summary?;
        total.imported += summary.imported;
        total.skipped += summary.skipped;
        total.record_count += summary.record_count;
    }
    Ok(total)
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

async fn sync_kev_epss_snapshots(db: &CveDatabase, label: &str) -> Result<(), String> {
    let kev_started = Instant::now();
    eprintln!("{label}: syncing CISA KEV snapshot");
    let kev = download_kev_json()
        .await
        .map_err(|err| format!("{label}: failed to download CISA KEV: {err}"))?;
    let kev_summary = db
        .import_kev_json(&kev)
        .await
        .map_err(|err| format!("{label}: failed to import CISA KEV: {err}"))?;
    eprintln!(
        "{label}: CISA KEV sync completed records={} imported={} skipped={} in {}",
        kev_summary.record_count,
        kev_summary.imported,
        kev_summary.skipped,
        format_elapsed(kev_started.elapsed())
    );

    let epss_started = Instant::now();
    eprintln!("{label}: syncing FIRST EPSS current snapshot");
    let epss = download_epss_current_csv()
        .await
        .map_err(|err| format!("{label}: failed to download FIRST EPSS: {err}"))?;
    let epss_summary = db
        .import_epss_csv(&epss)
        .await
        .map_err(|err| format!("{label}: failed to import FIRST EPSS: {err}"))?;
    eprintln!(
        "{label}: FIRST EPSS sync completed records={} imported={} skipped={} in {}",
        epss_summary.record_count,
        epss_summary.imported,
        epss_summary.skipped,
        format_elapsed(epss_started.elapsed())
    );
    Ok(())
}

pub(crate) struct OsvZipImportOptions<'a> {
    target_paths: Option<&'a HashSet<String>>,
    selection: Option<&'a OsvImportSelection>,
    seen_osv_ids: Option<&'a mut HashSet<String>>,
    cursor: Option<&'a str>,
    label: &'a str,
    bulk_init: bool,
}

pub(crate) async fn import_osv_zip_file_in_batches(
    db: &CveDatabase,
    path: &Path,
    options: OsvZipImportOptions<'_>,
) -> Result<qanvuli_db::ImportSummary, String> {
    let OsvZipImportOptions {
        target_paths,
        selection,
        seen_osv_ids,
        cursor,
        label,
        bulk_init,
    } = options;
    let started = Instant::now();
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let archive =
        zip::ZipArchive::new(file).map_err(|err| format!("failed to read OSV zip: {err}"))?;
    let reader_skip_osv_ids = seen_osv_ids.as_ref().map(|ids| (**ids).clone());
    let source_totals = osv_source_totals(
        &archive,
        target_paths,
        selection,
        reader_skip_osv_ids.as_ref(),
    );

    let (batch_tx, batch_rx) = mpsc::sync_channel(8);
    let reader_path = path.to_path_buf();
    let reader_target_paths = target_paths.cloned();
    let reader_selection = selection.cloned();
    let reader_skip_osv_ids = reader_skip_osv_ids.clone();
    let reader = std::thread::spawn(move || {
        read_osv_zip_batches(
            &reader_path,
            reader_target_paths.as_ref(),
            reader_selection.as_ref(),
            reader_skip_osv_ids.as_ref(),
            batch_tx,
        )
    });

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut seen = 0usize;
    let mut timings = IngestTimings::default();
    let mut chunk_index = 0usize;
    let mut import_error = None;
    while let Ok(batch) = batch_rx.recv() {
        let batch = match batch {
            Ok(batch) => batch,
            Err(err) => {
                import_error = Some(err);
                break;
            }
        };
        seen = batch.seen;
        let import_result = if bulk_init {
            db.import_osv_records_bulk_init_with_cursor_count_and_timings(
                batch.records,
                cursor,
                Some(batch.seen),
            )
            .await
        } else {
            db.import_osv_records_with_cursor_count_and_timings(
                batch.records,
                cursor,
                Some(batch.seen),
            )
            .await
        };
        let summary = match import_result {
            Ok(summary) => summary,
            Err(err) => {
                import_error = Some(format!("{label}: failed to import OSV batch: {err}"));
                break;
            }
        };
        let (summary, import_timings) = summary;
        let chunk_elapsed = batch.read_elapsed + import_timings.total;
        timings.read += batch.read_elapsed;
        timings.send_wait += batch.send_wait_elapsed;
        timings.hash += import_timings.hash;
        timings.parse += import_timings.parse;
        timings.hash_lookup += import_timings.hash_lookup;
        timings.db_write += import_timings.db_write;
        imported += summary.imported;
        skipped += summary.skipped;
        eprintln!(
            "{label}: OSV timings chunk={} read={:?}, send_wait={:?}, hash={:?}, parse={:?}, hash_lookup={:?}, db_write={:?}, total={:?}",
            chunk_index,
            batch.read_elapsed,
            batch.send_wait_elapsed,
            import_timings.hash,
            import_timings.parse,
            import_timings.hash_lookup,
            import_timings.db_write,
            chunk_elapsed
        );
        eprintln!(
            "{label}: OSV progress chunk={chunk_index}, batch={}, processed={}, db_sources={}, imported={}, skipped={}",
            batch.batch_count,
            batch.seen,
            source_progress_summary(&batch.source_seen, &source_totals),
            summary.imported,
            summary.skipped
        );
        chunk_index += 1;
    }
    drop(batch_rx);
    let reader_result = reader
        .join()
        .map_err(|_| format!("{label}: OSV zip reader thread panicked"))?;
    if let Some(err) = import_error {
        return Err(err);
    }
    let reader_result = reader_result?;
    if let Some(seen_osv_ids) = seen_osv_ids {
        seen_osv_ids.extend(reader_result.seen_osv_ids.iter().cloned());
    }
    let matched_prefixes = reader_result.matched_prefixes;
    if let Some(selection) = selection
        && !selection.all
    {
        let missing = selection
            .prefixes()
            .difference(&matched_prefixes)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "{label}: OSV all.zip did not contain JSON records for prefix(es): {}",
                missing.join(", ")
            ));
        }
    }
    eprintln!(
        "{label}: OSV import completed records={seen} imported={imported} skipped={skipped} elapsed={:?}, read={:?}, send_wait={:?}, hash={:?}, parse={:?}, hash_lookup={:?}, db_write={:?}",
        started.elapsed(),
        timings.read,
        timings.send_wait,
        timings.hash,
        timings.parse,
        timings.hash_lookup,
        timings.db_write
    );
    Ok(qanvuli_db::ImportSummary {
        source: "OSV".to_owned(),
        imported,
        skipped,
        record_count: seen,
        content_hash: None,
    })
}

fn read_osv_zip_batches(
    path: &Path,
    target_paths: Option<&HashSet<String>>,
    selection: Option<&OsvImportSelection>,
    skip_osv_ids: Option<&HashSet<String>>,
    batch_tx: mpsc::SyncSender<Result<OsvImportBatch, String>>,
) -> Result<OsvZipReadResult, String> {
    let file = std::fs::File::open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|err| format!("failed to read OSV zip: {err}"))?;
    let mut records = Vec::with_capacity(OSV_IMPORT_BATCH_SIZE);
    let mut seen = 0usize;
    let mut matched_prefixes = BTreeSet::new();
    let mut seen_osv_ids = HashSet::new();
    let mut source_seen = BTreeMap::new();
    let mut read_elapsed = Duration::default();

    for index in 0..archive.len() {
        let read_started = Instant::now();
        let mut entry = archive
            .by_index(index)
            .map_err(|err| format!("failed to read OSV zip entry {index}: {err}"))?;
        let name = entry.name().to_owned();
        if !name.ends_with(".json") {
            read_elapsed += read_started.elapsed();
            continue;
        }
        if let Some(target_paths) = target_paths
            && !target_paths.contains(&name)
        {
            read_elapsed += read_started.elapsed();
            continue;
        }
        let osv_id = osv_id_from_path(&name);
        if let Some(selection) = selection
            && !selection.matches_id(&osv_id)
        {
            read_elapsed += read_started.elapsed();
            continue;
        }
        if let Some(selection) = selection
            && !selection.all
        {
            for prefix in selection.prefixes() {
                if osv_id.starts_with(&format!("{prefix}-")) {
                    matched_prefixes.insert(prefix.clone());
                }
            }
        }
        if skip_osv_ids.is_some_and(|ids| ids.contains(&osv_id)) || seen_osv_ids.contains(&osv_id) {
            read_elapsed += read_started.elapsed();
            continue;
        }
        let source_prefix = osv_source_prefix(&osv_id);
        *source_seen.entry(source_prefix).or_insert(0usize) += 1;
        let mut raw_json = String::new();
        entry
            .read_to_string(&mut raw_json)
            .map_err(|err| format!("failed to read {name}: {err}"))?;
        read_elapsed += read_started.elapsed();
        records.push(OsvRawRecord {
            source_path: Some(format!("gs://osv-vulnerabilities/{name}")),
            raw_json,
        });
        seen_osv_ids.insert(osv_id);
        seen += 1;

        if records.len() >= OSV_IMPORT_BATCH_SIZE {
            send_osv_import_batch(
                &batch_tx,
                &mut records,
                seen,
                &source_seen,
                &mut read_elapsed,
            )?;
        }
    }

    if !records.is_empty() {
        send_osv_import_batch(
            &batch_tx,
            &mut records,
            seen,
            &source_seen,
            &mut read_elapsed,
        )?;
    }

    Ok(OsvZipReadResult {
        matched_prefixes,
        seen_osv_ids,
    })
}

fn send_osv_import_batch(
    batch_tx: &mpsc::SyncSender<Result<OsvImportBatch, String>>,
    records: &mut Vec<OsvRawRecord>,
    seen: usize,
    source_seen: &BTreeMap<String, usize>,
    read_elapsed: &mut Duration,
) -> Result<(), String> {
    let batch_records = std::mem::replace(records, Vec::with_capacity(OSV_IMPORT_BATCH_SIZE));
    let batch_count = batch_records.len();
    let batch = OsvImportBatch {
        records: batch_records,
        batch_count,
        seen,
        source_seen: source_seen.clone(),
        read_elapsed: *read_elapsed,
        send_wait_elapsed: Duration::default(),
    };
    *read_elapsed = Duration::default();
    send_osv_import_batch_with_wait(batch_tx, batch)
}

fn send_osv_import_batch_with_wait(
    batch_tx: &mpsc::SyncSender<Result<OsvImportBatch, String>>,
    mut batch: OsvImportBatch,
) -> Result<(), String> {
    let wait_started = Instant::now();
    loop {
        batch.send_wait_elapsed = wait_started.elapsed();
        match batch_tx.try_send(Ok(batch)) {
            Ok(()) => return Ok(()),
            Err(mpsc::TrySendError::Full(Ok(returned))) => {
                batch = returned;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err("OSV import pipeline stopped before zip reader completed".to_owned());
            }
            Err(mpsc::TrySendError::Full(Err(err))) => return Err(err),
        }
    }
}

fn osv_id_from_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_ascii_uppercase()
}

fn osv_source_totals(
    archive: &zip::ZipArchive<std::fs::File>,
    target_paths: Option<&HashSet<String>>,
    selection: Option<&OsvImportSelection>,
    skip_osv_ids: Option<&HashSet<String>>,
) -> BTreeMap<String, usize> {
    let mut totals = BTreeMap::new();
    let mut seen_osv_ids = HashSet::new();
    for name in archive.file_names() {
        if !name.ends_with(".json") {
            continue;
        }
        if let Some(target_paths) = target_paths
            && !target_paths.contains(name)
        {
            continue;
        }
        let osv_id = osv_id_from_path(name);
        if let Some(selection) = selection
            && !selection.matches_id(&osv_id)
        {
            continue;
        }
        if skip_osv_ids.is_some_and(|ids| ids.contains(&osv_id)) || seen_osv_ids.contains(&osv_id) {
            continue;
        }
        seen_osv_ids.insert(osv_id.clone());
        *totals.entry(osv_source_prefix(&osv_id)).or_insert(0usize) += 1;
    }
    totals
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

fn source_progress_summary(
    source_seen: &BTreeMap<String, usize>,
    source_totals: &BTreeMap<String, usize>,
) -> String {
    if source_seen.is_empty() {
        return "-".to_owned();
    }
    source_seen
        .iter()
        .map(|(source, seen)| {
            source_totals
                .get(source)
                .map(|total| format!("{source}:{seen}/{total}"))
                .unwrap_or_else(|| format!("{source}:{seen}"))
        })
        .collect::<Vec<_>>()
        .join(",")
}

async fn download_osv_all_zip_to_temp(osv: &OsvGcsSource, label: &str) -> Result<PathBuf, String> {
    download_osv_zip_to_temp(osv, OSV_ALL_ZIP, label).await
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
    let catalog_path = temporary_zip_file_path(&catalog_file.name, None).map_err(|err| {
        format!(
            "failed to prepare temporary download path for {}: {err}",
            catalog_file.name
        )
    })?;
    let download = match catalog_file
        .async_download_if_changed_as(&catalog_path, etag.as_deref(), last_modified.as_deref())
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
    let _ = std::fs::remove_file(&path);
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
            IngestOptions {
                max_chunks,
                cwe_synced: true,
                keep_artifacts: keep_downloads,
                progress,
            },
        )
        .await?;
        if !keep_downloads {
            remove_processed_zip(&zip)?;
        }
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
                return apply_local_delta_updates(
                    db,
                    vec![path],
                    max_chunks,
                    keep_downloads,
                    progress,
                )
                .await;
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
            return apply_local_delta_updates(db, vec![path], max_chunks, keep_downloads, progress)
                .await;
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
        let asset_path = temporary_zip_file_path(&filename, Some(asset.size)).map_err(|err| {
            format!("failed to prepare temporary download path for {filename}: {err}")
        })?;
        asset
            .async_download_as(&asset_path)
            .await
            .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
        ingest_zip_with_progress(
            db,
            "delta",
            &asset_path,
            IngestMode::Upsert,
            IngestOptions {
                max_chunks,
                cwe_synced: true,
                keep_artifacts: keep_downloads,
                progress: progress.clone(),
            },
        )
        .await?;
        if max_chunks.is_none() {
            db.mark_cve_asset_applied(&asset.name, &asset.url)
                .await
                .map_err(|err| format!("failed to mark CVE asset applied: {err}"))?;
        }
        if !keep_downloads {
            remove_processed_zip(&asset_path)?;
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
        IngestOptions {
            max_chunks,
            cwe_synced: true,
            keep_artifacts: keep_downloads,
            progress,
        },
    )
    .await?;
    if !keep_downloads {
        remove_processed_zip(&path)?;
    }
    Ok(vec![path])
}

async fn apply_local_delta_updates(
    db: &CveDatabase,
    assets: Vec<PathBuf>,
    max_chunks: Option<usize>,
    keep_downloads: bool,
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
            IngestOptions {
                max_chunks,
                cwe_synced: true,
                keep_artifacts: keep_downloads,
                progress: progress.clone(),
            },
        )
        .await?;
        if max_chunks.is_none() && !asset_name.is_empty() {
            db.mark_cve_asset_applied(&asset_name, "local")
                .await
                .map_err(|err| format!("failed to mark CVE asset applied: {err}"))?;
        }
        if !keep_downloads {
            remove_processed_zip(&asset_path)?;
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
    for (index, (_, candidate)) in candidates.iter().enumerate() {
        if candidate.zip_type == CVE_ZIP_TYPE_DELTA_END_OF_DAY {
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

pub struct IngestOptions {
    pub max_chunks: Option<usize>,
    pub cwe_synced: bool,
    pub keep_artifacts: bool,
    pub progress: Option<IngestProgressCallback>,
}

pub async fn ingest_zip(
    db: &CveDatabase,
    label: &str,
    asset_path: &Path,
    mode: IngestMode,
    max_chunks: Option<usize>,
    cwe_synced: bool,
    keep_artifacts: bool,
) -> Result<(), String> {
    ingest_zip_with_progress(
        db,
        label,
        asset_path,
        mode,
        IngestOptions {
            max_chunks,
            cwe_synced,
            keep_artifacts,
            progress: None,
        },
    )
    .await
}

pub async fn ingest_zip_with_progress(
    db: &CveDatabase,
    label: &str,
    asset_path: &Path,
    mode: IngestMode,
    options: IngestOptions,
) -> Result<(), String> {
    let IngestOptions {
        max_chunks,
        cwe_synced,
        keep_artifacts,
        progress,
    } = options;
    let total_start = Instant::now();
    eprintln!("{label}: opening zip {}", asset_path.display());
    let mut storage = loader::ZipStorage::new(asset_path.to_string_lossy().to_string())
        .map_err(|err| format!("{label}: failed to open {}: {err}", asset_path.display()))?;
    // Preserve nested archive extraction until the database write has completed.
    storage.retain_extracted_dir();
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
        db.rebuild_schema()
            .await
            .map_err(|err| format!("{label}: failed to rebuild schema: {err}"))?;
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
        sync_cwe_catalog(db)
            .await
            .map_err(|err| format!("{label}: {err}"))?;
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
            .map_err(|err| format!("{label}: failed to begin bulk load: {err}"))?;
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
                read_and_parse_extracted_chunk(label, chunk, &mut read_failed)?
            } else {
                read_and_parse_zip_chunk(label, chunk, &mut storage, &mut read_failed)?
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
                    .ok_or_else(|| {
                        format!("{label}: bulk replace session is missing in replace-all mode")
                    })?
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
                let mark_result =
                    match mode {
                        IngestMode::ReplaceAll => bulk_replace
                            .as_ref()
                            .ok_or_else(|| {
                                format!(
                                    "{label}: bulk replace session is missing in replace-all mode"
                                )
                            })?
                            .mark_json_files_read(read_files)
                            .await,
                        IngestMode::Upsert => db.mark_json_files_read(read_files).await,
                    };
                if let Err(err) = mark_result {
                    return Err(format!(
                        "{label}: failed to mark read json files in chunk {chunk_index}: {err}"
                    ));
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
                let failed_total = failed + chunk.len();
                return Err(format!(
                    "{label}: failed to write chunk {chunk_index}: {err}; inserted={inserted}, failed={failed_total}"
                ));
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
        if failed > 0 {
            return Err(format!(
                "{label}: refusing to finalize partial replace-all import; inserted={inserted}, failed={failed}"
            ));
        }
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
        let session = bulk_replace.take().ok_or_else(|| {
            format!("{label}: bulk replace session is missing in replace-all mode")
        })?;
        session
            .finish_storage_with_text_search(db)
            .await
            .map_err(|err| format!("{label}: failed to finish bulk load: {err}"))?;
        eprintln!(
            "{label}: finalized storage and text search in {:?}",
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
    if failed > 0 {
        return Err(format!(
            "{label}: completed with failed CVE files; inserted={inserted}, failed={failed}"
        ));
    }
    if !keep_artifacts && let Err(err) = storage.cleanup_extracted_dir() {
        eprintln!("{label}: failed to clean extracted archive: {err}");
    }
    Ok(())
}

fn parse_json_batch(label: &str, batch: Vec<(String, Vec<u8>)>) -> Vec<ParsedCveFile> {
    batch
        .into_iter()
        .map(|(json_path, json)| parse_json(label, json_path, json))
        .collect()
}

#[allow(clippy::type_complexity)]
fn read_and_parse_extracted_chunk(
    label: &str,
    chunk: &[JsonEntry],
    read_failed: &mut usize,
) -> Result<(Vec<ParsedCveFile>, Duration, Duration), String> {
    let total_start = Instant::now();
    let results = chunk
        .par_iter()
        .map(|entry| {
            let Some(filesystem_path) = entry.filesystem_path.as_ref() else {
                return Err(format!(
                    "{label}: extracted entry {} has no filesystem path",
                    entry.path
                ));
            };
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

    Ok((parsed, elapsed, Duration::ZERO))
}

#[allow(clippy::type_complexity)]
fn read_and_parse_zip_chunk(
    label: &str,
    chunk: &[JsonEntry],
    storage: &mut loader::ZipStorage,
    read_failed: &mut usize,
) -> Result<(Vec<ParsedCveFile>, Duration, Duration), String> {
    let read_start = Instant::now();
    let parsed_batches = std::sync::Mutex::new(Vec::<Vec<ParsedCveFile>>::new());
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
                    push_parsed_batch(label, parsed_batches, parsed);
                });
            }
        }

        if !batch.is_empty() {
            let parsed_batches = &parsed_batches;
            scope.spawn(move |_| {
                let parsed = parse_json_batch(label, batch);
                push_parsed_batch(label, parsed_batches, parsed);
            });
        }

        read_elapsed = read_start.elapsed();
    });
    let parse_elapsed = read_start.elapsed().saturating_sub(read_elapsed);
    let parsed = parsed_batches
        .into_inner()
        .map_err(|_| format!("{label}: parsed batch mutex poisoned"))?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    Ok((parsed, read_elapsed, parse_elapsed))
}

fn push_parsed_batch(
    label: &str,
    parsed_batches: &std::sync::Mutex<Vec<Vec<ParsedCveFile>>>,
    parsed: Vec<ParsedCveFile>,
) {
    match parsed_batches.lock() {
        Ok(mut batches) => batches.push(parsed),
        Err(poisoned) => {
            let mut batches = poisoned.into_inner();
            batches.push(vec![Err(format!("{label}: parsed batch mutex poisoned"))]);
        }
    }
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
    send_wait: Duration,
    hash: Duration,
    parse: Duration,
    hash_lookup: Duration,
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
        let skip_osv_ids = HashSet::from(["GHSA-SKIP".to_owned()]);
        let (batch_tx, batch_rx) = mpsc::sync_channel(8);
        let result = read_osv_zip_batches(
            &zip_path,
            None,
            Some(&selection),
            Some(&skip_osv_ids),
            batch_tx,
        )
        .unwrap();
        let batches = batch_rx.into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(result.seen_osv_ids, HashSet::from(["GHSA-KEEP".to_owned()]));
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
    async fn replace_all_ingest_initializes_from_local_archives() {
        use std::io::Write;

        let db_path = std::env::temp_dir().join(format!(
            "qanvuli-init-ingest-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let zip_path = std::env::temp_dir().join(format!(
            "qanvuli-init-ingest-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("cves/2024/CVE-2024-0001.json", options)
            .unwrap();
        zip.write_all(
            br#"{
                "dataType":"CVE_RECORD",
                "dataVersion":"5.1.0",
                "cveMetadata":{
                    "cveId":"CVE-2024-0001",
                    "assignerOrgId":"00000000-0000-4000-8000-000000000000",
                    "state":"PUBLISHED",
                    "serial":1,
                    "datePublished":"2024-01-01T00:00:00Z",
                    "dateUpdated":"2024-01-02T00:00:00Z"
                },
                "containers":{
                    "cna":{
                        "providerMetadata":{"orgId":"00000000-0000-4000-8000-000000000000"},
                        "title":"Example CVE",
                        "descriptions":[{"lang":"en","value":"Example vulnerability."}],
                        "affected":[{"vendor":"Example Vendor","product":"Example Product","defaultStatus":"affected"}],
                        "metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
                        "problemTypes":[{"descriptions":[{"lang":"en","type":"CWE","cweId":"CWE-79","description":"Cross-site Scripting"}]}],
                        "references":[{"url":"https://example.com/advisory"}]
                    }
                }
            }"#,
        )
        .unwrap();
        zip.finish().unwrap();

        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        reset_sqlite_database_files(&db_url).unwrap();

        let db = connect_db(&db_url).await.unwrap();
        ingest_zip_with_progress(
            &db,
            "test-init",
            &zip_path,
            IngestMode::ReplaceAll,
            IngestOptions {
                max_chunks: Some(1),
                cwe_synced: false,
                keep_artifacts: false,
                progress: None,
            },
        )
        .await
        .unwrap();

        let status = db.database_status().await.unwrap();
        assert!(status.cve_count > 0);
        assert!(status.cwe_count > 0);
        db.close().await.unwrap();

        reset_sqlite_database_files(&db_url).unwrap();
        let _ = std::fs::remove_file(zip_path);
    }

    #[tokio::test]
    async fn ingest_zip_reports_missing_archive_without_panicking() {
        let db = connect_db("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        let missing_zip = std::env::temp_dir().join(format!(
            "qanvuli-missing-ingest-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let err = ingest_zip_with_progress(
            &db,
            "test-missing",
            &missing_zip,
            IngestMode::Upsert,
            IngestOptions {
                max_chunks: Some(1),
                cwe_synced: true,
                keep_artifacts: false,
                progress: None,
            },
        )
        .await
        .unwrap_err();

        assert!(err.contains("test-missing: failed to open"));
        assert!(err.contains("failed to open zip archive"));
        db.close().await.unwrap();
    }
}
