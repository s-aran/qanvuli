use ahash::AHashSet;
use chrono::{DateTime, FixedOffset, NaiveDate, TimeDelta, Utc};
use clap::ValueEnum;
use qanvuli_core::ingest::OsvModifiedId;
use qanvuli_core::model::OSV_DATABASE_SOURCE_PREFIXES;
use qanvuli_core::{
    database::{OsvRawRecord, SqlxDatabase},
    ingest::{
        CveRelease, GitHubReleaseFile, JsonStorage, OSV_ALL_ZIP, OsvDownloadError, OsvGcsSource,
        ZipStorage, download_epss_current_csv, download_kev_json, parse_modified_id_csv,
    },
    model::is_known_osv_database_prefix,
};
use qanvuli_utils::github::DownloadProgressCallback;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

mod catalog;
pub mod database;

pub use catalog::{download_latest_cwe_catalog, sync_capec_catalog, sync_cwe_catalog};
pub use database::{
    close_database, connect_database, default_db_connection_string, print_json, redact_database_url,
};

/// Default row limit used by CLI search commands.
pub const DEFAULT_LIMIT: u64 = 25;

/// Help text for dynamic OSV source prefix flags such as `--osv-ghsa`.
pub const OSV_SOURCE_PREFIX_HELP: &str = r#"OSV source DB prefix flags:
  Select sources with repeatable --osv-{prefix} flags. Prefixes are case-insensitive.

  --osv-alba --osv-alea --osv-alpine --osv-alsa --osv-asb-a --osv-bell --osv-bit
  --osv-cga --osv-cleanstart --osv-curl --osv-cve --osv-debian --osv-dhi --osv-dla
  --osv-drupal --osv-dsa --osv-dtsa --osv-echo --osv-eef --osv-ela --osv-ghsa
  --osv-go --osv-gsd --osv-hsec --osv-jlsec --osv-kube --osv-lbsec --osv-lsn
  --osv-mal --osv-mgasa --osv-mini --osv-oesa --osv-opensuse-su --osv-osec
  --osv-osv --osv-phsa --osv-psf --osv-pub-a --osv-pysec --osv-rhba --osv-rhea
  --osv-rhsa --osv-rlsa --osv-root --osv-rsec --osv-rustsec --osv-rxsa
  --osv-suse-fu --osv-suse-ou --osv-suse-ru --osv-suse-su --osv-ubuntu --osv-usn --osv-v8
"#;

const INGEST_CHUNK_SIZE: usize = 20_000;
const OSV_IMPORT_BATCH_SIZE: usize = 6_000;
const OSV_IMPORT_PIPELINE_CAPACITY: usize = 1;
const OSV_IMPORT_HEARTBEAT: Duration = Duration::from_secs(10);
pub(crate) const OSV_IMPORT_ID_PREFIXES_METADATA_KEY: &str = "osv_import_id_prefixes";
pub(crate) const CVE_DELTA_CURSOR_METADATA_KEY: &str = "cve_delta_cursor";
const CVE_DAILY_UPDATE_AFTER: TimeDelta = TimeDelta::hours(24);
const CVE_FULL_UPDATE_AFTER: TimeDelta = TimeDelta::days(14);

pub(crate) fn cve_full_asset_cursor(path: &Path) -> Option<DateTime<Utc>> {
    let filename = path.file_name()?.to_str()?;
    if !filename.contains("_all_") {
        return None;
    }
    NaiveDate::parse_from_str(filename.get(..10)?, "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)
        .map(|value| value.and_utc())
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OsvImportMode {
    InitialReplacement,
    IncrementalUpdate,
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

fn timestamp_is_after(candidate: &str, cursor: &str) -> bool {
    match (
        DateTime::parse_from_rfc3339(candidate),
        DateTime::parse_from_rfc3339(cursor),
    ) {
        (Ok(candidate), Ok(cursor)) => candidate > cursor,
        _ => candidate > cursor,
    }
}

fn osv_target_paths_since(
    selection: &OsvImportSelection,
    modified_rows: &[OsvModifiedId],
    cursor: &str,
) -> AHashSet<String> {
    modified_rows
        .iter()
        .filter(|row| {
            selection.matches_id(&osv_id_from_path(&row.object_path))
                && timestamp_is_after(&row.modified_at, cursor)
        })
        .map(|row| row.object_path.clone())
        .collect()
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

/// Synchronizes enrichment feeds that are distributed separately from CVE records.
pub async fn sync_risk_feeds(
    db: SqlxDatabase,
    label: &str,
    cve_changed: bool,
) -> Result<bool, String> {
    let label = label.to_owned();
    let kev = download_kev_json()
        .await
        .map_err(|error| format!("{label}: failed to download CISA KEV: {error}"))?;
    let (_, kev_changed) = db
        .import_kev_json_with_status(kev, cve_changed)
        .await
        .map_err(|error| format!("{label}: failed to import CISA KEV: {error}"))?;
    let epss = download_epss_current_csv()
        .await
        .map_err(|error| format!("{label}: failed to download FIRST EPSS: {error}"))?;
    let (_, epss_changed) = db
        .import_epss_csv_with_status(epss, cve_changed)
        .await
        .map_err(|error| format!("{label}: failed to import FIRST EPSS: {error}"))?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("{label}: enrichment database check failed: {error}"))?;
    if !kev_changed {
        eprintln!("{label}: CISA KEV unchanged; database write skipped");
    }
    if !epss_changed {
        eprintln!("{label}: FIRST EPSS unchanged; database write skipped");
    }
    Ok(kev_changed || epss_changed)
}

pub(crate) struct DownloadedOsvSelection {
    label: String,
    selection: OsvImportSelection,
    cursor: String,
    target_osv_ids: Option<AHashSet<String>>,
    zip_paths: Vec<PathBuf>,
    download_elapsed: Duration,
    ready_at: Instant,
}

impl Drop for DownloadedOsvSelection {
    fn drop(&mut self) {
        for path in &self.zip_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Downloads the selected public OSV snapshot without touching SQLite.
pub(crate) async fn download_osv_selection_from_gcs(
    label: &str,
    selection: OsvImportSelection,
    previous_cursor: Option<&str>,
) -> Result<DownloadedOsvSelection, String> {
    let label = label.to_owned();
    let started = Instant::now();
    eprintln!(
        "{label}: prefetching OSV records from Google Cloud Storage ({})",
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
        .iter()
        .filter_map(|row| DateTime::parse_from_rfc3339(&row.modified_at).ok())
        .max()
        .map(|value| value.to_rfc3339())
        .or_else(|| previous_cursor.map(str::to_owned))
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let target_paths =
        previous_cursor.map(|cursor| osv_target_paths_since(&selection, &modified_rows, cursor));
    let selected_modified_rows = target_paths.as_ref().map_or_else(
        || modified_rows.clone(),
        |paths| {
            modified_rows
                .iter()
                .filter(|row| paths.contains(&row.object_path))
                .cloned()
                .collect()
        },
    );
    let target_osv_ids = target_paths.as_ref().map(|paths| {
        paths
            .iter()
            .map(|path| osv_id_from_path(path))
            .collect::<AHashSet<_>>()
    });
    let object_paths = if selection.all {
        if target_paths.as_ref().is_some_and(|paths| paths.is_empty()) {
            Vec::new()
        } else {
            vec![OSV_ALL_ZIP.to_owned()]
        }
    } else {
        let database_dirs = osv_database_dirs_for_selection(&selection, &selected_modified_rows);
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
    let mut prefer_fallback_temp = false;
    for object_path in &object_paths {
        let download_started = Instant::now();
        eprintln!("{label}: downloading OSV {object_path}");
        match download_osv_zip_to_temp(&source, object_path, &label, &mut prefer_fallback_temp)
            .await
        {
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
    let download_elapsed = started.elapsed();
    Ok(DownloadedOsvSelection {
        label,
        selection,
        cursor,
        target_osv_ids,
        zip_paths,
        download_elapsed,
        ready_at: Instant::now(),
    })
}

/// Imports a previously downloaded OSV selection and removes its temporary ZIPs on return.
pub(crate) async fn import_downloaded_osv_selection(
    db: SqlxDatabase,
    download: DownloadedOsvSelection,
    mode: OsvImportMode,
) -> Result<usize, String> {
    let queued_elapsed = download.ready_at.elapsed();
    let import_started = Instant::now();
    eprintln!(
        "{}: starting OSV database import ({} ZIPs; queued for {queued_elapsed:?})",
        download.label,
        download.zip_paths.len()
    );
    let result = import_osv_zips(
        db.clone(),
        &download.zip_paths,
        Some(&download.selection),
        download.target_osv_ids.as_ref(),
        &download.cursor,
        mode,
    )
    .await;
    let imported = result?;
    db.set_metadata_value(
        OSV_IMPORT_ID_PREFIXES_METADATA_KEY,
        &download.selection.as_metadata_value(),
    )
    .await
    .map_err(|error| format!("{}: failed to save OSV selection: {error}", download.label))?;
    eprintln!(
        "{}: imported {imported} OSV records; download={:?}, queued while other init work ran={queued_elapsed:?}, database import={:?}",
        download.label,
        download.download_elapsed,
        import_started.elapsed()
    );
    Ok(imported)
}

/// Downloads the selected public OSV snapshot and imports it through the SQLx writer.
pub async fn sync_osv(
    db: SqlxDatabase,
    label: &str,
    selection: OsvImportSelection,
) -> Result<usize, String> {
    sync_osv_with_refresh(db, label, selection, false).await
}

/// Synchronizes OSV data, optionally ignoring the cursor and redownloading every selected ZIP.
///
/// `refresh_all` upserts snapshots; absence does not delete a local advisory.
pub async fn sync_osv_with_refresh(
    db: SqlxDatabase,
    label: &str,
    selection: OsvImportSelection,
    refresh_all: bool,
) -> Result<usize, String> {
    let previous_cursor = db
        .osv_sync_cursor()
        .await
        .map_err(|error| format!("{label}: failed to read OSV cursor: {error}"))?;
    let stored_selection = db
        .metadata_value(OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
        .await
        .map_err(|error| format!("{label}: failed to read OSV selection: {error}"))?;
    let selection_expanded = OsvImportSelection::from_metadata(stored_selection.as_deref())
        .is_none_or(|stored| stored != selection);
    let incremental_cursor = (!selection_expanded && !refresh_all)
        .then_some(previous_cursor.as_deref())
        .flatten();
    let download = download_osv_selection_from_gcs(label, selection, incremental_cursor).await?;
    import_downloaded_osv_selection(db, download, OsvImportMode::IncrementalUpdate).await
}

/// Imports an OSV ZIP through the SQLx writer and advances the cursor only after every batch,
/// FTS rebuild, and schema validation has succeeded.
pub async fn import_osv_zip(
    db: SqlxDatabase,
    path: &Path,
    selection: Option<&OsvImportSelection>,
    completion_cursor: &str,
) -> Result<usize, String> {
    let paths = [path.to_path_buf()];
    import_osv_zips(
        db,
        &paths,
        selection,
        None,
        completion_cursor,
        OsvImportMode::IncrementalUpdate,
    )
    .await
}

async fn import_osv_zips(
    db: SqlxDatabase,
    paths: &[PathBuf],
    selection: Option<&OsvImportSelection>,
    target_osv_ids: Option<&AHashSet<String>>,
    completion_cursor: &str,
    mode: OsvImportMode,
) -> Result<usize, String> {
    let initial_replacement = mode == OsvImportMode::InitialReplacement;
    db.begin_osv_sync()
        .await
        .map_err(|error| format!("failed to begin OSV sync: {error}"))?;
    if initial_replacement {
        db.prepare_osv_bulk_load()
            .await
            .map_err(|error| format!("failed to prepare OSV bulk load: {error}"))?;
    }

    let mut totals = OsvImportTotals::default();
    let mut seen_osv_ids = AHashSet::new();
    for (path_index, path) in paths.iter().enumerate() {
        eprintln!(
            "osv: reading ZIP [{}/{}] {}",
            path_index + 1,
            paths.len(),
            path.display()
        );
        let read_osv_ids = import_osv_path(
            &db,
            path,
            selection,
            target_osv_ids,
            &seen_osv_ids,
            initial_replacement,
            &mut totals,
        )
        .await;
        match read_osv_ids {
            Ok(ids) => seen_osv_ids.extend(ids),
            Err(error) => return fail_osv_import(&db, initial_replacement, error).await,
        }
    }

    if let Err(error) =
        finish_osv_import(&db, completion_cursor, initial_replacement, &totals).await
    {
        return fail_osv_import(&db, initial_replacement, error).await;
    }
    Ok(totals.examined)
}

#[derive(Default)]
struct OsvImportTotals {
    examined: usize,
    changed: usize,
    inserted: usize,
    updated: usize,
    unchanged: usize,
}

impl OsvImportTotals {
    fn record(
        &mut self,
        stats: &qanvuli_core::database::OsvImportStats,
        elapsed: Duration,
        initial_replacement: bool,
    ) {
        self.examined += stats.examined;
        self.changed += stats.changed();
        self.inserted += stats.inserted;
        self.updated += stats.updated;
        self.unchanged += stats.unchanged;
        let records_per_second = stats.examined as f64 / elapsed.as_secs_f64();
        let mode = if initial_replacement {
            "full-init"
        } else {
            "incremental"
        };
        eprintln!(
            "osv: mode={mode}, examined={}, inserted={}, updated={}, unchanged={} (batch={} in {:?}, {:.0} records/s)",
            self.examined,
            self.inserted,
            self.updated,
            self.unchanged,
            stats.examined,
            elapsed,
            records_per_second,
        );
    }
}

async fn import_osv_path(
    db: &SqlxDatabase,
    path: &Path,
    selection: Option<&OsvImportSelection>,
    target_osv_ids: Option<&AHashSet<String>>,
    seen_osv_ids: &AHashSet<String>,
    initial_replacement: bool,
    totals: &mut OsvImportTotals,
) -> Result<AHashSet<String>, String> {
    // One queued batch overlaps ZIP reading with SQLite writes without retaining several
    // batches of raw and parsed advisory JSON at once.
    let (sender, mut receiver) = mpsc::channel(OSV_IMPORT_PIPELINE_CAPACITY);
    let path = path.to_path_buf();
    let selection = selection.cloned();
    let target_osv_ids = target_osv_ids.cloned();
    let skip_osv_ids = seen_osv_ids.clone();
    let reader = tokio::task::spawn_blocking(move || {
        read_osv_zip_batches(
            &path,
            target_osv_ids.as_ref(),
            selection.as_ref(),
            Some(&skip_osv_ids),
            sender,
        )
    });

    let mut import_error = None;
    while let Some(batch) = receiver.recv().await {
        let batch = match batch {
            Ok(batch) => batch,
            Err(error) => {
                import_error = Some(error);
                break;
            }
        };
        match import_osv_batch(db, batch, initial_replacement).await {
            Ok((stats, elapsed)) => totals.record(&stats, elapsed, initial_replacement),
            Err(error) => {
                import_error = Some(error);
                break;
            }
        }
    }

    // Dropping the receiver first unblocks a reader waiting on bounded backpressure.
    drop(receiver);
    let reader_result = reader
        .await
        .map_err(|_| "OSV zip reader task panicked".to_owned());
    if let Some(error) = import_error {
        return Err(error);
    }
    reader_result?
}

async fn import_osv_batch(
    db: &SqlxDatabase,
    batch: OsvImportBatch,
    initial_replacement: bool,
) -> Result<(qanvuli_core::database::OsvImportStats, Duration), String> {
    let started = Instant::now();
    let batch_size = batch.records.len();
    let import_future = async {
        if initial_replacement {
            db.import_osv_records_bulk_init(batch.records)
                .await
                .map(|examined| qanvuli_core::database::OsvImportStats {
                    examined,
                    inserted: examined,
                    updated: 0,
                    unchanged: 0,
                })
        } else {
            db.import_osv_records_incremental_with_stats(batch.records)
                .await
        }
    };
    tokio::pin!(import_future);
    let mut heartbeat = tokio::time::interval(OSV_IMPORT_HEARTBEAT);
    heartbeat.tick().await;
    let stats = loop {
        tokio::select! {
            result = &mut import_future => break result,
            _ = heartbeat.tick() => {
                eprintln!(
                    "osv: importing batch of {batch_size} records; elapsed {:?}...",
                    started.elapsed()
                );
            }
        }
    }
    .map_err(|error| format!("failed to import OSV batch: {error}"))?;
    Ok((stats, started.elapsed()))
}

async fn finish_osv_import(
    db: &SqlxDatabase,
    completion_cursor: &str,
    initial_replacement: bool,
    totals: &OsvImportTotals,
) -> Result<(), String> {
    eprintln!("osv: rebuilding deferred indexes and search data");
    let index_started = Instant::now();
    if initial_replacement {
        db.finish_osv_bulk_load()
            .await
            .map_err(|error| format!("failed to finish OSV bulk load: {error}"))?;
    } else if totals.changed > 0 {
        eprintln!(
            "osv: incrementally updated search rows for {} changed record(s)",
            totals.changed
        );
    } else {
        eprintln!(
            "osv: all {} examined records were unchanged; search writes skipped",
            totals.unchanged
        );
    }
    eprintln!(
        "osv: index/search maintenance completed in {:?}",
        index_started.elapsed()
    );
    ensure_osv_search_integrity(db).await?;
    db.complete_osv_sync(completion_cursor)
        .await
        .map_err(|error| format!("failed to advance OSV cursor: {error}"))
}

async fn ensure_osv_search_integrity(db: &SqlxDatabase) -> Result<(), String> {
    let Err(error) = db.check_search_integrity_quick().await else {
        return Ok(());
    };
    // Older incremental imports assigned a fresh FTS rowid on every OSV update. Rebuild once to
    // repair that stale projection; current writes preserve the advisory rowid.
    if !error.to_string().contains("OSV text FTS") {
        return Err(format!("failed OSV database check: {error}"));
    }
    eprintln!("osv: repairing stale OSV search projection");
    db.rebuild_osv_search()
        .await
        .map_err(|error| format!("failed to repair OSV search projection: {error}"))?;
    db.check_search_integrity_quick()
        .await
        .map_err(|error| format!("failed OSV database check after repair: {error}"))
}

async fn fail_osv_import<T>(
    db: &SqlxDatabase,
    initial_replacement: bool,
    error: String,
) -> Result<T, String> {
    if initial_replacement {
        let _ = db.finish_osv_bulk_load().await;
    }
    let _ = db.fail_osv_sync(&error).await;
    Err(error)
}

fn read_osv_zip_batches(
    path: &Path,
    target_osv_ids: Option<&AHashSet<String>>,
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
        let osv_id = osv_id_from_path(&name);
        if let Some(target_osv_ids) = target_osv_ids
            && !target_osv_ids.contains(&osv_id)
        {
            continue;
        }
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
    prefer_fallback_temp: &mut bool,
) -> Result<PathBuf, String> {
    let object_filename = object_path.replace('/', "-");
    let filename = format!(
        "qanvuli-osv-{object_filename}-{}-{}.zip",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    if *prefer_fallback_temp {
        let fallback = temporary_zip_file_path_in(binary_temporary_directory(), &filename)
            .map_err(|err| format!("{label}: failed to prepare temporary OSV zip path: {err}"))?;
        download_osv_zip_object(osv, object_path, &fallback)
            .await
            .map_err(|err| {
                format!(
                    "{label}: failed to download OSV {object_path} to fallback {}: {err}",
                    fallback.display()
                )
            })?;
        return Ok(fallback);
    }

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
            if err.is_local_storage() {
                *prefer_fallback_temp = true;
                eprintln!(
                    "{label}: disabling primary temporary storage for remaining OSV downloads"
                );
            }
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
) -> Result<(), OsvDownloadError> {
    if object_path == OSV_ALL_ZIP {
        osv.download_all_zip_to_file(output).await
    } else {
        let Some((source_prefix, filename)) = object_path.split_once('/') else {
            return osv.download_all_zip_to_file(output).await;
        };
        if filename == OSV_ALL_ZIP {
            osv.download_source_zip_to_file(source_prefix, output).await
        } else {
            osv.download_all_zip_to_file(output).await
        }
    }
}

// Keep enough headroom for concurrent range writes, filesystem accounting, and unrelated small
// temporary files. Checking only the advertised payload size can select an almost-full /tmp and
// fail partway through a sparse preallocated download.
const ZIP_DOWNLOAD_FREE_SPACE_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

fn zip_download_required_bytes(payload_bytes: u64) -> u64 {
    payload_bytes.saturating_add(ZIP_DOWNLOAD_FREE_SPACE_MARGIN_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TemporaryStorageChoice {
    Primary,
    Fallback,
}

fn choose_temporary_storage(
    required: Option<u64>,
    primary_available: Option<u64>,
    fallback_available: Option<u64>,
) -> Result<TemporaryStorageChoice, (u64, u64, u64)> {
    let Some(required) = required else {
        return Ok(TemporaryStorageChoice::Primary);
    };
    let Some(primary_available) = primary_available else {
        return Ok(TemporaryStorageChoice::Primary);
    };
    if primary_available >= required {
        return Ok(TemporaryStorageChoice::Primary);
    }
    if let Some(fallback_available) = fallback_available
        && fallback_available < required
    {
        return Err((required, primary_available, fallback_available));
    }
    Ok(TemporaryStorageChoice::Fallback)
}

fn temporary_zip_file_path(filename: &str, payload_bytes: Option<u64>) -> Result<PathBuf, String> {
    let system_temp_root = std::env::temp_dir();
    let temp_root = system_temp_root.join("qanvuli");
    let fallback = binary_temporary_directory();
    let required = payload_bytes.map(zip_download_required_bytes);
    match choose_temporary_storage(
        required,
        available_storage_bytes(&system_temp_root),
        available_storage_bytes(&fallback),
    ) {
        Ok(TemporaryStorageChoice::Fallback) => {
            eprintln!(
                "temporary storage {} has insufficient capacity for a download requiring {} bytes including safety margin; using {}",
                system_temp_root.display(),
                required.unwrap_or_default(),
                fallback.display()
            );
            return temporary_zip_file_path_in(fallback, filename);
        }
        Err((required, primary_available, fallback_available)) => {
            return Err(format!(
                "temporary storage capacity is insufficient: {} has {} bytes and fallback {} has {} bytes, but the download needs at least {} bytes including safety margin",
                system_temp_root.display(),
                primary_available,
                fallback.display(),
                fallback_available,
                required
            ));
        }
        Ok(TemporaryStorageChoice::Primary) => {}
    }
    temporary_zip_file_path_in(temp_root, filename)
        .or_else(|_| temporary_zip_file_path_in(fallback, filename))
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
    pub published_at: Option<DateTime<Utc>>,
}

pub async fn download_latest_asset_with_source(
    kind: ReleaseAssetKind,
) -> Result<DownloadedAsset, String> {
    download_latest_asset_with_source_with_progress(kind, None, kind.to_string()).await
}

/// Downloads the latest release asset and reports byte progress when requested.
pub async fn download_latest_asset_with_source_with_progress(
    kind: ReleaseAssetKind,
    progress: Option<IngestProgressCallback>,
    label: String,
) -> Result<DownloadedAsset, String> {
    eprintln!("{kind}: fetching GitHub release metadata");
    let (asset, published_at) = match latest_asset_with_published_at(kind).await {
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
                    published_at: None,
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
    eprintln!("{kind}: download target {}", output_path.display());
    download_release_asset_with_progress(&asset, &output_path, &label, progress).await?;
    eprintln!("{kind}: ready {}", output_path.display());
    Ok(DownloadedAsset {
        path: output_path,
        downloaded: true,
        published_at,
    })
}

pub(crate) async fn download_release_asset_with_progress(
    asset: &GitHubReleaseFile,
    output_path: &Path,
    label: &str,
    progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    let emit = |written_files| IngestProgress {
        label: label.to_owned(),
        asset: asset.name.clone(),
        phase: "downloading CVE archive".to_owned(),
        total_files: asset.size as usize,
        written_files,
        failed_files: 0,
    };
    if let Some(progress) = &progress {
        progress(emit(0));
    }
    let byte_progress: Option<DownloadProgressCallback> = progress.map(|progress| {
        let label = label.to_owned();
        let asset_name = asset.name.clone();
        let total = asset.size as usize;
        Arc::new(move |written: u64| {
            progress(IngestProgress {
                label: label.clone(),
                asset: asset_name.clone(),
                phase: "downloading CVE archive".to_owned(),
                total_files: total,
                written_files: written as usize,
                failed_files: 0,
            });
        }) as DownloadProgressCallback
    });
    asset
        .download_to_with_progress(output_path, byte_progress)
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CveArchiveOwnership {
    UserSupplied,
    Downloaded,
}

pub fn cleanup_processed_cve_archive(
    path: &Path,
    ownership: CveArchiveOwnership,
    keep_downloads: bool,
) -> Result<(), String> {
    if ownership == CveArchiveOwnership::Downloaded && !keep_downloads {
        remove_processed_zip(path)
    } else {
        Ok(())
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

pub async fn latest_asset(kind: ReleaseAssetKind) -> Result<GitHubReleaseFile, String> {
    latest_asset_with_published_at(kind)
        .await
        .map(|(asset, _)| asset)
}

async fn latest_asset_with_published_at(
    kind: ReleaseAssetKind,
) -> Result<(GitHubReleaseFile, Option<DateTime<Utc>>), String> {
    let mut cve = CveRelease::new();
    cve.refresh()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;

    let asset = match kind {
        ReleaseAssetKind::All => cve.latest_full_asset_with_date(),
        ReleaseAssetKind::Delta => cve.latest_delta_asset().map(|asset| (asset, None)),
        ReleaseAssetKind::DeltaMidnight => cve.latest_end_of_day_asset().map(|asset| (asset, None)),
    };

    asset
        .map(|(asset, published_at)| (asset.clone(), published_at))
        .ok_or_else(|| format!("no {kind} CVE zip asset found"))
}

pub async fn delta_assets_oldest_first() -> Result<Vec<GitHubReleaseFile>, String> {
    let mut cve = CveRelease::new();
    cve.refresh_all()
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;
    Ok(cve.delta_assets())
}

pub async fn delta_assets_published_after(
    cursor: DateTime<Utc>,
) -> Result<Vec<(DateTime<Utc>, GitHubReleaseFile)>, String> {
    let mut cve = CveRelease::new();
    cve.refresh_after(cursor)
        .await
        .map_err(|err| format!("failed to fetch CVE release list: {err}"))?;
    Ok(cve.delta_assets_after(cursor))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CveRemoteUpdateKind {
    Hourly,
    DailyThenHourly,
    Full,
}

fn cve_remote_update_kind(cursor: DateTime<Utc>, now: DateTime<Utc>) -> CveRemoteUpdateKind {
    let elapsed = now.signed_duration_since(cursor);
    if elapsed >= CVE_FULL_UPDATE_AFTER {
        CveRemoteUpdateKind::Full
    } else if elapsed > CVE_DAILY_UPDATE_AFTER {
        CveRemoteUpdateKind::DailyThenHourly
    } else {
        CveRemoteUpdateKind::Hourly
    }
}

enum CveRemoteUpdate {
    Full(GitHubReleaseFile),
    Deltas(Vec<(DateTime<Utc>, GitHubReleaseFile)>),
}

async fn cve_remote_update(
    cursor: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<CveRemoteUpdate, String> {
    let mut cve = CveRelease::new();
    match cve_remote_update_kind(cursor, now) {
        CveRemoteUpdateKind::Full => {
            cve.refresh()
                .await
                .map_err(|error| format!("failed to fetch CVE release list: {error}"))?;
            let asset = cve
                .latest_full_asset()
                .cloned()
                .ok_or_else(|| "no all CVE zip asset found".to_owned())?;
            Ok(CveRemoteUpdate::Full(asset))
        }
        kind => {
            cve.refresh_after(cursor)
                .await
                .map_err(|error| format!("failed to fetch CVE release list: {error}"))?;
            let assets = match kind {
                CveRemoteUpdateKind::Hourly => cve.delta_assets_after(cursor),
                CveRemoteUpdateKind::DailyThenHourly => cve.daily_then_hourly_assets_after(cursor),
                CveRemoteUpdateKind::Full => unreachable!(),
            };
            Ok(CveRemoteUpdate::Deltas(assets))
        }
    }
}

/// Applies local or downloaded CVE delta archives through the SQLx writer.
pub async fn apply_delta_updates(
    db: &SqlxDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
) -> Result<Vec<PathBuf>, String> {
    apply_delta_updates_with_progress(db, zip, max_chunks, None).await
}

/// Applies local or downloaded CVE deltas and optionally reports import progress.
pub async fn apply_delta_updates_with_progress(
    db: &SqlxDatabase,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
    progress: Option<IngestProgressCallback>,
) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = zip {
        import_cve_zip_with_mode(
            db.clone(),
            "update",
            &path,
            CveZipImportOptions {
                max_chunks,
                bulk_replace: false,
                rebuild_after: true,
                index_started: None,
                progress,
            },
        )
        .await?;
        db.mark_cve_asset_applied(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("local-cve.zip"),
            "local",
        )
        .await
        .map_err(|error| format!("failed to record local delta asset: {error}"))?;
        return Ok(vec![path]);
    }

    let cursor = db
        .metadata_value(CVE_DELTA_CURSOR_METADATA_KEY)
        .await
        .map_err(|error| format!("failed to read CVE delta cursor: {error}"))?
        .ok_or_else(|| {
            "CVE delta cursor is missing; run init to rebuild the database".to_owned()
        })?;
    let cursor = DateTime::parse_from_rfc3339(&cursor)
        .map_err(|error| format!("invalid CVE delta cursor; run init: {error}"))?
        .with_timezone(&Utc);
    let update = cve_remote_update(cursor, Utc::now()).await?;
    let assets = match update {
        CveRemoteUpdate::Full(asset) => {
            let asset_cursor = cve_full_asset_cursor(Path::new(&asset.name)).ok_or_else(|| {
                format!(
                    "cannot determine the full CVE archive timestamp from {}",
                    asset.name
                )
            })?;
            vec![(asset_cursor, asset)]
        }
        CveRemoteUpdate::Deltas(assets) => assets,
    };
    let mut paths = Vec::with_capacity(assets.len());
    let mut database_changed = false;
    let apply_result = async {
        for (published_at, asset) in assets {
            let filename = asset
                .safe_file_name()
                .map_err(|error| format!("unsafe asset name {}: {error}", asset.name))?;
            let path = temporary_zip_file_path(filename, Some(asset.size))
                .map_err(|error| format!("failed to prepare delta archive {filename}: {error}"))?;
            paths.push(path.clone());
            download_release_asset_with_progress(&asset, &path, "update", progress.clone()).await?;
            database_changed = true;
            import_cve_zip_with_mode(
                db.clone(),
                "update",
                &path,
                CveZipImportOptions {
                    max_chunks,
                    bulk_replace: false,
                    rebuild_after: false,
                    index_started: None,
                    progress: progress.clone(),
                },
            )
            .await?;
            db.mark_cve_asset_applied(&asset.name, &asset.url)
                .await
                .map_err(|error| format!("failed to record CVE delta {}: {error}", asset.name))?;
            // Persist progress per archive. If a subsequent download or enrichment
            // source fails, the next update resumes here instead of reimporting every
            // already-applied delta.
            if max_chunks.is_none() {
                db.set_metadata_value(CVE_DELTA_CURSOR_METADATA_KEY, &published_at.to_rfc3339())
                    .await
                    .map_err(|error| format!("failed to advance CVE delta cursor: {error}"))?;
            }
        }
        Ok::<(), String>(())
    }
    .await;
    let rebuild_result = if database_changed {
        // Each delta archive refreshed only its changed CVE projection rows while it was
        // ingested. A global rebuild here would rescan and reindex the entire CVE corpus.
        eprintln!("update: CVE delta search rows refreshed incrementally");
        Ok(())
    } else {
        eprintln!("update: CVE data unchanged; search rebuild skipped");
        Ok(())
    };
    if let Err(error) = apply_result.and(rebuild_result) {
        for path in &paths {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(paths)
}

/// Refreshes OSV using the stored selection plus any newly requested coverage.
pub async fn sync_osv_after_update(
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
    sync_osv(db.clone(), label, selection).await.map(|_| ())
}

/// Refreshes the catalogs and enrichment sources used by a normal update.
pub async fn sync_all_enrichment_sources_after_update(
    db: &SqlxDatabase,
    label: &str,
    requested_osv_additions: Option<&OsvImportSelection>,
    cve_changed: bool,
) -> Result<(), String> {
    sync_cwe_catalog(db.clone()).await?;
    sync_capec_catalog(db.clone()).await?;
    sync_osv_after_update(db, label, requested_osv_additions).await?;
    sync_risk_feeds(db.clone(), label, cve_changed)
        .await
        .map(|_| ())
}

/// Imports CVE JSON from a ZIP archive.
pub async fn import_cve_zip(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
) -> Result<usize, String> {
    import_cve_zip_with_mode(
        db,
        label,
        asset_path,
        CveZipImportOptions {
            max_chunks,
            bulk_replace: false,
            rebuild_after: true,
            index_started: None,
            progress: None,
        },
    )
    .await
}

/// Imports CVE JSON from a ZIP archive while reporting progress.
pub async fn import_cve_zip_with_progress(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
    progress: IngestProgressCallback,
) -> Result<usize, String> {
    import_cve_zip_with_mode(
        db,
        label,
        asset_path,
        CveZipImportOptions {
            max_chunks,
            bulk_replace: false,
            rebuild_after: true,
            index_started: None,
            progress: Some(progress),
        },
    )
    .await
}

/// Imports a replacement archive with deferred indexes.
pub async fn import_cve_zip_bulk(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
) -> Result<usize, String> {
    import_cve_zip_with_mode(
        db,
        label,
        asset_path,
        CveZipImportOptions {
            max_chunks,
            bulk_replace: true,
            rebuild_after: true,
            index_started: None,
            progress: None,
        },
    )
    .await
}

pub(crate) async fn import_cve_zip_bulk_with_index_signal(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    max_chunks: Option<usize>,
    index_started: oneshot::Sender<()>,
    progress: Option<IngestProgressCallback>,
) -> Result<usize, String> {
    import_cve_zip_with_mode(
        db,
        label,
        asset_path,
        CveZipImportOptions {
            max_chunks,
            bulk_replace: true,
            rebuild_after: true,
            index_started: Some(index_started),
            progress,
        },
    )
    .await
}

struct CveZipImportOptions {
    max_chunks: Option<usize>,
    bulk_replace: bool,
    rebuild_after: bool,
    index_started: Option<oneshot::Sender<()>>,
    progress: Option<IngestProgressCallback>,
}

async fn import_cve_zip_with_mode(
    db: SqlxDatabase,
    label: &str,
    asset_path: &Path,
    options: CveZipImportOptions,
) -> Result<usize, String> {
    let CveZipImportOptions {
        max_chunks,
        bulk_replace,
        rebuild_after,
        index_started,
        progress,
    } = options;
    let storage = ZipStorage::new(asset_path.to_string_lossy().to_string())
        .map_err(|error| format!("{label}: failed to open {}: {error}", asset_path.display()))?;
    let entries = storage.entries();
    let total_chunks = ingest_chunk_count(entries.len(), max_chunks);
    emit_ingest_progress(
        &progress,
        label,
        asset_path,
        "importing CVE chunks",
        total_chunks,
        0,
        0,
    );
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
    let mut changed_cve_ids = Vec::new();
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
        let import_result = if bulk_replace {
            db.import_cve_raw_jsons_bulk_init(records)
                .await
                .map(|count| (count, Vec::new()))
        } else {
            db.import_cve_raw_jsons_deferred_search_with_ids(records)
                .await
        };
        let (count, cve_ids) = import_result.map_err(|error| {
            format!("{label}: failed to import CVE chunk {chunk_index}: {error}")
        })?;
        imported += count;
        changed_cve_ids.extend(cve_ids);
        emit_ingest_progress(
            &progress,
            &label,
            asset_path,
            "importing CVE chunks",
            total_chunks,
            (chunk_index + 1).min(total_chunks),
            0,
        );
        eprintln!(
            "{label}: committed CVE chunk {chunk_index} in {:?}",
            write_started.elapsed()
        );
    }
    if !rebuild_after {
        if !bulk_replace {
            emit_ingest_progress(
                &progress,
                label,
                asset_path,
                "refreshing CVE search data",
                0,
                0,
                0,
            );
            eprintln!(
                "{label}: refreshing CVE search rows for {} changed CVE records",
                changed_cve_ids.len()
            );
            db.refresh_cve_search_for_ids(changed_cve_ids)
                .await
                .map_err(|error| format!("{label}: failed to refresh CVE search data: {error}"))?;
        }
        return Ok(imported);
    }
    emit_ingest_progress(
        &progress,
        label,
        asset_path,
        "rebuilding CVE search indexes",
        0,
        0,
        0,
    );
    let fts_started = Instant::now();
    eprintln!("{label}: rebuilding CVE search indexes");
    if bulk_replace {
        let result = if let Some(index_started) = index_started {
            db.finish_cve_bulk_load_with_index_signal(index_started)
                .await
        } else {
            db.finish_cve_bulk_load().await
        };
        result.map_err(|error| format!("{label}: failed to finish CVE bulk load: {error}"))?;
    } else {
        eprintln!(
            "{label}: refreshing CVE search rows for {} changed CVE records",
            changed_cve_ids.len()
        );
        db.refresh_cve_search_for_ids(changed_cve_ids)
            .await
            .map_err(|error| format!("{label}: failed to refresh CVE search data: {error}"))?;
    }
    eprintln!(
        "{label}: rebuilt search indexes in {:?}",
        fts_started.elapsed()
    );
    db.check_search_integrity_quick()
        .await
        .map_err(|error| format!("{label}: database integrity check failed: {error}"))?;
    Ok(imported)
}

fn ingest_chunk_count(entry_count: usize, max_chunks: Option<usize>) -> usize {
    let available_chunks = entry_count.div_ceil(INGEST_CHUNK_SIZE);
    max_chunks
        .map(|maximum| available_chunks.min(maximum))
        .unwrap_or(available_chunks)
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

/// Reads one CVE ZIP chunk using the access strategy matching its backing store.
///
/// Reads disk-backed ZIPs sequentially to preserve OS readahead.
///
/// In-memory archives use independent Rayon readers.
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
                .read_entry(entry)
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
mod tests;
