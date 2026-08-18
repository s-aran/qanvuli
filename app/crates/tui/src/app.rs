use super::{
    SEARCH_TIMEOUT, TUI_LOAD_MORE_LIMIT,
    db::{
        capec::search_capec_entries,
        cwe::search_cwe_entries,
        raw_json::{load_cve_raw_json, load_osv_raw_json},
        search::{
            SearchCandidate, SearchContinuation, SearchRequest, SearchResult, SearchTerm,
            run_count_request, run_search_request, run_search_request_after,
        },
    },
    display::DisplaySettings,
    form::AdvancedForm,
    mode::SearchMode,
};
use qanvuli_app_commands::common::IngestProgress;
use qanvuli_core::database::{
    CapecDetail, CapecEntry, CapecSearchFilters, CveAdvancedSearch, CveDatabase, CveStateScope,
    CveSummarySortOrder, CveSummaryWithDetail, CweEntry, EnrichedCveSummary, OsvSummary,
};
use ratatui::widgets::{ListState, Paragraph, Wrap};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::{sync::mpsc::UnboundedReceiver, task::JoinHandle};

mod capec_tree;
mod state;

#[cfg(test)]
mod tests;

use capec_tree::{filter_capec_tree, project_capec_tree};
use state::{CapecState, CweState, MainState, OverlayState, RawState, Tasks};

const MIN_PAGE_SIZE: usize = 1;
const OSV_IMPORT_ID_PREFIXES_METADATA_KEY: &str = "osv_import_id_prefixes";
pub(super) const CWE_STATUS_COUNT: usize = 6;
const CWE_STATUS_CONTROL_COUNT: usize = CWE_STATUS_COUNT + 3;
const CWE_STATUS_SELECT_ALL_CURSOR: usize = CWE_STATUS_COUNT;
const CWE_STATUS_CLEAR_ALL_CURSOR: usize = CWE_STATUS_COUNT + 1;
pub(super) const CWE_CAPEC_CURSOR: usize = CWE_STATUS_COUNT + 2;
pub(super) const CWE_STATUSES: [CweStatus; CWE_STATUS_COUNT] = [
    CweStatus::Stable,
    CweStatus::Usable,
    CweStatus::Draft,
    CweStatus::Incomplete,
    CweStatus::Obsolete,
    CweStatus::Deprecated,
];

pub(super) struct App {
    pub(super) main: MainState,
    pub(super) raw: RawState,
    pub(super) cwe: CweState,
    pub(super) capec: CapecState,
    pub(super) overlay: OverlayState,
    tasks: Tasks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PaneFocus {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RightPaneTab {
    Cve,
    Osv,
    Metadata,
    Enrichment,
}

impl RightPaneTab {
    pub(super) fn next(self) -> Self {
        match self {
            Self::Cve => Self::Osv,
            Self::Osv => Self::Metadata,
            Self::Metadata => Self::Enrichment,
            Self::Enrichment => Self::Cve,
        }
    }

    pub(super) fn previous(self) -> Self {
        match self {
            Self::Cve => Self::Enrichment,
            Self::Osv => Self::Cve,
            Self::Metadata => Self::Osv,
            Self::Enrichment => Self::Metadata,
        }
    }

    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Cve => "CVE",
            Self::Osv => "OSV",
            Self::Metadata => "Metadata",
            Self::Enrichment => "Enrichment",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ViewMode {
    Normal,
    RawJson,
    CweList,
    CapecList,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CweStatus {
    Stable,
    Usable,
    Draft,
    Incomplete,
    Obsolete,
    Deprecated,
}

impl CweStatus {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Usable => "Usable",
            Self::Draft => "Draft",
            Self::Incomplete => "Incomplete",
            Self::Obsolete => "Obsolete",
            Self::Deprecated => "Deprecated",
        }
    }
}

struct PendingSearch {
    kind: SearchKind,
    handle: JoinHandle<Result<SearchResult, String>>,
    count: Option<PendingCount>,
    timed_out_once: bool,
}

struct PendingCount {
    db: CveDatabase,
    request: SearchRequest,
}

struct PendingEnrichment {
    handle: JoinHandle<Result<Vec<EnrichedCveSummary>, String>>,
}

struct PendingMetadataCapec {
    handle: JoinHandle<Result<Vec<MetadataCapec>, String>>,
}

struct MetadataCapec {
    cve_id: String,
    capec_ids: Vec<i32>,
}

struct PendingMaintenance {
    operation: MaintenanceOperation,
    progress: UnboundedReceiver<IngestProgress>,
    result: UnboundedReceiver<Result<(), String>>,
}

enum SearchKind {
    Replace,
    Append { select_offset: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TimeoutChoice {
    Continue,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MaintenanceChoice {
    Init,
    Update,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MaintenanceOperation {
    Init,
    Update,
}

#[derive(Clone, Debug, Default)]
pub(super) struct MaintenanceProgress {
    pub(super) label: String,
    pub(super) asset: String,
    pub(super) phase: String,
    pub(super) total_files: usize,
    pub(super) written_files: usize,
    pub(super) failed_files: usize,
}

impl From<IngestProgress> for MaintenanceProgress {
    fn from(value: IngestProgress) -> Self {
        Self {
            label: value.label,
            asset: value.asset,
            phase: value.phase,
            total_files: value.total_files,
            written_files: value.written_files,
            failed_files: value.failed_files,
        }
    }
}

impl App {
    pub(super) fn new(query: String, limit: u64) -> Self {
        let search_mode = SearchMode::from_query_prefix(&query).unwrap_or(SearchMode::FreeText);
        let mut app = Self {
            main: MainState::new(query, limit, search_mode),
            raw: RawState::default(),
            cwe: CweState::default(),
            capec: CapecState::default(),
            overlay: OverlayState::default(),
            tasks: Tasks::default(),
        };
        app.sync_advanced_from_main();
        app
    }

    pub(super) fn start_search(&mut self, db: CveDatabase) {
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
        let sort_order = self.main.display.sort_order();
        let term = SearchTerm::new(self.main.search_mode, self.main.query.clone());
        let request = if !self.main.query.trim().is_empty() {
            SearchRequest::Query {
                term,
                state_scope: self.main.state_scope,
                kev_only: self.main.display.kev_only,
                sort_order,
            }
        } else {
            SearchRequest::Advanced {
                options: self.main_search_options(sort_order),
                include_cve: true,
                // Empty Enter is the TUI's browse-all action. Do not append every OSV
                // advisory to that CVE list.
                include_osv: !self.main.query.trim().is_empty(),
                osv_families: Vec::new(),
                ecosystems: None,
            }
        };
        self.main.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn start_advanced_search(&mut self, db: CveDatabase) {
        self.main.query = self.main.advanced.query.clone();
        self.main.search_mode = self.main.advanced.query_mode;
        self.main.search_mode_explicit = true;
        self.main.state_scope = self.main.advanced.state_scope;
        let mut options = self
            .main
            .advanced
            .to_search_options(self.main.display.sort_order());
        options.kev_only = self.main.display.kev_only;
        let ecosystems = options
            .package_ecosystem
            .as_deref()
            .map(str::trim)
            .filter(|ecosystem| !ecosystem.is_empty())
            .map(|ecosystem| vec![ecosystem.to_owned()]);
        let request = SearchRequest::Advanced {
            options,
            include_cve: self.main.advanced.source_cve,
            include_osv: self.main.advanced.source_osv,
            osv_families: if self.main.advanced.source_osv {
                self.main.advanced.selected_advisories()
            } else {
                Vec::new()
            },
            ecosystems,
        };
        self.main.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn open_advanced_search(&mut self, db: Option<CveDatabase>) {
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
        self.overlay.snapshots.advanced = Some(self.main.advanced.clone());
        self.load_scope_candidates(db);
        self.overlay.show_advanced = true;
    }

    pub(super) fn apply_advanced_search(&mut self) {
        self.overlay.snapshots.advanced = None;
        self.overlay.show_advanced = false;
    }

    pub(super) fn cancel_advanced_search(&mut self) {
        if let Some(previous) = self.overlay.snapshots.advanced.take() {
            self.main.advanced = previous;
            self.sync_main_from_advanced();
        }
        self.overlay.show_advanced = false;
    }

    pub(super) fn load_scope_candidates(&mut self, db: Option<CveDatabase>) {
        if self.tasks.scope.is_some() {
            return;
        }
        let Some(db) = db else {
            return;
        };
        self.tasks.scope = Some(tokio::spawn(async move {
            let configured_prefixes = db
                .metadata_value(OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
                .await
                .map_err(|err| err.to_string())?;
            let advisories =
                Self::registered_osv_advisory_families(&db, configured_prefixes.as_deref()).await?;
            Ok(advisories)
        }));
    }

    async fn registered_osv_advisory_families(
        db: &CveDatabase,
        configured_prefixes: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let Some(configured_prefixes) = configured_prefixes else {
            // Older databases did not persist this setting; match the default import scope.
            return Ok(vec!["GHSA".to_owned(), "OSV".to_owned()]);
        };
        if configured_prefixes.trim().eq_ignore_ascii_case("ALL") {
            return db
                .osv_advisory_families()
                .await
                .map_err(|err| err.to_string());
        }
        Ok(configured_prefixes
            .split(',')
            .map(str::trim)
            .filter(|prefix| !prefix.is_empty())
            .map(|prefix| prefix.trim_end_matches('-').to_ascii_uppercase())
            .collect())
    }

    pub(super) fn open_display_settings(&mut self) {
        self.overlay.snapshots.display =
            Some((self.main.display.clone(), self.main.advanced.clone()));
        self.main.display.source_focus = false;
        self.main.display.scroll = 0;
        self.overlay.show_display = true;
    }

    pub(super) fn cancel_display_settings(&mut self) {
        if let Some((display, advanced)) = self.overlay.snapshots.display.take() {
            self.main.display = display;
            self.main.advanced = advanced;
        }
        self.overlay.show_display = false;
    }

    pub(super) fn apply_display_settings(&mut self, db: Option<CveDatabase>) {
        self.overlay.snapshots.display = None;
        self.overlay.show_display = false;
        let Some(db) = db else {
            return;
        };
        let mut request = self.main.searched_request.clone();
        match &mut request {
            SearchRequest::Query {
                kev_only,
                sort_order,
                ..
            } => {
                *kev_only = self.main.display.kev_only;
                *sort_order = self.main.display.sort_order();
            }
            SearchRequest::Advanced { options, .. } => {
                options.kev_only = self.main.display.kev_only;
                options.sort_order = self.main.display.sort_order();
            }
        }
        self.main.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to apply display settings");
    }

    pub(super) fn start_load_more(&mut self, db: CveDatabase) {
        if self.searching() || self.main.exhausted || self.candidate_count() == 0 {
            return;
        }

        let request = self.main.searched_request.clone();
        let offset = self.main.search_offset;
        let select_offset = self.candidate_count();
        self.start_pending_search(
            db,
            request,
            TUI_LOAD_MORE_LIMIT,
            offset,
            SearchKind::Append { select_offset },
            "failed to load more search results",
        );
    }

    pub(super) async fn poll_search(&mut self) -> Result<(), String> {
        let Some(search) = self.tasks.search.as_ref() else {
            return Ok(());
        };
        if !search.handle.is_finished() {
            self.check_search_timeout();
            return Ok(());
        }

        let Some(search) = self.tasks.search.take() else {
            self.overlay.status_message = Some("search task disappeared".to_owned());
            self.tasks.search_started_at = None;
            self.tasks.search_timeout_at = None;
            self.overlay.show_timeout_prompt = false;
            return Ok(());
        };
        let kind = search.kind;
        let result = match search.handle.await {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                self.finish_failed_search(err);
                return Ok(());
            }
            Err(err) => {
                self.finish_failed_search(format!("failed to join search task: {err}"));
                return Ok(());
            }
        };
        self.tasks.search_started_at = None;
        self.tasks.search_timeout_at = None;
        self.overlay.show_timeout_prompt = false;
        let count = search.count;
        self.main.search_continuation = result.continuation;
        match kind {
            SearchKind::Replace => {
                self.main.exhausted = result.exhausted;
                self.main.search_offset = result.consumed;
                self.main.candidates = result.candidates;
                self.main.linked_osv = result.linked_osv;
                self.clear_detail();
                self.select_candidate(0);
                if let Some(count) = count {
                    self.tasks.count =
                        Some(tokio::spawn(run_count_request(count.db, count.request)));
                }
            }
            SearchKind::Append { select_offset } => {
                self.main.exhausted = result.exhausted;
                self.main.search_offset = self.main.search_offset.saturating_add(result.consumed);
                self.main.candidates.extend(result.candidates);
                for (cve_id, advisories) in result.linked_osv {
                    let existing = self.main.linked_osv.entry(cve_id).or_default();
                    let mut ids = existing
                        .iter()
                        .map(|row| row.osv_id.clone())
                        .collect::<HashSet<_>>();
                    existing.extend(
                        advisories
                            .into_iter()
                            .filter(|row| ids.insert(row.osv_id.clone())),
                    );
                }
                self.select_candidate(select_offset);
            }
        }
        for row in result.enrichment {
            self.main.enrichment.insert(row.cve_id.clone(), row);
        }
        Ok(())
    }

    pub(super) async fn poll_count(&mut self) {
        let Some(task) = self.tasks.count.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.count.take() else {
            self.overlay.status_message = Some("count task disappeared".to_owned());
            return;
        };
        match task.await {
            Ok(Ok(total)) => {
                self.main.total_results = Some(total);
            }
            Ok(Err(err)) => {
                self.overlay.status_message =
                    Some(format!("failed to count search results: {err}"));
            }
            Err(err) => {
                self.overlay.status_message = Some(format!("failed to join count task: {err}"));
            }
        }
    }

    pub(super) async fn poll_maintenance(&mut self) -> bool {
        let Some(maintenance) = self.tasks.maintenance.as_mut() else {
            return false;
        };
        while let Ok(progress) = maintenance.progress.try_recv() {
            self.overlay.maintenance_progress = Some(progress.into());
        }
        match maintenance.result.try_recv() {
            Ok(result) => {
                let operation = maintenance.operation;
                self.tasks.maintenance = None;
                let message = match result {
                    Ok(()) => match operation {
                        MaintenanceOperation::Init => "init completed".to_owned(),
                        MaintenanceOperation::Update => "update completed".to_owned(),
                    },
                    Err(err) => match operation {
                        MaintenanceOperation::Init => format!("init failed: {err}"),
                        MaintenanceOperation::Update => format!("update failed: {err}"),
                    },
                };
                self.overlay.status_message = Some(message);
                self.overlay.maintenance_progress = None;
                self.overlay.show_maintenance = false;
                true
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => false,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                let operation = maintenance.operation;
                self.tasks.maintenance = None;
                self.overlay.status_message = Some(match operation {
                    MaintenanceOperation::Init => "init task disconnected".to_owned(),
                    MaintenanceOperation::Update => "update task disconnected".to_owned(),
                });
                self.overlay.maintenance_progress = None;
                self.overlay.show_maintenance = false;
                true
            }
        }
    }

    pub(super) async fn poll_raw_json(&mut self) {
        let Some(task) = self.tasks.raw_json.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.raw_json.take() else {
            self.raw.json = Some("raw JSON task disappeared".to_owned());
            self.raw.scroll = 0;
            return;
        };
        match task.await {
            Ok(Ok(raw_json)) => {
                self.raw.json = Some(raw_json);
                self.raw.scroll = 0;
            }
            Ok(Err(err)) => {
                self.raw.json = Some(err);
                self.raw.scroll = 0;
            }
            Err(err) => {
                self.raw.json = Some(format!("failed to join raw JSON task: {err}"));
                self.raw.scroll = 0;
            }
        }
    }

    pub(super) async fn poll_enrichment(&mut self) {
        let Some(task) = self.tasks.enrichment.as_ref() else {
            return;
        };
        if !task.handle.is_finished() {
            return;
        }
        let Some(task) = self.tasks.enrichment.take() else {
            self.overlay.status_message = Some("enrichment task disappeared".to_owned());
            return;
        };
        match task.handle.await {
            Ok(Ok(rows)) => {
                for row in rows {
                    self.main.enrichment.insert(row.cve_id.clone(), row);
                }
            }
            Ok(Err(err)) => {
                self.overlay.status_message =
                    Some(format!("failed to load enrichment summaries: {err}"));
            }
            Err(err) => {
                self.overlay.status_message =
                    Some(format!("failed to join enrichment task: {err}"));
            }
        }
    }

    pub(super) fn ensure_loaded_enrichment(&mut self, db: Option<CveDatabase>) {
        if self.main.candidates.is_empty() || self.tasks.enrichment.is_some() {
            return;
        }
        let cve_ids = self
            .main
            .candidates
            .iter()
            .filter_map(|candidate| match candidate {
                SearchCandidate::Cve(cve) => Some(cve.summary.cve_id.clone()),
                SearchCandidate::Osv(_) => None,
            })
            .filter(|cve_id| !self.main.enrichment.contains_key(cve_id))
            .collect::<Vec<_>>();
        if cve_ids.is_empty() {
            return;
        }
        let Some(db) = db else {
            self.overlay.status_message = Some("database is unavailable".to_owned());
            return;
        };
        self.tasks.enrichment = Some(PendingEnrichment {
            handle: tokio::spawn(async move {
                db.enriched_cve_summaries(&cve_ids)
                    .await
                    .map_err(|err| err.to_string())
            }),
        });
    }

    pub(super) async fn poll_metadata_capec(&mut self) {
        let Some(task) = self.tasks.metadata_capec.as_ref() else {
            return;
        };
        if !task.handle.is_finished() {
            return;
        }
        let Some(task) = self.tasks.metadata_capec.take() else {
            return;
        };
        match task.handle.await {
            Ok(Ok(rows)) => {
                self.main
                    .metadata_capec_ids
                    .extend(rows.into_iter().map(|row| (row.cve_id, row.capec_ids)));
                self.clamp_metadata_scroll();
            }
            Ok(Err(err)) => {
                self.overlay.status_message = Some(format!("failed to load CAPEC links: {err}"));
            }
            Err(err) => {
                self.overlay.status_message =
                    Some(format!("failed to join CAPEC link task: {err}"));
            }
        }
    }

    pub(super) fn ensure_loaded_metadata_capec(&mut self, db: Option<CveDatabase>) {
        if self.tasks.metadata_capec.is_some() {
            return;
        }
        let pending = self
            .main
            .candidates
            .iter()
            .filter_map(|candidate| match candidate {
                SearchCandidate::Cve(cve)
                    if !self
                        .main
                        .metadata_capec_ids
                        .contains_key(&cve.summary.cve_id) =>
                {
                    Some(cve)
                }
                _ => None,
            })
            .map(|cve| {
                (
                    cve.summary.cve_id.clone(),
                    cve.detail.cwes.iter().map(|cwe| cwe.id).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return;
        }
        let Some(db) = db else {
            return;
        };
        self.tasks.metadata_capec = Some(PendingMetadataCapec {
            handle: tokio::spawn(async move {
                let cwe_ids = pending
                    .iter()
                    .flat_map(|(_, ids)| ids.iter().copied())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let links = db
                    .capec_ids_for_cwes(&cwe_ids)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(pending
                    .into_iter()
                    .map(|(cve_id, cwe_ids)| {
                        let mut capec_ids = cwe_ids
                            .iter()
                            .filter_map(|cwe_id| links.get(cwe_id))
                            .flatten()
                            .copied()
                            .collect::<Vec<_>>();
                        capec_ids.sort_unstable();
                        capec_ids.dedup();
                        MetadataCapec { cve_id, capec_ids }
                    })
                    .collect())
            }),
        });
    }

    pub(super) async fn poll_cwe_search(&mut self) {
        let Some(task) = self.tasks.cwe.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.cwe.take() else {
            self.overlay.status_message = Some("CWE task disappeared".to_owned());
            return;
        };
        match task.await {
            Ok(Ok(rows)) => {
                self.cwe.results = rows;
                self.cwe.scroll = 0;
                self.cwe.selected = 0;
                self.cwe.detail_scroll = 0;
                self.cwe.relation_return_id = None;
                self.clamp_cwe_scroll(self.main.left_page_size);
            }
            Ok(Err(err)) => {
                self.overlay.status_message = Some(err);
                self.cwe.results.clear();
                self.cwe.scroll = 0;
                self.cwe.selected = 0;
                self.cwe.detail_scroll = 0;
                self.cwe.relation_return_id = None;
            }
            Err(err) => {
                self.overlay.status_message = Some(format!("failed to join CWE task: {err}"));
                self.cwe.results.clear();
                self.cwe.scroll = 0;
                self.cwe.selected = 0;
                self.cwe.detail_scroll = 0;
                self.cwe.relation_return_id = None;
            }
        }
    }

    pub(super) async fn poll_capec_search(&mut self) {
        let Some(task) = self.tasks.capec.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.capec.take() else {
            return;
        };
        match task.await {
            Ok(Ok(rows)) => {
                self.capec.catalog = rows;
                self.apply_capec_filters();
            }
            Ok(Err(err)) => {
                self.overlay.status_message = Some(err);
                self.capec.results.clear();
                self.capec.tree_paths.clear();
                self.capec.tree_prefixes.clear();
            }
            Err(err) => {
                self.overlay.status_message = Some(format!("failed to join CAPEC task: {err}"));
                self.capec.results.clear();
                self.capec.tree_paths.clear();
                self.capec.tree_prefixes.clear();
            }
        }
    }

    pub(super) async fn poll_capec_detail(&mut self) {
        let Some(task) = self.tasks.capec_detail.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.capec_detail.take() else {
            return;
        };
        match task.await {
            Ok(Ok(detail)) => self.capec.taxonomy = detail,
            Ok(Err(error)) => self.overlay.status_message = Some(error),
            Err(error) => {
                self.overlay.status_message =
                    Some(format!("failed to join CAPEC detail task: {error}"))
            }
        }
    }

    pub(super) fn searching(&self) -> bool {
        self.tasks.search.is_some()
    }

    pub(super) async fn poll_scope_candidates(&mut self) {
        let Some(task) = self.tasks.scope.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.tasks.scope.take() else {
            return;
        };
        match task.await {
            Ok(Ok(advisories)) => self.main.advanced.set_scope_candidates(advisories),
            Ok(Err(err)) => self.overlay.status_message = Some(err),
            Err(err) => {
                self.overlay.status_message = Some(format!("failed to join scope task: {err}"))
            }
        }
    }

    pub(super) fn scope_candidates_loading(&self) -> bool {
        self.tasks.scope.is_some()
    }

    pub(super) fn has_background_task(&self) -> bool {
        self.tasks.search.is_some()
            || self.tasks.count.is_some()
            || self.tasks.raw_json.is_some()
            || self.tasks.enrichment.is_some()
            || self.tasks.cwe.is_some()
            || self.tasks.capec.is_some()
            || self.tasks.capec_detail.is_some()
            || self.tasks.scope.is_some()
            || self.tasks.maintenance.is_some()
    }

    pub(super) fn cwe_searching(&self) -> bool {
        self.tasks.cwe.is_some()
    }

    pub(super) fn maintenance_running(&self) -> bool {
        self.tasks.maintenance.is_some()
    }

    pub(super) fn maintenance_status(&self) -> Option<&'static str> {
        self.tasks
            .maintenance
            .as_ref()
            .map(|maintenance| match maintenance.operation {
                MaintenanceOperation::Init => "init running",
                MaintenanceOperation::Update => "update running",
            })
    }

    pub(super) fn detail_status(&self) -> &'static str {
        if self.searching() {
            "searching"
        } else if self.selected().is_none() && self.selected_osv().is_none() {
            "no selection"
        } else {
            "ready"
        }
    }

    pub(super) fn abort_search(&mut self) {
        if let Some(search) = self.tasks.search.take() {
            search.handle.abort();
        }
        if let Some(task) = self.tasks.count.take() {
            task.abort();
        }
        if let Some(task) = self.tasks.raw_json.take() {
            task.abort();
        }
        if let Some(task) = self.tasks.enrichment.take() {
            task.handle.abort();
        }
        if let Some(task) = self.tasks.cwe.take() {
            task.abort();
        }
        self.tasks.search_started_at = None;
        self.tasks.search_timeout_at = None;
        self.overlay.show_timeout_prompt = false;
    }

    /// Cancels and joins every task that may retain a cloned database handle.
    /// Maintenance must wait for these before closing the single-owner SQLite writer.
    pub(super) async fn abort_database_tasks(&mut self) {
        if let Some(search) = self.tasks.search.take() {
            search.handle.abort();
            let _ = search.handle.await;
        }
        if let Some(task) = self.tasks.count.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tasks.raw_json.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tasks.enrichment.take() {
            task.handle.abort();
            let _ = task.handle.await;
        }
        if let Some(task) = self.tasks.metadata_capec.take() {
            task.handle.abort();
            let _ = task.handle.await;
        }
        if let Some(task) = self.tasks.cwe.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tasks.capec.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tasks.capec_detail.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tasks.scope.take() {
            task.abort();
            let _ = task.await;
        }
        self.tasks.search_started_at = None;
        self.tasks.search_timeout_at = None;
        self.overlay.show_timeout_prompt = false;
    }

    pub(super) fn open_maintenance(&mut self) {
        if self.maintenance_running() {
            self.overlay.status_message =
                Some("database maintenance is already running".to_owned());
            return;
        }
        self.overlay.show_maintenance = true;
        self.overlay.maintenance_choice = MaintenanceChoice::Update;
        self.overlay.maintenance_confirming = false;
    }

    pub(super) fn close_maintenance(&mut self) {
        self.overlay.show_maintenance = false;
        self.overlay.maintenance_confirming = false;
    }

    pub(super) fn confirm_maintenance_choice(&mut self) {
        if self.overlay.maintenance_choice == MaintenanceChoice::Cancel {
            self.close_maintenance();
        } else {
            self.overlay.maintenance_confirming = true;
        }
    }

    pub(super) fn cancel_maintenance_confirmation(&mut self) {
        self.overlay.maintenance_confirming = false;
    }

    pub(super) fn toggle_maintenance_keep_downloads(&mut self) {
        self.overlay.maintenance_keep_downloads = !self.overlay.maintenance_keep_downloads;
    }

    pub(super) fn next_maintenance_choice(&mut self) {
        self.overlay.maintenance_choice = match self.overlay.maintenance_choice {
            MaintenanceChoice::Init => MaintenanceChoice::Update,
            MaintenanceChoice::Update => MaintenanceChoice::Cancel,
            MaintenanceChoice::Cancel => MaintenanceChoice::Init,
        };
    }

    pub(super) fn previous_maintenance_choice(&mut self) {
        self.overlay.maintenance_choice = match self.overlay.maintenance_choice {
            MaintenanceChoice::Init => MaintenanceChoice::Cancel,
            MaintenanceChoice::Update => MaintenanceChoice::Init,
            MaintenanceChoice::Cancel => MaintenanceChoice::Update,
        };
    }

    pub(super) fn start_maintenance(
        &mut self,
        operation: MaintenanceOperation,
        progress: UnboundedReceiver<IngestProgress>,
        result: UnboundedReceiver<Result<(), String>>,
    ) {
        self.abort_search();
        self.overlay.show_maintenance = true;
        self.overlay.maintenance_confirming = false;
        self.overlay.status_message = Some(match operation {
            MaintenanceOperation::Init => "init started".to_owned(),
            MaintenanceOperation::Update => "update started".to_owned(),
        });
        self.overlay.maintenance_progress = Some(MaintenanceProgress {
            label: match operation {
                MaintenanceOperation::Init => "init".to_owned(),
                MaintenanceOperation::Update => "update".to_owned(),
            },
            phase: "starting".to_owned(),
            ..MaintenanceProgress::default()
        });
        self.tasks.maintenance = Some(PendingMaintenance {
            operation,
            progress,
            result,
        });
    }

    pub(super) fn cancel_timed_out_search(&mut self) {
        self.abort_search();
        self.overlay.status_message = Some("search canceled".to_owned());
    }

    pub(super) fn continue_timed_out_search(&mut self) {
        if let Some(search) = self.tasks.search.as_mut() {
            search.timed_out_once = true;
            self.tasks.search_timeout_at = Some(Instant::now() + SEARCH_TIMEOUT);
        }
        self.overlay.show_timeout_prompt = false;
        self.overlay.timeout_choice = TimeoutChoice::Continue;
        self.overlay.status_message = Some("search continued".to_owned());
    }

    pub(super) fn toggle_timeout_choice(&mut self) {
        self.overlay.timeout_choice = match self.overlay.timeout_choice {
            TimeoutChoice::Continue => TimeoutChoice::Cancel,
            TimeoutChoice::Cancel => TimeoutChoice::Continue,
        };
    }

    pub(super) fn select_timeout_continue(&mut self) {
        self.overlay.timeout_choice = TimeoutChoice::Continue;
    }

    pub(super) fn select_timeout_cancel(&mut self) {
        self.overlay.timeout_choice = TimeoutChoice::Cancel;
    }

    pub(super) fn confirm_timeout_choice(&mut self) {
        match self.overlay.timeout_choice {
            TimeoutChoice::Continue => self.continue_timed_out_search(),
            TimeoutChoice::Cancel => self.cancel_timed_out_search(),
        }
    }

    pub(super) fn search_spinner(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame = self
            .tasks
            .search_started_at
            .map(|started_at| (started_at.elapsed().as_millis() / 80) as usize)
            .unwrap_or(0);
        FRAMES[frame % FRAMES.len()]
    }

    pub(super) fn selected(&self) -> Option<&CveSummaryWithDetail> {
        match self
            .main
            .list_state
            .selected()
            .and_then(|index| self.candidate(index))?
        {
            SearchCandidate::Cve(cve) => Some(cve),
            SearchCandidate::Osv(_) => None,
        }
    }

    pub(super) fn selected_metadata_capec_ids(&self) -> Option<&[i32]> {
        self.selected().and_then(|cve| {
            self.main
                .metadata_capec_ids
                .get(&cve.summary.cve_id)
                .map(Vec::as_slice)
        })
    }

    pub(super) fn selected_osv(&self) -> Option<&OsvSummary> {
        match self
            .main
            .list_state
            .selected()
            .and_then(|index| self.candidate(index))?
        {
            SearchCandidate::Cve(_) => None,
            SearchCandidate::Osv(osv) => Some(osv),
        }
    }

    pub(super) fn candidate_count(&self) -> usize {
        self.main.candidates.len()
    }

    pub(super) fn candidate(&self, index: usize) -> Option<&SearchCandidate> {
        self.main.candidates.get(index)
    }

    pub(super) fn toggle_raw_json_mode(&mut self, db: Option<CveDatabase>) {
        if self.raw.view_mode == ViewMode::RawJson {
            self.raw.view_mode = ViewMode::Normal;
            return;
        }
        self.raw.view_mode = ViewMode::RawJson;
        self.raw.scroll = 0;
        let Some(db) = db else {
            self.raw.json = Some("Database is unavailable".to_owned());
            return;
        };
        if let Some(task) = self.tasks.raw_json.take() {
            task.abort();
        }
        self.raw.json = Some("Loading".to_owned());
        self.tasks.raw_json = match (
            self.selected().map(|cve| cve.summary.cve_id.clone()),
            self.selected_osv().map(|osv| osv.osv_id.clone()),
        ) {
            (Some(cve_id), _) => Some(tokio::spawn(load_cve_raw_json(db, cve_id))),
            (_, Some(osv_id)) => Some(tokio::spawn(load_osv_raw_json(db, osv_id))),
            (None, None) => {
                self.raw.json = Some("No result selected".to_owned());
                None
            }
        };
    }

    pub(super) fn toggle_cwe_list_mode(&mut self, db: Option<CveDatabase>) {
        if self.raw.view_mode == ViewMode::CweList {
            self.raw.view_mode = ViewMode::Normal;
            return;
        }
        self.raw.view_mode = ViewMode::CweList;
        self.start_cwe_search(db);
    }

    pub(super) fn toggle_capec_list_mode(&mut self, db: Option<CveDatabase>) {
        if self.raw.view_mode == ViewMode::CapecList {
            self.raw.view_mode = ViewMode::Normal;
            return;
        }
        self.raw.view_mode = ViewMode::CapecList;
        self.start_capec_search(db);
    }

    pub(super) fn selected_capec(&self) -> Option<&CapecEntry> {
        self.capec.results.get(self.capec.selected)
    }

    pub(super) fn push_capec_query(&mut self, ch: char, db: Option<CveDatabase>) {
        self.capec.query.push(ch);
        self.start_capec_search(db);
    }

    pub(super) fn backspace_capec_query(&mut self, db: Option<CveDatabase>) {
        self.capec.query.pop();
        self.start_capec_search(db);
    }

    pub(super) fn move_capec(&mut self, down: bool, page_size: usize, step: usize) {
        if self.capec.results.is_empty() {
            return;
        }
        self.capec.selected = if down {
            self.capec
                .selected
                .saturating_add(step)
                .min(self.capec.results.len() - 1)
        } else {
            self.capec.selected.saturating_sub(step)
        };
        let page_size = page_size.max(1);
        if self.capec.selected < self.capec.scroll as usize {
            self.capec.scroll = self.capec.selected as u16;
        } else if self.capec.selected >= self.capec.scroll as usize + page_size {
            self.capec.scroll = self.capec.selected.saturating_sub(page_size - 1) as u16;
        }
        self.capec.detail_scroll = 0;
        self.capec.relation_return_path = None;
    }

    pub(super) fn move_capec_to_parent(&mut self, page_size: usize) {
        let Some(path) = self.capec.tree_paths.get(self.capec.selected).cloned() else {
            return;
        };
        if path.len() < 2 {
            self.overlay.status_message =
                Some("selected CAPEC has no parent on this path".to_owned());
            return;
        }
        let mut parent_path = path.clone();
        parent_path.pop();
        self.capec.relation_return_path = Some(path);
        self.select_capec_path(&parent_path, page_size);
    }

    pub(super) fn move_capec_to_relation_return(&mut self, page_size: usize) {
        let Some(path) = self.capec.relation_return_path.take() else {
            self.overlay.status_message = Some("no CAPEC relation return target".to_owned());
            return;
        };
        self.select_capec_path(&path, page_size);
    }

    pub(super) fn move_capec_sibling(&mut self, next: bool, page_size: usize) {
        let Some(path) = self.capec.tree_paths.get(self.capec.selected).cloned() else {
            return;
        };
        let parent = path.get(..path.len().saturating_sub(1)).unwrap_or_default();
        let candidates = self
            .capec
            .tree_paths
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                candidate.len() == path.len()
                    && candidate
                        .get(..candidate.len().saturating_sub(1))
                        .unwrap_or_default()
                        == parent
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let Some(position) = candidates
            .iter()
            .position(|index| *index == self.capec.selected)
        else {
            return;
        };
        let target = if next {
            candidates.get(position + 1)
        } else {
            position
                .checked_sub(1)
                .and_then(|index| candidates.get(index))
        };
        if let Some(target) = target {
            self.capec.selected = *target;
            self.scroll_capec_selection_into_view(page_size);
            self.capec.detail_scroll = 0;
            self.capec.relation_return_path = None;
        }
    }

    fn select_capec_path(&mut self, path: &[i32], page_size: usize) {
        if let Some(index) = self
            .capec
            .tree_paths
            .iter()
            .position(|candidate| candidate == path)
        {
            self.capec.selected = index;
            self.scroll_capec_selection_into_view(page_size);
            self.capec.detail_scroll = 0;
            self.overlay.status_message = None;
        }
    }

    fn scroll_capec_selection_into_view(&mut self, page_size: usize) {
        let page_size = page_size.max(1);
        if self.capec.selected < self.capec.scroll as usize {
            self.capec.scroll = self.capec.selected as u16;
        } else if self.capec.selected >= self.capec.scroll as usize + page_size {
            self.capec.scroll = self.capec.selected.saturating_sub(page_size - 1) as u16;
        }
    }

    pub(super) fn open_capec_filter(&mut self) {
        self.overlay.snapshots.capec_filter = Some((
            self.capec.status_filter.clone(),
            self.capec.type_filter.clone(),
            self.capec.cwe_filter.clone(),
        ));
        self.capec.show_filter = true;
    }

    pub(super) fn open_capec_taxonomy(&mut self, db: Option<CveDatabase>) {
        self.capec.show_taxonomy = true;
        self.capec.taxonomy_scroll = 0;
        self.capec.taxonomy_selected = 0;
        self.capec.taxonomy = None;
        if let Some(task) = self.tasks.capec_detail.take() {
            task.abort();
        }
        let Some((db, id)) = db.zip(self.selected_capec().map(|entry| entry.id)) else {
            return;
        };
        self.tasks.capec_detail = Some(tokio::spawn(async move {
            db.find_capec(id)
                .await
                .map_err(|error| format!("failed to load CAPEC-{id} classifications: {error}"))
        }));
    }

    pub(super) fn apply_capec_filter(&mut self, db: Option<CveDatabase>) {
        self.overlay.snapshots.capec_filter = None;
        self.capec.show_filter = false;
        self.start_capec_search(db);
    }

    pub(super) fn cancel_capec_filter(&mut self) {
        if let Some((status, abstraction, cwe)) = self.overlay.snapshots.capec_filter.take() {
            self.capec.status_filter = status;
            self.capec.type_filter = abstraction;
            self.capec.cwe_filter = cwe;
        }
        self.capec.show_filter = false;
    }

    pub(super) fn push_cwe_query(&mut self, ch: char, db: Option<CveDatabase>) {
        self.cwe.query.push(ch);
        self.start_cwe_search(db);
    }

    pub(super) fn backspace_cwe_query(&mut self, db: Option<CveDatabase>) {
        self.cwe.query.pop();
        self.start_cwe_search(db);
    }

    pub(super) fn selected_cwe_status_labels(&self) -> Vec<&'static str> {
        CWE_STATUSES
            .iter()
            .enumerate()
            .filter_map(|(index, status)| self.cwe.status_filter[index].then_some(status.label()))
            .collect()
    }

    pub(super) fn cwe_status_summary(&self) -> String {
        let labels = self.selected_cwe_status_labels();
        if labels.is_empty() {
            "none".to_owned()
        } else {
            labels.join("|")
        }
    }

    pub(super) fn open_cwe_status_popup(&mut self) {
        self.overlay.snapshots.cwe_filter =
            Some((self.cwe.status_filter, self.cwe.capec_filter.clone()));
        self.cwe.show_status = true;
    }

    pub(super) fn cancel_cwe_status_popup(&mut self) {
        if let Some((statuses, capec)) = self.overlay.snapshots.cwe_filter.take() {
            self.cwe.status_filter = statuses;
            self.cwe.capec_filter = capec;
        }
        self.cwe.show_status = false;
    }

    pub(super) fn apply_cwe_filters(&mut self, db: Option<CveDatabase>) {
        self.overlay.snapshots.cwe_filter = None;
        self.cwe.show_status = false;
        self.start_cwe_search(db);
    }

    pub(super) fn next_cwe_status(&mut self) {
        self.cwe.status_cursor = (self.cwe.status_cursor + 1) % CWE_STATUS_CONTROL_COUNT;
    }

    pub(super) fn previous_cwe_status(&mut self) {
        self.cwe.status_cursor = if self.cwe.status_cursor == 0 {
            CWE_STATUS_CONTROL_COUNT - 1
        } else {
            self.cwe.status_cursor - 1
        };
    }

    pub(super) fn toggle_current_cwe_status(&mut self) {
        match self.cwe.status_cursor {
            0..CWE_STATUS_COUNT => {
                self.cwe.status_filter[self.cwe.status_cursor] =
                    !self.cwe.status_filter[self.cwe.status_cursor];
            }
            CWE_STATUS_SELECT_ALL_CURSOR => self.cwe.status_filter = [true; CWE_STATUS_COUNT],
            CWE_STATUS_CLEAR_ALL_CURSOR => self.cwe.status_filter = [false; CWE_STATUS_COUNT],
            _ => {}
        }
    }

    pub(super) fn select_all_cwe_statuses(&mut self) {
        self.cwe.status_filter = [true; CWE_STATUS_COUNT];
    }

    pub(super) fn clear_all_cwe_statuses(&mut self) {
        self.cwe.status_filter = [false; CWE_STATUS_COUNT];
    }

    pub(super) fn activate_cwe_status_control(&mut self) -> bool {
        match self.cwe.status_cursor {
            CWE_STATUS_SELECT_ALL_CURSOR => {
                self.select_all_cwe_statuses();
                true
            }
            CWE_STATUS_CLEAR_ALL_CURSOR => {
                self.clear_all_cwe_statuses();
                true
            }
            _ => false,
        }
    }

    pub(super) fn push_cwe_capec_filter(&mut self, ch: char) {
        self.cwe.capec_filter.push(ch);
    }

    pub(super) fn backspace_cwe_capec_filter(&mut self) {
        self.cwe.capec_filter.pop();
    }

    pub(super) fn selected_cwe(&self) -> Option<&CweEntry> {
        self.cwe.results.get(self.cwe.selected)
    }

    pub(super) fn start_detail_search(&mut self) {
        self.overlay.detail_search_input = true;
        self.overlay.detail_search_error = None;
    }

    pub(super) fn close_detail_search(&mut self) {
        self.overlay.detail_search_input = false;
        self.overlay.detail_search_error = None;
    }

    pub(super) fn push_detail_search(&mut self, ch: char) {
        self.overlay.detail_search_query.push(ch);
        self.overlay.detail_search_error = None;
    }

    pub(super) fn backspace_detail_search(&mut self) {
        self.overlay.detail_search_query.pop();
        self.overlay.detail_search_error = None;
    }

    pub(super) fn set_page_sizes(
        &mut self,
        left: usize,
        right: usize,
        metadata: usize,
        detail_width: usize,
        metadata_width: usize,
    ) {
        self.main.left_page_size = left.max(MIN_PAGE_SIZE);
        self.main.right_page_size = right.max(MIN_PAGE_SIZE);
        self.main.metadata_page_size = metadata.max(MIN_PAGE_SIZE);
        self.main.detail_content_width = detail_width.max(MIN_PAGE_SIZE);
        self.main.metadata_content_width = metadata_width.max(MIN_PAGE_SIZE);
        self.clamp_detail_scroll();
        self.clamp_metadata_scroll();
    }

    pub(super) fn toggle_focus(&mut self) {
        self.main.focus = match self.main.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn toggle_cwe_focus(&mut self) {
        self.main.focus = match self.main.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn previous_focus(&mut self) {
        self.main.focus = match self.main.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn next_right_tab(&mut self) {
        self.main.right_tab = if self.selected_osv().is_some() {
            match self.main.right_tab {
                RightPaneTab::Cve | RightPaneTab::Osv => RightPaneTab::Metadata,
                RightPaneTab::Metadata => RightPaneTab::Enrichment,
                RightPaneTab::Enrichment => RightPaneTab::Cve,
            }
        } else {
            self.main.right_tab.next()
        };
        self.reset_main_view_scroll();
    }

    pub(super) fn previous_right_tab(&mut self) {
        self.main.right_tab = if self.selected_osv().is_some() {
            match self.main.right_tab {
                RightPaneTab::Cve | RightPaneTab::Osv => RightPaneTab::Enrichment,
                RightPaneTab::Metadata => RightPaneTab::Cve,
                RightPaneTab::Enrichment => RightPaneTab::Metadata,
            }
        } else {
            self.main.right_tab.previous()
        };
        self.reset_main_view_scroll();
    }

    pub(super) fn next_or_load_more(&mut self, db: CveDatabase) {
        let candidate_count = self.candidate_count();
        if candidate_count == 0 {
            self.main.list_state.select(None);
            return;
        }
        let current = self.main.list_state.selected().unwrap_or(0);
        if current + 1 >= candidate_count {
            self.start_load_more(db);
            return;
        }
        let next = self
            .main
            .list_state
            .selected()
            .map(|index| (index + 1).min(candidate_count - 1))
            .unwrap_or(0);
        if next != current {
            self.main.list_state.select(Some(next));
            self.reset_main_view_scroll();
        }
    }

    pub(super) fn move_focused_down(&mut self, db: CveDatabase) {
        match self.main.focus {
            PaneFocus::Left => self.next_or_load_more(db),
            PaneFocus::Right => {
                if self.main.right_tab == RightPaneTab::Cve {
                    self.main.detail_scroll = self.main.detail_scroll.saturating_add(1);
                    self.clamp_detail_scroll();
                } else {
                    self.main.metadata_scroll = self.main.metadata_scroll.saturating_add(1);
                    self.clamp_metadata_scroll();
                }
            }
        }
    }

    pub(super) fn move_focused_up(&mut self) {
        match self.main.focus {
            PaneFocus::Left => self.previous(),
            PaneFocus::Right => {
                if self.main.right_tab == RightPaneTab::Cve {
                    self.main.detail_scroll = self.main.detail_scroll.saturating_sub(1);
                    self.clamp_detail_scroll();
                } else {
                    self.main.metadata_scroll = self.main.metadata_scroll.saturating_sub(1);
                    self.clamp_metadata_scroll();
                }
            }
        }
    }

    pub(super) fn move_half_page_down(&mut self, db: CveDatabase) {
        self.move_focused_page(db, PageDirection::Down, PageAmount::Half);
    }

    pub(super) fn move_half_page_up(&mut self) {
        self.move_focused_page_without_db(PageDirection::Up, PageAmount::Half);
    }

    pub(super) fn move_full_page_down(&mut self, db: CveDatabase) {
        self.move_focused_page(db, PageDirection::Down, PageAmount::Full);
    }

    pub(super) fn move_full_page_up(&mut self) {
        self.move_focused_page_without_db(PageDirection::Up, PageAmount::Full);
    }

    pub(super) fn previous(&mut self) {
        if self.candidate_count() == 0 {
            self.main.list_state.select(None);
            return;
        }
        let previous = self
            .main
            .list_state
            .selected()
            .map(|index| index.saturating_sub(1))
            .unwrap_or(0);
        if self.main.list_state.selected() != Some(previous) {
            self.main.list_state.select(Some(previous));
            self.reset_main_view_scroll();
        }
    }

    pub(super) fn scroll_detail_to_top(&mut self) {
        self.main.detail_scroll = 0;
    }

    pub(super) fn next_search_mode(&mut self) {
        self.main.search_mode = self.main.search_mode.next();
        self.main.search_mode_explicit = true;
        self.sync_advanced_from_main();
    }

    pub(super) fn previous_search_mode(&mut self) {
        self.main.search_mode = self.main.search_mode.previous();
        self.main.search_mode_explicit = true;
        self.sync_advanced_from_main();
    }

    pub(super) fn push_query(&mut self, ch: char) {
        self.main.query.push(ch);
        self.scroll_detail_to_top();
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
    }

    pub(super) fn backspace_query(&mut self) {
        self.main.query.pop();
        self.scroll_detail_to_top();
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
    }

    pub(super) fn move_raw_down(&mut self, line_count: usize, page_size: usize) {
        self.raw.scroll = self.raw.scroll.saturating_add(1);
        self.raw.scroll = self
            .raw
            .scroll
            .min(line_count.saturating_sub(page_size.max(MIN_PAGE_SIZE)) as u16);
    }

    pub(super) fn move_raw_up(&mut self) {
        self.raw.scroll = self.raw.scroll.saturating_sub(1);
    }

    pub(super) fn move_raw_page_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.raw.scroll = self
            .raw
            .scroll
            .saturating_add(page_size as u16)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_raw_page_up(&mut self, page_size: usize) {
        self.raw.scroll = self
            .raw
            .scroll
            .saturating_sub(page_size.max(MIN_PAGE_SIZE) as u16);
    }

    pub(super) fn move_cwe_down(&mut self, page_size: usize) {
        self.move_cwe_page(PageDirection::Down, 1, page_size);
    }

    pub(super) fn move_cwe_up(&mut self, page_size: usize) {
        self.move_cwe_page(PageDirection::Up, 1, page_size);
    }

    pub(super) fn move_cwe_half_page_down(&mut self, page_size: usize) {
        self.move_cwe_page(
            PageDirection::Down,
            (page_size / 2).max(MIN_PAGE_SIZE),
            page_size,
        );
    }

    pub(super) fn move_cwe_half_page_up(&mut self, page_size: usize) {
        self.move_cwe_page(
            PageDirection::Up,
            (page_size / 2).max(MIN_PAGE_SIZE),
            page_size,
        );
    }

    pub(super) fn move_cwe_full_page_down(&mut self, page_size: usize) {
        self.move_cwe_page(PageDirection::Down, page_size.max(MIN_PAGE_SIZE), page_size);
    }

    pub(super) fn move_cwe_full_page_up(&mut self, page_size: usize) {
        self.move_cwe_page(PageDirection::Up, page_size.max(MIN_PAGE_SIZE), page_size);
    }

    pub(super) fn move_cwe_to_parent(&mut self, page_size: usize) {
        self.cwe.relation_return_id = None;
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let Some(parent_id) = selected.parent_id else {
            self.overlay.status_message = Some("selected CWE has no parent".to_owned());
            return;
        };
        let return_id = selected.id;
        if !self.select_cwe_by_id(parent_id, page_size) {
            self.overlay.status_message =
                Some(format!("parent CWE-{parent_id} is not in current results"));
            return;
        }
        self.cwe.relation_return_id = Some(return_id);
    }

    pub(super) fn move_cwe_to_relation_return(&mut self, page_size: usize) {
        let Some(return_id) = self.cwe.relation_return_id.take() else {
            self.overlay.status_message = Some("no CWE relation return target".to_owned());
            return;
        };
        if !self.select_cwe_by_id(return_id, page_size) {
            self.overlay.status_message = Some(format!(
                "return target CWE-{return_id} is not in current results"
            ));
        }
    }

    pub(super) fn move_cwe_to_previous_sibling(&mut self, page_size: usize) {
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let sibling_id = self
            .cwe
            .results
            .iter()
            .filter(|cwe| cwe.parent_id == selected.parent_id && cwe.id < selected.id)
            .map(|cwe| cwe.id)
            .max();
        let Some(sibling_id) = sibling_id else {
            self.overlay.status_message =
                Some("selected CWE has no previous sibling in current results".to_owned());
            return;
        };
        self.cwe.relation_return_id = None;
        self.select_cwe_by_id(sibling_id, page_size);
    }

    pub(super) fn move_cwe_to_next_sibling(&mut self, page_size: usize) {
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let sibling_id = self
            .cwe
            .results
            .iter()
            .filter(|cwe| cwe.parent_id == selected.parent_id && cwe.id > selected.id)
            .map(|cwe| cwe.id)
            .min();
        let Some(sibling_id) = sibling_id else {
            self.overlay.status_message =
                Some("selected CWE has no next sibling in current results".to_owned());
            return;
        };
        self.cwe.relation_return_id = None;
        self.select_cwe_by_id(sibling_id, page_size);
    }

    fn select_cwe_by_id(&mut self, id: i32, page_size: usize) -> bool {
        let Some(index) = self.cwe.results.iter().position(|cwe| cwe.id == id) else {
            return false;
        };
        self.cwe.selected = index;
        self.scroll_cwe_selection_into_view(page_size);
        self.cwe.detail_scroll = 0;
        self.overlay.status_message = None;
        true
    }

    fn move_cwe_page(&mut self, direction: PageDirection, step: usize, page_size: usize) {
        if self.cwe.results.is_empty() {
            self.cwe.selected = 0;
            self.cwe.scroll = 0;
            self.cwe.detail_scroll = 0;
            return;
        }

        self.cwe.selected = match direction {
            PageDirection::Up => self.cwe.selected.saturating_sub(step),
            PageDirection::Down => self
                .cwe
                .selected
                .saturating_add(step)
                .min(self.cwe.results.len() - 1),
        };
        self.scroll_cwe_selection_into_view(page_size);
        self.cwe.detail_scroll = 0;
        self.cwe.relation_return_id = None;
    }

    fn scroll_cwe_selection_into_view(&mut self, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        if self.cwe.selected < self.cwe.scroll as usize {
            self.cwe.scroll = self.cwe.selected as u16;
        } else if self.cwe.selected >= self.cwe.scroll as usize + page_size {
            self.cwe.scroll =
                self.cwe
                    .selected
                    .saturating_sub(page_size - 1)
                    .min(self.cwe.results.len().saturating_sub(page_size)) as u16;
        }
        self.clamp_cwe_scroll(page_size);
    }

    fn clamp_cwe_scroll(&mut self, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        let max_scroll = self.cwe.results.len().saturating_sub(page_size) as u16;
        self.cwe.scroll = self.cwe.scroll.min(max_scroll);
    }

    pub(super) fn move_cwe_detail_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.cwe.detail_scroll = self
            .cwe
            .detail_scroll
            .saturating_add(1)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_cwe_detail_up(&mut self) {
        self.cwe.detail_scroll = self.cwe.detail_scroll.saturating_sub(1);
    }

    pub(super) fn move_cwe_detail_page_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.cwe.detail_scroll = self
            .cwe
            .detail_scroll
            .saturating_add(page_size as u16)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_cwe_detail_page_up(&mut self, page_size: usize) {
        self.cwe.detail_scroll = self
            .cwe
            .detail_scroll
            .saturating_sub(page_size.max(MIN_PAGE_SIZE) as u16);
    }

    pub(super) fn sync_main_from_advanced(&mut self) {
        self.main.query = self.main.advanced.query.clone();
        self.main.search_mode = self.main.advanced.query_mode;
        self.main.search_mode_explicit = true;
        self.main.state_scope = self.main.advanced.state_scope;
        self.scroll_detail_to_top();
    }

    pub(super) fn sync_advanced_from_main(&mut self) {
        self.main.advanced.query = self.main.query.clone();
        self.main.advanced.query_mode = self.main.search_mode;
        self.main.advanced.state_scope = self.main.state_scope;
    }

    pub(super) fn apply_prefix_mode(&mut self) {
        if self.main.search_mode_explicit {
            return;
        }
        self.main.search_mode =
            SearchMode::from_query_prefix(&self.main.query).unwrap_or(SearchMode::FreeText);
    }

    fn main_search_options(&self, sort_order: CveSummarySortOrder) -> CveAdvancedSearch {
        CveAdvancedSearch {
            query: option_string(&self.main.query),
            query_mode: Some(self.main.search_mode.into()),
            published_from: None,
            published_to: None,
            cwe: None,
            product: None,
            product_exact: None,
            package_ecosystem: None,
            package_version: None,
            vendor: None,
            vendor_exact: None,
            kev_only: self.main.display.kev_only,
            state_scope: self.main.state_scope,
            sort_order,
        }
    }

    fn start_replace_search(
        &mut self,
        db: CveDatabase,
        request: SearchRequest,
        error_prefix: &str,
    ) {
        self.main.exhausted = false;
        self.main.total_results = None;
        self.start_pending_search(
            db,
            request,
            self.main.limit,
            0,
            SearchKind::Replace,
            error_prefix,
        );
    }

    fn start_pending_search(
        &mut self,
        db: CveDatabase,
        request: SearchRequest,
        limit: u64,
        offset: u64,
        kind: SearchKind,
        error_prefix: &str,
    ) {
        self.abort_search();
        self.overlay.status_message = None;
        self.arm_search_timeout();
        let count = (matches!(&kind, SearchKind::Replace) && request.should_count()).then(|| {
            PendingCount {
                db: db.clone(),
                request: request.clone(),
            }
        });
        let continuation =
            matches!(&kind, SearchKind::Append { .. }).then_some(self.main.search_continuation);
        let error_prefix = error_prefix.to_owned();
        self.tasks.search = Some(PendingSearch {
            kind,
            count,
            timed_out_once: false,
            handle: tokio::spawn(async move {
                let result = if let Some(continuation) = continuation {
                    run_search_request_after(db, request, limit, continuation).await
                } else {
                    run_search_request(db, request, limit, offset).await
                };
                result.map_err(|err| format!("{error_prefix}: {err}"))
            }),
        });
    }

    fn start_cwe_search(&mut self, db: Option<CveDatabase>) {
        if let Some(task) = self.tasks.cwe.take() {
            task.abort();
        }
        self.cwe.scroll = 0;
        self.cwe.relation_return_id = None;
        let Some(db) = db else {
            self.overlay.status_message = Some("database is unavailable".to_owned());
            self.cwe.results.clear();
            return;
        };
        let query = self.cwe.query.clone();
        let statuses = self
            .selected_cwe_status_labels()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let capec_id = self
            .cwe
            .capec_filter
            .trim()
            .trim_start_matches("CAPEC-")
            .parse()
            .ok();
        self.tasks.cwe = Some(tokio::spawn(search_cwe_entries(
            db, query, statuses, capec_id,
        )));
    }

    fn start_capec_search(&mut self, db: Option<CveDatabase>) {
        if !self.capec.catalog.is_empty() {
            self.apply_capec_filters();
            return;
        }
        if self.tasks.capec.is_some() {
            return;
        }
        let Some(db) = db else {
            self.capec.results.clear();
            self.capec.tree_paths.clear();
            self.capec.tree_prefixes.clear();
            return;
        };
        self.tasks.capec = Some(tokio::spawn(search_capec_entries(
            db,
            CapecSearchFilters::default(),
        )));
    }

    fn apply_capec_filters(&mut self) {
        let query = self.capec.query.trim().to_ascii_lowercase();
        let status = self.capec.status_filter.trim();
        let abstraction = self.capec.type_filter.trim();
        let cwe_id = self
            .capec
            .cwe_filter
            .trim()
            .trim_start_matches("CWE-")
            .parse::<i32>()
            .ok();
        let matched = self
            .capec
            .catalog
            .iter()
            .filter(|entry| {
                (query.is_empty()
                    || entry.id.to_string() == query
                    || format!("capec-{}", entry.id) == query
                    || entry.name.to_ascii_lowercase().contains(&query)
                    || entry.description.to_ascii_lowercase().contains(&query)
                    || entry
                        .extended_description
                        .as_deref()
                        .is_some_and(|text| text.to_ascii_lowercase().contains(&query)))
                    && (status.is_empty() || entry.status.eq_ignore_ascii_case(status))
                    && (abstraction.is_empty()
                        || entry.abstraction.eq_ignore_ascii_case(abstraction))
                    && cwe_id.is_none_or(|id| entry.cwe_ids.contains(&id))
            })
            .map(|entry| entry.id)
            .collect::<HashSet<_>>();
        let tree = filter_capec_tree(project_capec_tree(self.capec.catalog.clone()), &matched);
        self.capec.results = tree.entries;
        self.capec.tree_paths = tree.paths;
        self.capec.tree_prefixes = tree.prefixes;
        self.capec.scroll = 0;
        self.capec.selected = 0;
        self.capec.detail_scroll = 0;
        self.capec.relation_return_path = None;
    }

    fn move_focused_page(&mut self, db: CveDatabase, direction: PageDirection, amount: PageAmount) {
        match self.main.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, Some(db)),
            PaneFocus::Right => self.move_right_page(direction, amount),
        }
    }

    fn move_focused_page_without_db(&mut self, direction: PageDirection, amount: PageAmount) {
        match self.main.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, None),
            PaneFocus::Right => self.move_right_page(direction, amount),
        }
    }

    fn move_right_page(&mut self, direction: PageDirection, amount: PageAmount) {
        if self.main.right_tab == RightPaneTab::Cve {
            self.move_detail_page(direction, amount);
        } else {
            self.move_metadata_page(direction, amount);
        }
    }

    fn move_candidate_page(
        &mut self,
        direction: PageDirection,
        amount: PageAmount,
        db: Option<CveDatabase>,
    ) {
        let candidate_count = self.candidate_count();
        if candidate_count == 0 {
            self.main.list_state.select(None);
            return;
        }

        let current = self.main.list_state.selected().unwrap_or(0);
        let step = self.left_step(amount);
        let next = match direction {
            PageDirection::Up => current.saturating_sub(step),
            PageDirection::Down => current.saturating_add(step).min(candidate_count - 1),
        };
        if next != current {
            self.main.list_state.select(Some(next));
            self.reset_main_view_scroll();
        }
        if matches!(direction, PageDirection::Down)
            && next + 1 >= candidate_count
            && let Some(db) = db
        {
            self.start_load_more(db);
        }
    }

    fn move_detail_page(&mut self, direction: PageDirection, amount: PageAmount) {
        let step = self.right_step(amount) as u16;
        self.main.detail_scroll = match direction {
            PageDirection::Up => self.main.detail_scroll.saturating_sub(step),
            PageDirection::Down => self.main.detail_scroll.saturating_add(step),
        };
        self.clamp_detail_scroll();
    }

    fn move_metadata_page(&mut self, direction: PageDirection, amount: PageAmount) {
        let step = self.metadata_step(amount) as u16;
        self.main.metadata_scroll = match direction {
            PageDirection::Up => self.main.metadata_scroll.saturating_sub(step),
            PageDirection::Down => self.main.metadata_scroll.saturating_add(step),
        };
        self.clamp_metadata_scroll();
    }

    pub(super) fn clamp_detail_scroll(&mut self) {
        self.main.detail_scroll = self.main.detail_scroll.min(self.max_detail_scroll());
    }

    pub(super) fn clamp_metadata_scroll(&mut self) {
        self.main.metadata_scroll = self.main.metadata_scroll.min(self.max_metadata_scroll());
    }

    fn max_detail_scroll(&self) -> u16 {
        let line_count = if let Some(cve) = self.selected() {
            Paragraph::new(crate::modes::main::detail::detail_lines(
                cve,
                self.main.display.timezone,
                &crate::common::DetailSearch::new(""),
                self.main.detail_content_width,
            ))
            .wrap(Wrap { trim: false })
            .line_count(self.main.detail_content_width.min(u16::MAX as usize) as u16)
        } else if let Some(osv) = self.selected_osv() {
            Paragraph::new(crate::modes::main::detail::osv_detail_lines(
                osv,
                self.main.display.timezone,
                &crate::common::DetailSearch::new(""),
                self.main.detail_content_width,
            ))
            .wrap(Wrap { trim: false })
            .line_count(self.main.detail_content_width.min(u16::MAX as usize) as u16)
        } else {
            1
        };
        line_count.saturating_sub(self.main.right_page_size) as u16
    }

    fn max_metadata_scroll(&self) -> u16 {
        let line_count = if self.main.right_tab == RightPaneTab::Cve {
            1
        } else {
            Paragraph::new(crate::modes::main::right::tab_lines(
                self,
                self.main.right_tab,
                &crate::common::DetailSearch::new(""),
                self.main.metadata_content_width,
            ))
            .wrap(Wrap { trim: true })
            .line_count(self.main.metadata_content_width.min(u16::MAX as usize) as u16)
        };
        line_count.saturating_sub(self.main.metadata_page_size) as u16
    }

    fn left_step(&self, amount: PageAmount) -> usize {
        let visible_candidates = (self.main.left_page_size / 2).max(MIN_PAGE_SIZE);
        match amount {
            PageAmount::Half => (visible_candidates / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => visible_candidates,
        }
    }

    fn right_step(&self, amount: PageAmount) -> usize {
        match amount {
            PageAmount::Half => (self.main.right_page_size / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => self.main.right_page_size.max(MIN_PAGE_SIZE),
        }
    }

    fn metadata_step(&self, amount: PageAmount) -> usize {
        match amount {
            PageAmount::Half => (self.main.metadata_page_size / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => self.main.metadata_page_size.max(MIN_PAGE_SIZE),
        }
    }

    fn clear_detail(&mut self) {
        self.main.detail_scroll = 0;
        self.main.metadata_scroll = 0;
        self.main.enrichment.clear();
        if let Some(task) = self.tasks.enrichment.take() {
            task.handle.abort();
        }
        self.main.metadata_capec_ids.clear();
        if let Some(task) = self.tasks.metadata_capec.take() {
            task.handle.abort();
        }
    }

    fn select_candidate(&mut self, index: usize) {
        let candidate_count = self.candidate_count();
        if candidate_count == 0 {
            self.main.list_state.select(None);
        } else {
            self.main
                .list_state
                .select(Some(index.min(candidate_count - 1)));
        }
        self.reset_main_view_scroll();
    }

    fn reset_main_view_scroll(&mut self) {
        self.main.detail_scroll = 0;
        self.main.metadata_scroll = 0;
    }

    fn finish_failed_search(&mut self, message: String) {
        self.tasks.search_started_at = None;
        self.tasks.search_timeout_at = None;
        self.overlay.show_timeout_prompt = false;
        self.overlay.status_message = Some(message);
    }

    fn arm_search_timeout(&mut self) {
        let now = Instant::now();
        self.tasks.search_started_at = Some(now);
        self.tasks.search_timeout_at = Some(now + SEARCH_TIMEOUT);
        self.overlay.show_timeout_prompt = false;
        self.overlay.timeout_choice = TimeoutChoice::Continue;
    }

    fn check_search_timeout(&mut self) {
        let Some(timeout_at) = self.tasks.search_timeout_at else {
            return;
        };
        if Instant::now() < timeout_at {
            return;
        }
        let Some(search) = self.tasks.search.as_mut() else {
            return;
        };
        if search.timed_out_once {
            search.handle.abort();
            self.tasks.search = None;
            self.tasks.search_started_at = None;
            self.tasks.search_timeout_at = None;
            self.overlay.show_timeout_prompt = false;
            self.overlay.status_message = Some(format!(
                "search timed out after {} seconds",
                SEARCH_TIMEOUT.as_secs() * 2
            ));
        } else {
            self.overlay.show_timeout_prompt = true;
            self.overlay.timeout_choice = TimeoutChoice::Continue;
        }
    }
}

#[derive(Clone, Copy)]
enum PageDirection {
    Up,
    Down,
}

#[derive(Clone, Copy)]
enum PageAmount {
    Half,
    Full,
}

fn option_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn default_cwe_status_filter() -> [bool; CWE_STATUS_COUNT] {
    let mut filter = [false; CWE_STATUS_COUNT];
    filter[0] = true;
    filter
}
