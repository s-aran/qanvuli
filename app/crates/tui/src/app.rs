use super::{
    SEARCH_TIMEOUT, TUI_LOAD_MORE_LIMIT,
    db::{
        cwe::search_cwe_entries,
        raw_json::{load_cve_raw_json, load_osv_raw_json},
        search::{SearchRequest, SearchResult, run_count_request, run_search_request},
    },
    display::DisplaySettings,
    form::AdvancedForm,
    mode::SearchMode,
    utils::text::{normalize_spaces, wrapped_line_count},
};
use qanvuli_app_commands::common::IngestProgress;
use qanvuli_core::database::{
    CveAdvancedSearch, CveDatabase, CveStateScope, CveSummarySortOrder, CveSummaryWithDetail,
    CweEntry, EnrichedCveSummary, OsvSummary,
};
use ratatui::widgets::{ListState, Paragraph, Wrap};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::{sync::mpsc::UnboundedReceiver, task::JoinHandle};

const MIN_PAGE_SIZE: usize = 1;
const OSV_IMPORT_ID_PREFIXES_METADATA_KEY: &str = "osv_import_id_prefixes";
pub(super) const CWE_STATUS_COUNT: usize = 6;
const CWE_STATUS_CONTROL_COUNT: usize = CWE_STATUS_COUNT + 2;
const CWE_STATUS_SELECT_ALL_CURSOR: usize = CWE_STATUS_COUNT;
const CWE_STATUS_CLEAR_ALL_CURSOR: usize = CWE_STATUS_COUNT + 1;
pub(super) const CWE_STATUSES: [CweStatus; CWE_STATUS_COUNT] = [
    CweStatus::Stable,
    CweStatus::Usable,
    CweStatus::Draft,
    CweStatus::Incomplete,
    CweStatus::Obsolete,
    CweStatus::Deprecated,
];

pub(super) struct App {
    pub(super) query: String,
    pub(super) search_mode: SearchMode,
    pub(super) state_scope: CveStateScope,
    pub(super) advanced: AdvancedForm,
    pub(super) display: DisplaySettings,
    pub(super) limit: u64,
    search_offset: u64,
    pub(super) results: Vec<CveSummaryWithDetail>,
    pub(super) osv_results: Vec<OsvSummary>,
    pub(super) linked_osv: HashMap<String, Vec<OsvSummary>>,
    pub(super) total_results: Option<u64>,
    pub(super) list_state: ListState,
    pub(super) focus: PaneFocus,
    pub(super) right_tab: RightPaneTab,
    pub(super) detail_scroll: u16,
    pub(super) metadata_scroll: u16,
    pub(super) view_mode: ViewMode,
    pub(super) raw_json: Option<String>,
    pub(super) raw_scroll: u16,
    pub(super) cwe_query: String,
    pub(super) cwe_results: Vec<CweEntry>,
    pub(super) cwe_scroll: u16,
    pub(super) cwe_selected: usize,
    pub(super) cwe_detail_scroll: u16,
    pub(super) cwe_relation_return_id: Option<i32>,
    pub(super) cwe_status_filter: [bool; CWE_STATUS_COUNT],
    pub(super) cwe_status_cursor: usize,
    pub(super) show_cwe_status: bool,
    pub(super) detail_search_query: String,
    pub(super) detail_search_input: bool,
    pub(super) detail_search_error: Option<String>,
    search: Option<PendingSearch>,
    count_task: Option<JoinHandle<Result<u64, String>>>,
    raw_json_task: Option<JoinHandle<Result<String, String>>>,
    pub(super) enrichment: HashMap<String, EnrichedCveSummary>,
    enrichment_task: Option<PendingEnrichment>,
    cwe_task: Option<JoinHandle<Result<Vec<CweEntry>, String>>>,
    scope_task: Option<JoinHandle<Result<Vec<String>, String>>>,
    search_started_at: Option<Instant>,
    search_timeout_at: Option<Instant>,
    searched_request: SearchRequest,
    exhausted: bool,
    left_page_size: usize,
    right_page_size: usize,
    metadata_page_size: usize,
    detail_content_width: usize,
    metadata_content_width: usize,
    pub(super) show_help: bool,
    pub(super) show_advanced: bool,
    pub(super) show_display: bool,
    pub(super) show_timeout_prompt: bool,
    pub(super) show_maintenance: bool,
    pub(super) timeout_choice: TimeoutChoice,
    pub(super) maintenance_choice: MaintenanceChoice,
    pub(super) maintenance_keep_downloads: bool,
    pub(super) status_message: Option<String>,
    pub(super) db_as_of: Option<String>,
    pub(super) maintenance_progress: Option<MaintenanceProgress>,
    maintenance: Option<PendingMaintenance>,
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
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        let search_mode = SearchMode::from_query_prefix(&query).unwrap_or(SearchMode::FreeText);
        let mut app = Self {
            query,
            search_mode,
            state_scope: CveStateScope::PublishedOnly,
            advanced: AdvancedForm::default(),
            display: DisplaySettings::default(),
            limit,
            search_offset: 0,
            results: Vec::new(),
            osv_results: Vec::new(),
            linked_osv: HashMap::new(),
            total_results: None,
            list_state,
            focus: PaneFocus::Left,
            right_tab: RightPaneTab::Cve,
            detail_scroll: 0,
            metadata_scroll: 0,
            view_mode: ViewMode::Normal,
            raw_json: None,
            raw_scroll: 0,
            enrichment: HashMap::new(),
            enrichment_task: None,
            cwe_query: String::new(),
            cwe_results: Vec::new(),
            cwe_scroll: 0,
            cwe_selected: 0,
            cwe_detail_scroll: 0,
            cwe_relation_return_id: None,
            cwe_status_filter: default_cwe_status_filter(),
            cwe_status_cursor: 0,
            show_cwe_status: false,
            detail_search_query: String::new(),
            detail_search_input: false,
            detail_search_error: None,
            search: None,
            count_task: None,
            raw_json_task: None,
            cwe_task: None,
            scope_task: None,
            search_started_at: None,
            search_timeout_at: None,
            searched_request: SearchRequest::Mode {
                mode: search_mode,
                query: String::new(),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
            },
            exhausted: false,
            left_page_size: 10,
            right_page_size: 10,
            metadata_page_size: 10,
            detail_content_width: 80,
            metadata_content_width: 80,
            show_help: false,
            show_advanced: false,
            show_display: false,
            show_timeout_prompt: false,
            show_maintenance: false,
            timeout_choice: TimeoutChoice::Continue,
            maintenance_choice: MaintenanceChoice::Update,
            maintenance_keep_downloads: false,
            status_message: None,
            db_as_of: None,
            maintenance_progress: None,
            maintenance: None,
        };
        app.sync_advanced_from_main();
        app
    }

    pub(super) fn start_search(&mut self, db: CveDatabase) {
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
        let sort_order = self.display.sort_order();
        let request = if self.search_mode == SearchMode::Identifier && !self.query.trim().is_empty()
        {
            SearchRequest::Mode {
                mode: self.search_mode,
                query: self.query.clone(),
                state_scope: self.state_scope,
                kev_only: self.display.kev_only,
            }
        } else {
            SearchRequest::Advanced {
                options: self.main_search_options(sort_order),
                include_cve: true,
                // Empty Enter is the TUI's browse-all action. Do not append every OSV
                // advisory to that CVE list.
                include_osv: !self.query.trim().is_empty(),
                osv_families: Vec::new(),
                ecosystems: None,
            }
        };
        self.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn start_advanced_search(&mut self, db: CveDatabase) {
        self.query = self.advanced.query.clone();
        self.search_mode = self.advanced.query_mode;
        self.state_scope = self.advanced.state_scope;
        let mut options = self.advanced.to_search_options(self.display.sort_order());
        options.kev_only = self.display.kev_only;
        let ecosystems = options
            .package_ecosystem
            .as_deref()
            .map(str::trim)
            .filter(|ecosystem| !ecosystem.is_empty())
            .map(|ecosystem| vec![ecosystem.to_owned()]);
        let request = SearchRequest::Advanced {
            options,
            include_cve: self.advanced.source_cve,
            include_osv: self.advanced.source_osv,
            osv_families: if self.advanced.source_osv {
                self.advanced.selected_advisories()
            } else {
                Vec::new()
            },
            ecosystems,
        };
        self.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn open_advanced_search(&mut self, db: Option<CveDatabase>) {
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
        self.load_scope_candidates(db);
        self.show_advanced = true;
    }

    pub(super) fn load_scope_candidates(&mut self, db: Option<CveDatabase>) {
        if self.scope_task.is_some() {
            return;
        }
        let Some(db) = db else {
            return;
        };
        self.scope_task = Some(tokio::spawn(async move {
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
        self.display.source_focus = false;
        self.display.scroll = 0;
        self.show_display = true;
    }

    pub(super) fn start_load_more(&mut self, db: CveDatabase) {
        if self.searching() || self.exhausted || self.candidate_count() == 0 {
            return;
        }

        let request = self.searched_request.clone();
        let offset = self.search_offset;
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
        let Some(search) = self.search.as_ref() else {
            return Ok(());
        };
        if !search.handle.is_finished() {
            self.check_search_timeout();
            return Ok(());
        }

        let Some(search) = self.search.take() else {
            self.status_message = Some("search task disappeared".to_owned());
            self.search_started_at = None;
            self.search_timeout_at = None;
            self.show_timeout_prompt = false;
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
        self.search_started_at = None;
        self.search_timeout_at = None;
        self.show_timeout_prompt = false;
        let count = search.count;
        for row in result.enrichment {
            self.enrichment.insert(row.cve_id.clone(), row);
        }
        match kind {
            SearchKind::Replace => {
                self.exhausted = result.exhausted;
                self.search_offset = result.consumed;
                self.results = result.rows;
                self.osv_results = result.osv_rows;
                self.linked_osv = result.linked_osv;
                self.clear_detail();
                self.select_candidate(0);
                if let Some(count) = count {
                    self.count_task =
                        Some(tokio::spawn(run_count_request(count.db, count.request)));
                }
            }
            SearchKind::Append { select_offset } => {
                self.exhausted = result.exhausted;
                self.search_offset = self.search_offset.saturating_add(result.consumed);
                let mut cve_ids = self
                    .results
                    .iter()
                    .map(|row| row.summary.cve_id.clone())
                    .collect::<HashSet<_>>();
                self.results.extend(
                    result
                        .rows
                        .into_iter()
                        .filter(|row| cve_ids.insert(row.summary.cve_id.clone())),
                );
                let mut osv_ids = self
                    .osv_results
                    .iter()
                    .map(|row| row.osv_id.clone())
                    .collect::<HashSet<_>>();
                self.osv_results.extend(
                    result
                        .osv_rows
                        .into_iter()
                        .filter(|row| osv_ids.insert(row.osv_id.clone())),
                );
                for (cve_id, advisories) in result.linked_osv {
                    let existing = self.linked_osv.entry(cve_id).or_default();
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
        Ok(())
    }

    pub(super) async fn poll_count(&mut self) {
        let Some(task) = self.count_task.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.count_task.take() else {
            self.status_message = Some("count task disappeared".to_owned());
            return;
        };
        match task.await {
            Ok(Ok(total)) => {
                self.total_results = Some(total);
            }
            Ok(Err(err)) => {
                self.status_message = Some(format!("failed to count search results: {err}"));
            }
            Err(err) => {
                self.status_message = Some(format!("failed to join count task: {err}"));
            }
        }
    }

    pub(super) async fn poll_maintenance(&mut self) -> bool {
        let Some(maintenance) = self.maintenance.as_mut() else {
            return false;
        };
        while let Ok(progress) = maintenance.progress.try_recv() {
            self.maintenance_progress = Some(progress.into());
        }
        match maintenance.result.try_recv() {
            Ok(result) => {
                let operation = maintenance.operation;
                self.maintenance = None;
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
                self.status_message = Some(message);
                self.maintenance_progress = None;
                self.show_maintenance = false;
                true
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => false,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                let operation = maintenance.operation;
                self.maintenance = None;
                self.status_message = Some(match operation {
                    MaintenanceOperation::Init => "init task disconnected".to_owned(),
                    MaintenanceOperation::Update => "update task disconnected".to_owned(),
                });
                self.maintenance_progress = None;
                self.show_maintenance = false;
                true
            }
        }
    }

    pub(super) async fn poll_raw_json(&mut self) {
        let Some(task) = self.raw_json_task.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.raw_json_task.take() else {
            self.raw_json = Some("raw JSON task disappeared".to_owned());
            self.raw_scroll = 0;
            return;
        };
        match task.await {
            Ok(Ok(raw_json)) => {
                self.raw_json = Some(raw_json);
                self.raw_scroll = 0;
            }
            Ok(Err(err)) => {
                self.raw_json = Some(err);
                self.raw_scroll = 0;
            }
            Err(err) => {
                self.raw_json = Some(format!("failed to join raw JSON task: {err}"));
                self.raw_scroll = 0;
            }
        }
    }

    pub(super) async fn poll_enrichment(&mut self) {
        let Some(task) = self.enrichment_task.as_ref() else {
            return;
        };
        if !task.handle.is_finished() {
            return;
        }
        let Some(task) = self.enrichment_task.take() else {
            self.status_message = Some("enrichment task disappeared".to_owned());
            return;
        };
        match task.handle.await {
            Ok(Ok(rows)) => {
                for row in rows {
                    self.enrichment.insert(row.cve_id.clone(), row);
                }
            }
            Ok(Err(err)) => {
                self.status_message = Some(format!("failed to load enrichment summaries: {err}"));
            }
            Err(err) => {
                self.status_message = Some(format!("failed to join enrichment task: {err}"));
            }
        }
    }

    pub(super) fn ensure_loaded_enrichment(&mut self, db: Option<CveDatabase>) {
        if self.results.is_empty() || self.enrichment_task.is_some() {
            return;
        }
        let cve_ids = self
            .results
            .iter()
            .map(|cve| cve.summary.cve_id.clone())
            .filter(|cve_id| !self.enrichment.contains_key(cve_id))
            .collect::<Vec<_>>();
        if cve_ids.is_empty() {
            return;
        }
        let Some(db) = db else {
            self.status_message = Some("database is unavailable".to_owned());
            return;
        };
        self.enrichment_task = Some(PendingEnrichment {
            handle: tokio::spawn(async move {
                db.enriched_cve_summaries(&cve_ids)
                    .await
                    .map_err(|err| err.to_string())
            }),
        });
    }

    pub(super) async fn poll_cwe_search(&mut self) {
        let Some(task) = self.cwe_task.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.cwe_task.take() else {
            self.status_message = Some("CWE task disappeared".to_owned());
            return;
        };
        match task.await {
            Ok(Ok(rows)) => {
                self.cwe_results = rows;
                self.cwe_scroll = 0;
                self.cwe_selected = 0;
                self.cwe_detail_scroll = 0;
                self.cwe_relation_return_id = None;
                self.clamp_cwe_scroll(self.left_page_size);
            }
            Ok(Err(err)) => {
                self.status_message = Some(err);
                self.cwe_results.clear();
                self.cwe_scroll = 0;
                self.cwe_selected = 0;
                self.cwe_detail_scroll = 0;
                self.cwe_relation_return_id = None;
            }
            Err(err) => {
                self.status_message = Some(format!("failed to join CWE task: {err}"));
                self.cwe_results.clear();
                self.cwe_scroll = 0;
                self.cwe_selected = 0;
                self.cwe_detail_scroll = 0;
                self.cwe_relation_return_id = None;
            }
        }
    }

    pub(super) fn searching(&self) -> bool {
        self.search.is_some()
    }

    pub(super) async fn poll_scope_candidates(&mut self) {
        let Some(task) = self.scope_task.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Some(task) = self.scope_task.take() else {
            return;
        };
        match task.await {
            Ok(Ok(advisories)) => self.advanced.set_scope_candidates(advisories),
            Ok(Err(err)) => self.status_message = Some(err),
            Err(err) => self.status_message = Some(format!("failed to join scope task: {err}")),
        }
    }

    pub(super) fn scope_candidates_loading(&self) -> bool {
        self.scope_task.is_some()
    }

    pub(super) fn has_background_task(&self) -> bool {
        self.search.is_some()
            || self.count_task.is_some()
            || self.raw_json_task.is_some()
            || self.enrichment_task.is_some()
            || self.cwe_task.is_some()
            || self.scope_task.is_some()
            || self.maintenance.is_some()
    }

    pub(super) fn cwe_searching(&self) -> bool {
        self.cwe_task.is_some()
    }

    pub(super) fn maintenance_running(&self) -> bool {
        self.maintenance.is_some()
    }

    pub(super) fn maintenance_status(&self) -> Option<&'static str> {
        self.maintenance
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
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }
        if let Some(task) = self.count_task.take() {
            task.abort();
        }
        if let Some(task) = self.raw_json_task.take() {
            task.abort();
        }
        if let Some(task) = self.enrichment_task.take() {
            task.handle.abort();
        }
        if let Some(task) = self.cwe_task.take() {
            task.abort();
        }
        self.search_started_at = None;
        self.search_timeout_at = None;
        self.show_timeout_prompt = false;
    }

    /// Cancels and joins every task that may retain a cloned database handle.
    /// Maintenance must wait for these before closing the single-owner SQLite writer.
    pub(super) async fn abort_database_tasks(&mut self) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
            let _ = search.handle.await;
        }
        if let Some(task) = self.count_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.raw_json_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.enrichment_task.take() {
            task.handle.abort();
            let _ = task.handle.await;
        }
        if let Some(task) = self.cwe_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.scope_task.take() {
            task.abort();
            let _ = task.await;
        }
        self.search_started_at = None;
        self.search_timeout_at = None;
        self.show_timeout_prompt = false;
    }

    pub(super) fn open_maintenance(&mut self) {
        if self.maintenance_running() {
            self.status_message = Some("database maintenance is already running".to_owned());
            return;
        }
        self.show_maintenance = true;
        self.maintenance_choice = MaintenanceChoice::Update;
    }

    pub(super) fn close_maintenance(&mut self) {
        self.show_maintenance = false;
    }

    pub(super) fn toggle_maintenance_keep_downloads(&mut self) {
        self.maintenance_keep_downloads = !self.maintenance_keep_downloads;
    }

    pub(super) fn next_maintenance_choice(&mut self) {
        self.maintenance_choice = match self.maintenance_choice {
            MaintenanceChoice::Init => MaintenanceChoice::Update,
            MaintenanceChoice::Update => MaintenanceChoice::Cancel,
            MaintenanceChoice::Cancel => MaintenanceChoice::Init,
        };
    }

    pub(super) fn previous_maintenance_choice(&mut self) {
        self.maintenance_choice = match self.maintenance_choice {
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
        self.show_maintenance = true;
        self.status_message = Some(match operation {
            MaintenanceOperation::Init => "init started".to_owned(),
            MaintenanceOperation::Update => "update started".to_owned(),
        });
        self.maintenance_progress = Some(MaintenanceProgress {
            label: match operation {
                MaintenanceOperation::Init => "init".to_owned(),
                MaintenanceOperation::Update => "update".to_owned(),
            },
            phase: "starting".to_owned(),
            ..MaintenanceProgress::default()
        });
        self.maintenance = Some(PendingMaintenance {
            operation,
            progress,
            result,
        });
    }

    pub(super) fn cancel_timed_out_search(&mut self) {
        self.abort_search();
        self.status_message = Some("search canceled".to_owned());
    }

    pub(super) fn continue_timed_out_search(&mut self) {
        if let Some(search) = self.search.as_mut() {
            search.timed_out_once = true;
            self.search_timeout_at = Some(Instant::now() + SEARCH_TIMEOUT);
        }
        self.show_timeout_prompt = false;
        self.timeout_choice = TimeoutChoice::Continue;
        self.status_message = Some("search continued".to_owned());
    }

    pub(super) fn toggle_timeout_choice(&mut self) {
        self.timeout_choice = match self.timeout_choice {
            TimeoutChoice::Continue => TimeoutChoice::Cancel,
            TimeoutChoice::Cancel => TimeoutChoice::Continue,
        };
    }

    pub(super) fn select_timeout_continue(&mut self) {
        self.timeout_choice = TimeoutChoice::Continue;
    }

    pub(super) fn select_timeout_cancel(&mut self) {
        self.timeout_choice = TimeoutChoice::Cancel;
    }

    pub(super) fn confirm_timeout_choice(&mut self) {
        match self.timeout_choice {
            TimeoutChoice::Continue => self.continue_timed_out_search(),
            TimeoutChoice::Cancel => self.cancel_timed_out_search(),
        }
    }

    pub(super) fn search_spinner(&self) -> &'static str {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame = self
            .search_started_at
            .map(|started_at| (started_at.elapsed().as_millis() / 80) as usize)
            .unwrap_or(0);
        FRAMES[frame % FRAMES.len()]
    }

    pub(super) fn selected(&self) -> Option<&CveSummaryWithDetail> {
        self.list_state
            .selected()
            .and_then(|index| self.results.get(index))
    }

    pub(super) fn selected_osv(&self) -> Option<&OsvSummary> {
        self.list_state
            .selected()
            .and_then(|index| index.checked_sub(self.results.len()))
            .and_then(|index| self.osv_results.get(index))
    }

    pub(super) fn candidate_count(&self) -> usize {
        self.results.len() + self.osv_results.len()
    }

    pub(super) fn toggle_raw_json_mode(&mut self, db: Option<CveDatabase>) {
        if self.view_mode == ViewMode::RawJson {
            self.view_mode = ViewMode::Normal;
            return;
        }
        self.view_mode = ViewMode::RawJson;
        self.raw_scroll = 0;
        let Some(db) = db else {
            self.raw_json = Some("Database is unavailable".to_owned());
            return;
        };
        if let Some(task) = self.raw_json_task.take() {
            task.abort();
        }
        self.raw_json = Some("Loading".to_owned());
        self.raw_json_task = match (
            self.selected().map(|cve| cve.summary.cve_id.clone()),
            self.selected_osv().map(|osv| osv.osv_id.clone()),
        ) {
            (Some(cve_id), _) => Some(tokio::spawn(load_cve_raw_json(db, cve_id))),
            (_, Some(osv_id)) => Some(tokio::spawn(load_osv_raw_json(db, osv_id))),
            (None, None) => {
                self.raw_json = Some("No result selected".to_owned());
                None
            }
        };
    }

    pub(super) fn toggle_cwe_list_mode(&mut self, db: Option<CveDatabase>) {
        if self.view_mode == ViewMode::CweList {
            self.view_mode = ViewMode::Normal;
            return;
        }
        self.view_mode = ViewMode::CweList;
        self.start_cwe_search(db);
    }

    pub(super) fn push_cwe_query(&mut self, ch: char, db: Option<CveDatabase>) {
        self.cwe_query.push(ch);
        self.start_cwe_search(db);
    }

    pub(super) fn backspace_cwe_query(&mut self, db: Option<CveDatabase>) {
        self.cwe_query.pop();
        self.start_cwe_search(db);
    }

    pub(super) fn selected_cwe_status_labels(&self) -> Vec<&'static str> {
        CWE_STATUSES
            .iter()
            .enumerate()
            .filter_map(|(index, status)| self.cwe_status_filter[index].then_some(status.label()))
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
        self.show_cwe_status = true;
    }

    pub(super) fn close_cwe_status_popup(&mut self) {
        self.show_cwe_status = false;
    }

    pub(super) fn next_cwe_status(&mut self) {
        self.cwe_status_cursor = (self.cwe_status_cursor + 1) % CWE_STATUS_CONTROL_COUNT;
    }

    pub(super) fn previous_cwe_status(&mut self) {
        self.cwe_status_cursor = if self.cwe_status_cursor == 0 {
            CWE_STATUS_CONTROL_COUNT - 1
        } else {
            self.cwe_status_cursor - 1
        };
    }

    pub(super) fn toggle_current_cwe_status(&mut self, db: Option<CveDatabase>) {
        match self.cwe_status_cursor {
            0..CWE_STATUS_COUNT => {
                self.cwe_status_filter[self.cwe_status_cursor] =
                    !self.cwe_status_filter[self.cwe_status_cursor];
            }
            CWE_STATUS_SELECT_ALL_CURSOR => self.cwe_status_filter = [true; CWE_STATUS_COUNT],
            CWE_STATUS_CLEAR_ALL_CURSOR => self.cwe_status_filter = [false; CWE_STATUS_COUNT],
            _ => {}
        }
        self.start_cwe_search(db);
    }

    pub(super) fn select_all_cwe_statuses(&mut self, db: Option<CveDatabase>) {
        self.cwe_status_filter = [true; CWE_STATUS_COUNT];
        self.start_cwe_search(db);
    }

    pub(super) fn clear_all_cwe_statuses(&mut self, db: Option<CveDatabase>) {
        self.cwe_status_filter = [false; CWE_STATUS_COUNT];
        self.start_cwe_search(db);
    }

    pub(super) fn activate_cwe_status_control(&mut self, db: Option<CveDatabase>) -> bool {
        match self.cwe_status_cursor {
            CWE_STATUS_SELECT_ALL_CURSOR => {
                self.select_all_cwe_statuses(db);
                true
            }
            CWE_STATUS_CLEAR_ALL_CURSOR => {
                self.clear_all_cwe_statuses(db);
                true
            }
            _ => false,
        }
    }

    pub(super) fn selected_cwe(&self) -> Option<&CweEntry> {
        self.cwe_results.get(self.cwe_selected)
    }

    pub(super) fn start_detail_search(&mut self) {
        self.detail_search_input = true;
        self.detail_search_error = None;
    }

    pub(super) fn close_detail_search(&mut self) {
        self.detail_search_input = false;
        self.detail_search_error = None;
    }

    pub(super) fn push_detail_search(&mut self, ch: char) {
        self.detail_search_query.push(ch);
        self.detail_search_error = None;
    }

    pub(super) fn backspace_detail_search(&mut self) {
        self.detail_search_query.pop();
        self.detail_search_error = None;
    }

    pub(super) fn set_page_sizes(
        &mut self,
        left: usize,
        right: usize,
        metadata: usize,
        detail_width: usize,
        metadata_width: usize,
    ) {
        self.left_page_size = left.max(MIN_PAGE_SIZE);
        self.right_page_size = right.max(MIN_PAGE_SIZE);
        self.metadata_page_size = metadata.max(MIN_PAGE_SIZE);
        self.detail_content_width = detail_width.max(MIN_PAGE_SIZE);
        self.metadata_content_width = metadata_width.max(MIN_PAGE_SIZE);
        self.clamp_detail_scroll();
        self.clamp_metadata_scroll();
    }

    pub(super) fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn toggle_cwe_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn previous_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn next_right_tab(&mut self) {
        self.right_tab = if self.selected_osv().is_some() {
            match self.right_tab {
                RightPaneTab::Cve | RightPaneTab::Osv => RightPaneTab::Metadata,
                RightPaneTab::Metadata => RightPaneTab::Enrichment,
                RightPaneTab::Enrichment => RightPaneTab::Cve,
            }
        } else {
            self.right_tab.next()
        };
    }

    pub(super) fn previous_right_tab(&mut self) {
        self.right_tab = if self.selected_osv().is_some() {
            match self.right_tab {
                RightPaneTab::Cve | RightPaneTab::Osv => RightPaneTab::Enrichment,
                RightPaneTab::Metadata => RightPaneTab::Cve,
                RightPaneTab::Enrichment => RightPaneTab::Metadata,
            }
        } else {
            self.right_tab.previous()
        };
    }

    pub(super) fn next_or_load_more(&mut self, db: CveDatabase) {
        let candidate_count = self.candidate_count();
        if candidate_count == 0 {
            self.list_state.select(None);
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        if current + 1 >= candidate_count {
            self.start_load_more(db);
            return;
        }
        let next = self
            .list_state
            .selected()
            .map(|index| (index + 1).min(candidate_count - 1))
            .unwrap_or(0);
        self.list_state.select(Some(next));
    }

    pub(super) fn move_focused_down(&mut self, db: CveDatabase) {
        match self.focus {
            PaneFocus::Left => self.next_or_load_more(db),
            PaneFocus::Right => {
                if self.right_tab == RightPaneTab::Cve {
                    self.detail_scroll = self.detail_scroll.saturating_add(1);
                    self.clamp_detail_scroll();
                } else {
                    self.metadata_scroll = self.metadata_scroll.saturating_add(1);
                    self.clamp_metadata_scroll();
                }
            }
        }
    }

    pub(super) fn move_focused_up(&mut self) {
        match self.focus {
            PaneFocus::Left => self.previous(),
            PaneFocus::Right => {
                if self.right_tab == RightPaneTab::Cve {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1);
                    self.clamp_detail_scroll();
                } else {
                    self.metadata_scroll = self.metadata_scroll.saturating_sub(1);
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
            self.list_state.select(None);
            return;
        }
        let previous = self
            .list_state
            .selected()
            .map(|index| index.saturating_sub(1))
            .unwrap_or(0);
        self.list_state.select(Some(previous));
    }

    pub(super) fn scroll_detail_to_top(&mut self) {
        self.detail_scroll = 0;
    }

    pub(super) fn next_search_mode(&mut self) {
        self.search_mode = self.search_mode.next();
        self.sync_advanced_from_main();
    }

    pub(super) fn previous_search_mode(&mut self) {
        self.search_mode = self.search_mode.previous();
        self.sync_advanced_from_main();
    }

    pub(super) fn push_query(&mut self, ch: char) {
        self.query.push(ch);
        self.scroll_detail_to_top();
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
    }

    pub(super) fn backspace_query(&mut self) {
        self.query.pop();
        self.scroll_detail_to_top();
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
    }

    pub(super) fn move_raw_down(&mut self, line_count: usize, page_size: usize) {
        self.raw_scroll = self.raw_scroll.saturating_add(1);
        self.raw_scroll = self
            .raw_scroll
            .min(line_count.saturating_sub(page_size.max(MIN_PAGE_SIZE)) as u16);
    }

    pub(super) fn move_raw_up(&mut self) {
        self.raw_scroll = self.raw_scroll.saturating_sub(1);
    }

    pub(super) fn move_raw_page_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.raw_scroll = self
            .raw_scroll
            .saturating_add(page_size as u16)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_raw_page_up(&mut self, page_size: usize) {
        self.raw_scroll = self
            .raw_scroll
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
        self.cwe_relation_return_id = None;
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let Some(parent_id) = selected.parent_id else {
            self.status_message = Some("selected CWE has no parent".to_owned());
            return;
        };
        let return_id = selected.id;
        if !self.select_cwe_by_id(parent_id, page_size) {
            self.status_message = Some(format!("parent CWE-{parent_id} is not in current results"));
            return;
        }
        self.cwe_relation_return_id = Some(return_id);
    }

    pub(super) fn move_cwe_to_relation_return(&mut self, page_size: usize) {
        let Some(return_id) = self.cwe_relation_return_id.take() else {
            self.status_message = Some("no CWE relation return target".to_owned());
            return;
        };
        if !self.select_cwe_by_id(return_id, page_size) {
            self.status_message = Some(format!(
                "return target CWE-{return_id} is not in current results"
            ));
        }
    }

    pub(super) fn move_cwe_to_previous_sibling(&mut self, page_size: usize) {
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let sibling_id = self
            .cwe_results
            .iter()
            .filter(|cwe| cwe.parent_id == selected.parent_id && cwe.id < selected.id)
            .map(|cwe| cwe.id)
            .max();
        let Some(sibling_id) = sibling_id else {
            self.status_message =
                Some("selected CWE has no previous sibling in current results".to_owned());
            return;
        };
        self.cwe_relation_return_id = None;
        self.select_cwe_by_id(sibling_id, page_size);
    }

    pub(super) fn move_cwe_to_next_sibling(&mut self, page_size: usize) {
        let Some(selected) = self.selected_cwe() else {
            return;
        };
        let sibling_id = self
            .cwe_results
            .iter()
            .filter(|cwe| cwe.parent_id == selected.parent_id && cwe.id > selected.id)
            .map(|cwe| cwe.id)
            .min();
        let Some(sibling_id) = sibling_id else {
            self.status_message =
                Some("selected CWE has no next sibling in current results".to_owned());
            return;
        };
        self.cwe_relation_return_id = None;
        self.select_cwe_by_id(sibling_id, page_size);
    }

    fn select_cwe_by_id(&mut self, id: i32, page_size: usize) -> bool {
        let Some(index) = self.cwe_results.iter().position(|cwe| cwe.id == id) else {
            return false;
        };
        self.cwe_selected = index;
        self.scroll_cwe_selection_into_view(page_size);
        self.cwe_detail_scroll = 0;
        self.status_message = None;
        true
    }

    fn move_cwe_page(&mut self, direction: PageDirection, step: usize, page_size: usize) {
        if self.cwe_results.is_empty() {
            self.cwe_selected = 0;
            self.cwe_scroll = 0;
            self.cwe_detail_scroll = 0;
            return;
        }

        self.cwe_selected = match direction {
            PageDirection::Up => self.cwe_selected.saturating_sub(step),
            PageDirection::Down => self
                .cwe_selected
                .saturating_add(step)
                .min(self.cwe_results.len() - 1),
        };
        self.scroll_cwe_selection_into_view(page_size);
        self.cwe_detail_scroll = 0;
        self.cwe_relation_return_id = None;
    }

    fn scroll_cwe_selection_into_view(&mut self, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        if self.cwe_selected < self.cwe_scroll as usize {
            self.cwe_scroll = self.cwe_selected as u16;
        } else if self.cwe_selected >= self.cwe_scroll as usize + page_size {
            self.cwe_scroll =
                self.cwe_selected
                    .saturating_sub(page_size - 1)
                    .min(self.cwe_results.len().saturating_sub(page_size)) as u16;
        }
        self.clamp_cwe_scroll(page_size);
    }

    fn clamp_cwe_scroll(&mut self, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        let max_scroll = self.cwe_results.len().saturating_sub(page_size) as u16;
        self.cwe_scroll = self.cwe_scroll.min(max_scroll);
    }

    pub(super) fn move_cwe_detail_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.cwe_detail_scroll = self
            .cwe_detail_scroll
            .saturating_add(1)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_cwe_detail_up(&mut self) {
        self.cwe_detail_scroll = self.cwe_detail_scroll.saturating_sub(1);
    }

    pub(super) fn move_cwe_detail_page_down(&mut self, line_count: usize, page_size: usize) {
        let page_size = page_size.max(MIN_PAGE_SIZE);
        self.cwe_detail_scroll = self
            .cwe_detail_scroll
            .saturating_add(page_size as u16)
            .min(line_count.saturating_sub(page_size) as u16);
    }

    pub(super) fn move_cwe_detail_page_up(&mut self, page_size: usize) {
        self.cwe_detail_scroll = self
            .cwe_detail_scroll
            .saturating_sub(page_size.max(MIN_PAGE_SIZE) as u16);
    }

    pub(super) fn sync_main_from_advanced(&mut self) {
        self.query = self.advanced.query.clone();
        self.search_mode = self.advanced.query_mode;
        self.state_scope = self.advanced.state_scope;
        self.scroll_detail_to_top();
    }

    pub(super) fn sync_advanced_from_main(&mut self) {
        self.advanced.query = self.query.clone();
        self.advanced.query_mode = self.search_mode;
        self.advanced.state_scope = self.state_scope;
    }

    pub(super) fn reset_screen(&mut self) {
        self.abort_search();
        self.query.clear();
        self.search_mode = SearchMode::FreeText;
        self.state_scope = CveStateScope::PublishedOnly;
        self.advanced = AdvancedForm::default();
        self.display = DisplaySettings::default();
        self.results.clear();
        self.osv_results.clear();
        self.linked_osv.clear();
        self.search_offset = 0;
        self.enrichment.clear();
        self.total_results = None;
        self.list_state.select(Some(0));
        self.focus = PaneFocus::Left;
        self.view_mode = ViewMode::Normal;
        self.detail_scroll = 0;
        self.metadata_scroll = 0;
        self.raw_json = None;
        self.raw_scroll = 0;
        self.cwe_query.clear();
        self.cwe_results.clear();
        self.cwe_scroll = 0;
        self.cwe_selected = 0;
        self.cwe_detail_scroll = 0;
        self.cwe_relation_return_id = None;
        self.cwe_status_filter = default_cwe_status_filter();
        self.cwe_status_cursor = 0;
        self.show_cwe_status = false;
        self.detail_search_query.clear();
        self.detail_search_input = false;
        self.detail_search_error = None;
        self.searched_request = SearchRequest::Mode {
            mode: SearchMode::FreeText,
            query: String::new(),
            state_scope: CveStateScope::PublishedOnly,
            kev_only: false,
        };
        self.exhausted = false;
        self.show_help = false;
        self.show_advanced = false;
        self.show_display = false;
        self.show_timeout_prompt = false;
        self.show_maintenance = false;
        self.timeout_choice = TimeoutChoice::Continue;
        self.maintenance_choice = MaintenanceChoice::Update;
        self.status_message = None;
        self.maintenance_progress = None;
    }

    pub(super) fn apply_prefix_mode(&mut self) {
        if let Some(mode) = SearchMode::from_query_prefix(&self.query) {
            self.search_mode = mode;
        }
    }

    fn main_search_options(&self, sort_order: CveSummarySortOrder) -> CveAdvancedSearch {
        CveAdvancedSearch {
            query: option_string(&self.query),
            query_mode: Some(self.search_mode.into()),
            published_from: None,
            published_to: None,
            cwe: None,
            product: None,
            product_exact: None,
            package_ecosystem: None,
            package_version: None,
            vendor: None,
            vendor_exact: None,
            kev_only: self.display.kev_only,
            state_scope: self.state_scope,
            sort_order,
        }
    }

    fn start_replace_search(
        &mut self,
        db: CveDatabase,
        request: SearchRequest,
        error_prefix: &str,
    ) {
        self.exhausted = false;
        self.total_results = None;
        self.start_pending_search(
            db,
            request,
            self.limit,
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
        self.status_message = None;
        self.arm_search_timeout();
        let count = matches!(&kind, SearchKind::Replace).then(|| PendingCount {
            db: db.clone(),
            request: request.clone(),
        });
        let error_prefix = error_prefix.to_owned();
        self.search = Some(PendingSearch {
            kind,
            count,
            timed_out_once: false,
            handle: tokio::spawn(async move {
                run_search_request(db, request, limit, offset)
                    .await
                    .map_err(|err| format!("{error_prefix}: {err}"))
            }),
        });
    }

    fn start_cwe_search(&mut self, db: Option<CveDatabase>) {
        if let Some(task) = self.cwe_task.take() {
            task.abort();
        }
        self.cwe_scroll = 0;
        self.cwe_relation_return_id = None;
        let Some(db) = db else {
            self.status_message = Some("database is unavailable".to_owned());
            self.cwe_results.clear();
            return;
        };
        let query = self.cwe_query.clone();
        let statuses = self
            .selected_cwe_status_labels()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        self.cwe_task = Some(tokio::spawn(search_cwe_entries(db, query, statuses)));
    }

    fn move_focused_page(&mut self, db: CveDatabase, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, Some(db)),
            PaneFocus::Right => self.move_right_page(direction, amount),
        }
    }

    fn move_focused_page_without_db(&mut self, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, None),
            PaneFocus::Right => self.move_right_page(direction, amount),
        }
    }

    fn move_right_page(&mut self, direction: PageDirection, amount: PageAmount) {
        if self.right_tab == RightPaneTab::Cve {
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
            self.list_state.select(None);
            return;
        }

        let current = self.list_state.selected().unwrap_or(0);
        let step = self.left_step(amount);
        let next = match direction {
            PageDirection::Up => current.saturating_sub(step),
            PageDirection::Down => current.saturating_add(step).min(candidate_count - 1),
        };
        self.list_state.select(Some(next));
        if matches!(direction, PageDirection::Down)
            && next + 1 >= candidate_count
            && let Some(db) = db
        {
            self.start_load_more(db);
        }
    }

    fn move_detail_page(&mut self, direction: PageDirection, amount: PageAmount) {
        let step = self.right_step(amount) as u16;
        self.detail_scroll = match direction {
            PageDirection::Up => self.detail_scroll.saturating_sub(step),
            PageDirection::Down => self.detail_scroll.saturating_add(step),
        };
        self.clamp_detail_scroll();
    }

    fn move_metadata_page(&mut self, direction: PageDirection, amount: PageAmount) {
        let step = self.metadata_step(amount) as u16;
        self.metadata_scroll = match direction {
            PageDirection::Up => self.metadata_scroll.saturating_sub(step),
            PageDirection::Down => self.metadata_scroll.saturating_add(step),
        };
        self.clamp_metadata_scroll();
    }

    pub(super) fn clamp_detail_scroll(&mut self) {
        self.detail_scroll = self.detail_scroll.min(self.max_detail_scroll());
    }

    pub(super) fn clamp_metadata_scroll(&mut self) {
        self.metadata_scroll = self.metadata_scroll.min(self.max_metadata_scroll());
    }

    fn max_detail_scroll(&self) -> u16 {
        let line_count = if let Some(cve) = self.selected() {
            Paragraph::new(crate::modes::main::detail::detail_lines(
                cve,
                self.display.timezone,
                &crate::common::DetailSearch::new(""),
            ))
            .wrap(Wrap { trim: false })
            .line_count(self.detail_content_width.min(u16::MAX as usize) as u16)
        } else if let Some(osv) = self.selected_osv() {
            Paragraph::new(crate::modes::main::detail::osv_detail_lines(
                osv,
                self.display.timezone,
                &crate::common::DetailSearch::new(""),
            ))
            .wrap(Wrap { trim: false })
            .line_count(self.detail_content_width.min(u16::MAX as usize) as u16)
        } else {
            1
        };
        line_count.saturating_sub(self.right_page_size) as u16
    }

    fn max_metadata_scroll(&self) -> u16 {
        let line_count = match self.right_tab {
            RightPaneTab::Cve => 1,
            RightPaneTab::Osv => Paragraph::new(crate::modes::main::right::osv_lines(
                self,
                &crate::common::DetailSearch::new(""),
            ))
            .wrap(Wrap { trim: false })
            .line_count(self.metadata_content_width.min(u16::MAX as usize) as u16),
            RightPaneTab::Metadata => {
                if let Some(cve) = self.selected() {
                    metadata_line_count(cve, self.metadata_content_width)
                } else if let Some(osv) = self.selected_osv() {
                    osv_metadata_line_count(osv, self.metadata_content_width)
                } else {
                    1
                }
            }
            RightPaneTab::Enrichment => self.enrichment_line_count(),
        };
        line_count.saturating_sub(self.metadata_page_size) as u16
    }

    fn enrichment_line_count(&self) -> usize {
        let Some(cve) = self.selected() else {
            return self.selected_osv().map_or(1, |_| 3);
        };
        let Some(enrichment) = self.enrichment.get(&cve.summary.cve_id) else {
            return 3;
        };
        let width = self.metadata_content_width;
        let mut lines = vec![
            format!("Identifier: {}", enrichment.cve_id),
            String::new(),
            "Priority".to_owned(),
        ];
        lines.push(format!(
            "  KEV: {}",
            if enrichment.kev_listed {
                "listed"
            } else {
                "not listed"
            }
        ));
        lines.push(match (enrichment.epss, enrichment.epss_percentile) {
            (Some(epss), Some(percentile)) => format!(
                "  EPSS: score={epss:.5} percentile={percentile:.5} date={} model={}",
                enrichment.epss_score_date.as_deref().unwrap_or("-"),
                enrichment.epss_model_version.as_deref().unwrap_or("-")
            ),
            _ => "  EPSS: not synced".to_owned(),
        });
        if enrichment.kev_listed {
            lines.push(format!(
                "  KEV due={} ransomware={}",
                enrichment.kev_due_date.as_deref().unwrap_or("-"),
                enrichment
                    .kev_known_ransomware_campaign_use
                    .as_deref()
                    .unwrap_or("-")
            ));
        }
        let aliases = summary_values(&enrichment.aliases);
        let osv_summaries = summary_values(&enrichment.osv_summaries);
        let packages = summary_values(&enrichment.affected_packages);
        append_summary_section(&mut lines, "Aliases", &aliases);
        append_summary_section(&mut lines, "OSV Advisories", &osv_summaries);
        append_summary_section(&mut lines, "Affected Packages", &packages);
        lines.push(String::new());
        lines.push("Evidence".to_owned());
        if !aliases.is_empty() {
            lines.push("  alias_resolution source=OSV aliases".to_owned());
        }
        if enrichment.kev_listed {
            lines.push("  kev_join source=CISA KEV".to_owned());
        }
        if enrichment.epss.is_some() {
            lines.push("  epss_join source=FIRST EPSS".to_owned());
        }
        if aliases.is_empty() && !enrichment.kev_listed && enrichment.epss.is_none() {
            lines.push("  none".to_owned());
        }
        lines
            .iter()
            .map(|line| wrapped_line_count(line, width))
            .sum()
    }

    fn left_step(&self, amount: PageAmount) -> usize {
        match amount {
            PageAmount::Half => (self.left_page_size / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => self.left_page_size.max(MIN_PAGE_SIZE),
        }
    }

    fn right_step(&self, amount: PageAmount) -> usize {
        match amount {
            PageAmount::Half => (self.right_page_size / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => self.right_page_size.max(MIN_PAGE_SIZE),
        }
    }

    fn metadata_step(&self, amount: PageAmount) -> usize {
        match amount {
            PageAmount::Half => (self.metadata_page_size / 2).max(MIN_PAGE_SIZE),
            PageAmount::Full => self.metadata_page_size.max(MIN_PAGE_SIZE),
        }
    }

    fn clear_detail(&mut self) {
        self.detail_scroll = 0;
        self.metadata_scroll = 0;
        self.enrichment.clear();
        if let Some(task) = self.enrichment_task.take() {
            task.handle.abort();
        }
    }

    fn select_candidate(&mut self, index: usize) {
        let candidate_count = self.candidate_count();
        if candidate_count == 0 {
            self.list_state.select(None);
        } else {
            self.list_state.select(Some(index.min(candidate_count - 1)));
        }
    }

    fn finish_failed_search(&mut self, message: String) {
        self.search_started_at = None;
        self.search_timeout_at = None;
        self.show_timeout_prompt = false;
        self.status_message = Some(message);
    }

    fn arm_search_timeout(&mut self) {
        let now = Instant::now();
        self.search_started_at = Some(now);
        self.search_timeout_at = Some(now + SEARCH_TIMEOUT);
        self.show_timeout_prompt = false;
        self.timeout_choice = TimeoutChoice::Continue;
    }

    fn check_search_timeout(&mut self) {
        let Some(timeout_at) = self.search_timeout_at else {
            return;
        };
        if Instant::now() < timeout_at {
            return;
        }
        let Some(search) = self.search.as_mut() else {
            return;
        };
        if search.timed_out_once {
            search.handle.abort();
            self.search = None;
            self.search_started_at = None;
            self.search_timeout_at = None;
            self.show_timeout_prompt = false;
            self.status_message = Some(format!(
                "search timed out after {} seconds",
                SEARCH_TIMEOUT.as_secs() * 2
            ));
        } else {
            self.show_timeout_prompt = true;
            self.timeout_choice = TimeoutChoice::Continue;
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

fn osv_metadata_line_count(osv: &OsvSummary, width: usize) -> usize {
    [
        format!("Identifier: {}", osv.osv_id),
        format!(
            "Schema version: {}",
            osv.schema_version.as_deref().unwrap_or("-")
        ),
        format!("Published: {}", osv.published_at.as_deref().unwrap_or("-")),
        format!("Updated: {}", osv.modified_at.as_deref().unwrap_or("-")),
        format!("Withdrawn: {}", osv.withdrawn_at.as_deref().unwrap_or("-")),
    ]
    .iter()
    .map(|line| wrapped_line_count(line, width))
    .sum()
}

fn summary_values(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect()
}

fn append_summary_section(lines: &mut Vec<String>, title: &str, values: &[&str]) {
    lines.push(String::new());
    lines.push(title.to_owned());
    if values.is_empty() {
        lines.push("  none".to_owned());
    } else {
        lines.extend(values.iter().map(|value| format!("  {value}")));
    }
}

fn metadata_line_count(cve: &CveSummaryWithDetail, width: usize) -> usize {
    let detail = &cve.detail;
    let cwe_lines = detail
        .cwes
        .iter()
        .map(|cwe| {
            let description = cwe
                .description
                .as_deref()
                .map(normalize_spaces)
                .unwrap_or_default();
            wrapped_line_count(&format!("CWE-{} {}", cwe.id, description), width)
        })
        .sum::<usize>()
        .max(1);
    let cvss_lines = detail
        .cvss
        .iter()
        .map(|cvss| {
            let score = cvss
                .base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| "-".to_owned());
            let severity = cvss.base_severity.as_deref().unwrap_or("-");
            let vector = cvss.vector_string.as_deref().unwrap_or("");
            wrapped_line_count(
                &format!("{} {} {} {}", cvss.version, score, severity, vector),
                width,
            )
        })
        .sum::<usize>()
        .max(1);
    let affected_lines = detail
        .affected
        .iter()
        .map(|affected| {
            let vendor = affected.vendor.as_deref().unwrap_or("-");
            let product = affected.product.as_deref().unwrap_or("-");
            let package = affected.package_name.as_deref().unwrap_or("-");
            let status = affected.default_status.as_deref().unwrap_or("-");
            let collection = affected.collection_url.as_deref().unwrap_or("");
            let suffix = if collection.is_empty() {
                String::new()
            } else {
                format!(" {collection}")
            };
            let component_lines = wrapped_line_count(
                &format!("{vendor}/{product} pkg:{package} status:{status}{suffix}"),
                width,
            );
            let description_lines = affected
                .description
                .as_deref()
                .map(normalize_spaces)
                .filter(|description| !description.is_empty())
                .map(|description| {
                    wrapped_line_count(&format!("  Description: {description}"), width)
                })
                .unwrap_or_default();
            component_lines + description_lines
        })
        .sum::<usize>()
        .max(1);
    cwe_lines + cvss_lines + affected_lines + 2
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_enter_starts_a_sorted_cve_browse_search() {
        let database = CveDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize_schema().await.unwrap();
        let mut app = App::new(String::new(), 25);

        app.start_search(database);

        match &app.searched_request {
            SearchRequest::Advanced {
                options,
                include_cve,
                include_osv,
                ..
            } => {
                assert_eq!(options.sort_order, CveSummarySortOrder::PublishedDesc);
                assert!(options.query.is_none());
                assert!(*include_cve);
                assert!(!include_osv);
            }
            SearchRequest::Mode { .. } => panic!("empty Enter must browse CVEs"),
        }
        app.abort_search();
    }
}
