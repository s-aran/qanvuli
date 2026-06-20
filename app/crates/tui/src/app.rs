use super::{
    SEARCH_TIMEOUT, TUI_LOAD_MORE_LIMIT,
    display::DisplaySettings,
    form::AdvancedForm,
    mode::SearchMode,
    search::{SearchRequest, SearchResult, run_search_request},
};
use qanvuli_app_commands::common::IngestProgress;
use qanvuli_db::{
    CveAdvancedSearch, CveDatabase, CveStateScope, CveSummarySortOrder, CveSummaryWithDetail,
    CweEntry,
};
use ratatui::widgets::ListState;
use std::time::Instant;
use tokio::{sync::mpsc::UnboundedReceiver, task::JoinHandle};

const MIN_PAGE_SIZE: usize = 1;

pub(super) struct App {
    pub(super) query: String,
    pub(super) search_mode: SearchMode,
    pub(super) state_scope: CveStateScope,
    pub(super) advanced: AdvancedForm,
    pub(super) display: DisplaySettings,
    pub(super) limit: u64,
    pub(super) results: Vec<CveSummaryWithDetail>,
    pub(super) total_results: Option<u64>,
    pub(super) list_state: ListState,
    pub(super) focus: PaneFocus,
    pub(super) detail_scroll: u16,
    pub(super) metadata_scroll: u16,
    pub(super) view_mode: ViewMode,
    pub(super) raw_json: Option<String>,
    pub(super) raw_scroll: u16,
    pub(super) cwe_query: String,
    pub(super) cwe_results: Vec<CweEntry>,
    pub(super) cwe_scroll: u16,
    search: Option<PendingSearch>,
    raw_json_task: Option<JoinHandle<Result<String, String>>>,
    cwe_task: Option<JoinHandle<Result<Vec<CweEntry>, String>>>,
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
    pub(super) status_message: Option<String>,
    pub(super) db_as_of: Option<String>,
    pub(super) maintenance_progress: Option<MaintenanceProgress>,
    maintenance: Option<PendingMaintenance>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PaneFocus {
    Left,
    Right,
    Metadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ViewMode {
    Normal,
    RawJson,
    CweList,
}

struct PendingSearch {
    kind: SearchKind,
    handle: JoinHandle<Result<SearchResult, String>>,
    timed_out_once: bool,
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
            results: Vec::new(),
            total_results: None,
            list_state,
            focus: PaneFocus::Left,
            detail_scroll: 0,
            metadata_scroll: 0,
            view_mode: ViewMode::Normal,
            raw_json: None,
            raw_scroll: 0,
            cwe_query: String::new(),
            cwe_results: Vec::new(),
            cwe_scroll: 0,
            search: None,
            raw_json_task: None,
            cwe_task: None,
            search_started_at: None,
            search_timeout_at: None,
            searched_request: SearchRequest::Mode {
                mode: search_mode,
                query: String::new(),
                state_scope: CveStateScope::PublishedOnly,
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
        let request = if sort_order == CveSummarySortOrder::PublishedDesc {
            SearchRequest::Mode {
                mode: self.search_mode,
                query: self.query.clone(),
                state_scope: self.state_scope,
            }
        } else {
            SearchRequest::Advanced(self.main_search_options(sort_order))
        };
        self.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn start_advanced_search(&mut self, db: CveDatabase) {
        self.query = self.advanced.query.clone();
        self.search_mode = self.advanced.query_mode;
        self.state_scope = self.advanced.state_scope;
        let request =
            SearchRequest::Advanced(self.advanced.to_search_options(self.display.sort_order()));
        self.searched_request = request.clone();
        self.start_replace_search(db, request, "failed to search");
    }

    pub(super) fn open_advanced_search(&mut self) {
        self.apply_prefix_mode();
        self.sync_advanced_from_main();
        self.show_advanced = true;
    }

    pub(super) fn open_display_settings(&mut self) {
        self.show_display = true;
    }

    pub(super) fn start_load_more(&mut self, db: CveDatabase) {
        if self.searching() || self.exhausted || self.results.is_empty() {
            return;
        }

        let request = self.searched_request.clone();
        let offset = self.results.len() as u64;
        let select_offset = self.results.len();
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

        let search = self.search.take().expect("search handle disappeared");
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
        match kind {
            SearchKind::Replace => {
                self.exhausted = result.rows.len() < self.limit as usize;
                self.total_results = Some(result.total);
                self.results = result.rows;
                self.clear_detail();
                self.select_candidate(0);
            }
            SearchKind::Append { select_offset } => {
                self.exhausted = result.rows.len() < TUI_LOAD_MORE_LIMIT as usize;
                self.total_results = Some(result.total);
                self.results.extend(result.rows);
                self.select_candidate(select_offset);
            }
        }
        Ok(())
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
        let task = self
            .raw_json_task
            .take()
            .expect("raw JSON task disappeared");
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

    pub(super) async fn poll_cwe_search(&mut self) {
        let Some(task) = self.cwe_task.as_ref() else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let task = self.cwe_task.take().expect("CWE task disappeared");
        match task.await {
            Ok(Ok(rows)) => {
                self.cwe_results = rows;
                self.cwe_scroll = 0;
            }
            Ok(Err(err)) => {
                self.status_message = Some(err);
                self.cwe_results.clear();
                self.cwe_scroll = 0;
            }
            Err(err) => {
                self.status_message = Some(format!("failed to join CWE task: {err}"));
                self.cwe_results.clear();
                self.cwe_scroll = 0;
            }
        }
    }

    pub(super) fn searching(&self) -> bool {
        self.search.is_some()
    }

    pub(super) fn has_background_task(&self) -> bool {
        self.search.is_some() || self.raw_json_task.is_some() || self.cwe_task.is_some()
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
        } else if self.selected().is_none() {
            "no selection"
        } else {
            "ready"
        }
    }

    pub(super) fn abort_search(&mut self) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }
        if let Some(task) = self.raw_json_task.take() {
            task.abort();
        }
        if let Some(task) = self.cwe_task.take() {
            task.abort();
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

    pub(super) fn toggle_raw_json_mode(&mut self, db: Option<CveDatabase>) {
        if self.view_mode == ViewMode::RawJson {
            self.view_mode = ViewMode::Normal;
            return;
        }
        self.view_mode = ViewMode::RawJson;
        self.raw_scroll = 0;
        let Some(cve_id) = self.selected().map(|cve| cve.summary.cve_id.clone()) else {
            self.raw_json = Some("No CVE selected".to_owned());
            return;
        };
        let Some(db) = db else {
            self.raw_json = Some("Database is unavailable".to_owned());
            return;
        };
        if let Some(task) = self.raw_json_task.take() {
            task.abort();
        }
        self.raw_json = Some("Loading".to_owned());
        self.raw_json_task = Some(tokio::spawn(async move {
            let raw_json = db
                .find_cve_raw_json_by_id(&cve_id)
                .await
                .map_err(|err| format!("failed to load raw JSON: {err}"))?
                .ok_or_else(|| format!("{cve_id} not found"))?;
            serde_json::to_string_pretty(&raw_json)
                .map_err(|err| format!("failed to encode raw JSON: {err}"))
        }));
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
            PaneFocus::Right => PaneFocus::Metadata,
            PaneFocus::Metadata => PaneFocus::Left,
        };
    }

    pub(super) fn previous_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Left => PaneFocus::Metadata,
            PaneFocus::Right => PaneFocus::Left,
            PaneFocus::Metadata => PaneFocus::Right,
        };
    }

    pub(super) fn next_or_load_more(&mut self, db: CveDatabase) {
        if self.results.is_empty() {
            self.list_state.select(None);
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        if current + 1 >= self.results.len() {
            self.start_load_more(db);
            return;
        }
        let next = self
            .list_state
            .selected()
            .map(|index| (index + 1).min(self.results.len() - 1))
            .unwrap_or(0);
        self.list_state.select(Some(next));
    }

    pub(super) fn move_focused_down(&mut self, db: CveDatabase) {
        match self.focus {
            PaneFocus::Left => self.next_or_load_more(db),
            PaneFocus::Right => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
                self.clamp_detail_scroll();
            }
            PaneFocus::Metadata => {
                self.metadata_scroll = self.metadata_scroll.saturating_add(1);
                self.clamp_metadata_scroll();
            }
        }
    }

    pub(super) fn move_focused_up(&mut self) {
        match self.focus {
            PaneFocus::Left => self.previous(),
            PaneFocus::Right => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
                self.clamp_detail_scroll();
            }
            PaneFocus::Metadata => {
                self.metadata_scroll = self.metadata_scroll.saturating_sub(1);
                self.clamp_metadata_scroll();
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
        if self.results.is_empty() {
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
        let max_scroll = self
            .cwe_results
            .len()
            .saturating_sub(page_size.max(MIN_PAGE_SIZE)) as u16;
        self.cwe_scroll = self.cwe_scroll.saturating_add(1).min(max_scroll);
    }

    pub(super) fn move_cwe_up(&mut self) {
        self.cwe_scroll = self.cwe_scroll.saturating_sub(1);
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
        self.searched_request = SearchRequest::Mode {
            mode: SearchMode::FreeText,
            query: String::new(),
            state_scope: CveStateScope::PublishedOnly,
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
            vendor: None,
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
        let error_prefix = error_prefix.to_owned();
        self.search = Some(PendingSearch {
            kind,
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
        let Some(db) = db else {
            self.status_message = Some("database is unavailable".to_owned());
            self.cwe_results.clear();
            return;
        };
        let query = self.cwe_query.clone();
        self.cwe_task = Some(tokio::spawn(async move {
            db.search_cwe_entries(&query, 200)
                .await
                .map_err(|err| format!("failed to search CWE: {err}"))
        }));
    }

    fn move_focused_page(&mut self, db: CveDatabase, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, Some(db)),
            PaneFocus::Right => self.move_detail_page(direction, amount),
            PaneFocus::Metadata => self.move_metadata_page(direction, amount),
        }
    }

    fn move_focused_page_without_db(&mut self, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, None),
            PaneFocus::Right => self.move_detail_page(direction, amount),
            PaneFocus::Metadata => self.move_metadata_page(direction, amount),
        }
    }

    fn move_candidate_page(
        &mut self,
        direction: PageDirection,
        amount: PageAmount,
        db: Option<CveDatabase>,
    ) {
        if self.results.is_empty() {
            self.list_state.select(None);
            return;
        }

        let current = self.list_state.selected().unwrap_or(0);
        let step = self.left_step(amount);
        let next = match direction {
            PageDirection::Up => current.saturating_sub(step),
            PageDirection::Down => current.saturating_add(step).min(self.results.len() - 1),
        };
        self.list_state.select(Some(next));
        if matches!(direction, PageDirection::Down)
            && next + 1 >= self.results.len()
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
        let line_count = self
            .selected()
            .map(|cve| detail_line_count(cve, self.detail_content_width))
            .unwrap_or(1);
        line_count.saturating_sub(self.right_page_size) as u16
    }

    fn max_metadata_scroll(&self) -> u16 {
        let line_count = self
            .selected()
            .map(|cve| metadata_line_count(cve, self.metadata_content_width))
            .unwrap_or(1);
        line_count.saturating_sub(self.metadata_page_size) as u16
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
    }

    fn select_candidate(&mut self, index: usize) {
        if self.results.is_empty() {
            self.list_state.select(None);
        } else {
            self.list_state
                .select(Some(index.min(self.results.len() - 1)));
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

fn detail_line_count(cve: &CveSummaryWithDetail, width: usize) -> usize {
    let description_lines = cve
        .summary
        .description_en
        .as_deref()
        .map(|description| wrapped_line_count(description, width))
        .unwrap_or(1);
    6 + description_lines
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
            wrapped_line_count(
                &format!("{vendor}/{product} pkg:{package} status:{status}{suffix}"),
                width,
            )
        })
        .sum::<usize>()
        .max(1);
    cwe_lines + cvss_lines + affected_lines + 2
}

fn wrapped_line_count(value: &str, width: usize) -> usize {
    let width = width.max(MIN_PAGE_SIZE);
    value
        .lines()
        .map(|line| (line.chars().count().max(1) + width - 1) / width)
        .sum::<usize>()
        .max(1)
}

fn normalize_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn option_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
