use super::{
    TUI_LOAD_MORE_LIMIT,
    display::DisplaySettings,
    form::AdvancedForm,
    mode::SearchMode,
    search::{SearchRequest, SearchResult, run_search_request},
};
use qanvuli_db::{
    CveAdvancedSearch, CveDatabase, CveStateScope, CveSummarySortOrder, CveSummaryWithDetail,
};
use ratatui::widgets::ListState;
use std::time::Instant;
use tokio::task::JoinHandle;

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
    search: Option<PendingSearch>,
    search_started_at: Option<Instant>,
    searched_request: SearchRequest,
    exhausted: bool,
    left_page_size: usize,
    right_page_size: usize,
    pub(super) show_help: bool,
    pub(super) show_advanced: bool,
    pub(super) show_display: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PaneFocus {
    Left,
    Right,
}

struct PendingSearch {
    kind: SearchKind,
    handle: JoinHandle<Result<SearchResult, String>>,
}

enum SearchKind {
    Replace,
    Append { select_offset: usize },
}

impl App {
    pub(super) fn new(query: String, limit: u64) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        let search_mode = SearchMode::from_query_prefix(&query).unwrap_or(SearchMode::FreeText);
        Self {
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
            search: None,
            search_started_at: None,
            searched_request: SearchRequest::Mode {
                mode: search_mode,
                query: String::new(),
                state_scope: CveStateScope::PublishedOnly,
            },
            exhausted: false,
            left_page_size: 10,
            right_page_size: 10,
            show_help: false,
            show_advanced: false,
            show_display: false,
        }
    }

    pub(super) fn start_search(&mut self, db: CveDatabase) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }

        self.apply_prefix_mode();
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
        let limit = self.limit;
        self.searched_request = request.clone();
        self.exhausted = false;
        self.total_results = None;
        self.search_started_at = Some(Instant::now());
        self.search = Some(PendingSearch {
            kind: SearchKind::Replace,
            handle: tokio::spawn(async move {
                run_search_request(db, request, limit, 0)
                    .await
                    .map_err(|err| format!("failed to search: {err}"))
            }),
        });
    }

    pub(super) fn start_advanced_search(&mut self, db: CveDatabase) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }

        self.query = self.advanced.query.clone();
        self.search_mode = self.advanced.query_mode;
        self.state_scope = self.advanced.state_scope;
        let request =
            SearchRequest::Advanced(self.advanced.to_search_options(self.display.sort_order()));
        self.searched_request = request.clone();
        self.exhausted = false;
        self.total_results = None;
        self.search_started_at = Some(Instant::now());
        let limit = self.limit;
        self.search = Some(PendingSearch {
            kind: SearchKind::Replace,
            handle: tokio::spawn(async move {
                run_search_request(db, request, limit, 0)
                    .await
                    .map_err(|err| format!("failed to search: {err}"))
            }),
        });
    }

    pub(super) fn open_advanced_search(&mut self) {
        self.apply_prefix_mode();
        self.advanced.query = self.query.clone();
        self.advanced.query_mode = self.search_mode;
        self.advanced.state_scope = self.state_scope;
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
        self.search_started_at = Some(Instant::now());
        self.search = Some(PendingSearch {
            kind: SearchKind::Append { select_offset },
            handle: tokio::spawn(async move {
                run_search_request(db, request, TUI_LOAD_MORE_LIMIT, offset)
                    .await
                    .map_err(|err| format!("failed to load more search results: {err}"))
            }),
        });
    }

    pub(super) async fn poll_search(&mut self) -> Result<(), String> {
        let Some(search) = self.search.as_ref() else {
            return Ok(());
        };
        if !search.handle.is_finished() {
            return Ok(());
        }

        let search = self.search.take().expect("search handle disappeared");
        let kind = search.kind;
        let result = search
            .handle
            .await
            .map_err(|err| format!("failed to join search task: {err}"))??;
        self.search_started_at = None;
        match kind {
            SearchKind::Replace => {
                self.exhausted = result.rows.len() < self.limit as usize;
                self.total_results = Some(result.total);
                self.results = result.rows;
                self.clear_detail();
                if self.results.is_empty() {
                    self.list_state.select(None);
                } else {
                    self.list_state.select(Some(0));
                }
            }
            SearchKind::Append { select_offset } => {
                self.exhausted = result.rows.len() < TUI_LOAD_MORE_LIMIT as usize;
                self.total_results = Some(result.total);
                self.results.extend(result.rows);
                if self.results.is_empty() {
                    self.list_state.select(None);
                } else {
                    let next = select_offset.min(self.results.len() - 1);
                    self.list_state.select(Some(next));
                }
            }
        }
        Ok(())
    }

    pub(super) fn searching(&self) -> bool {
        self.search.is_some()
    }

    pub(super) fn detail_status(&self) -> &'static str {
        if self.selected().is_none() {
            "Detail: no selection"
        } else {
            "Detail: loaded"
        }
    }

    pub(super) fn abort_search(&mut self) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }
        self.search_started_at = None;
    }

    pub(super) fn spinner(&self) -> &'static str {
        const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
        let frame = self
            .search_started_at
            .map(|started_at| (started_at.elapsed().as_millis() / 150) as usize)
            .unwrap_or(0);
        FRAMES[frame % FRAMES.len()]
    }

    pub(super) fn selected(&self) -> Option<&CveSummaryWithDetail> {
        self.list_state
            .selected()
            .and_then(|index| self.results.get(index))
    }

    pub(super) fn set_page_sizes(&mut self, left: usize, right: usize) {
        self.left_page_size = left.max(MIN_PAGE_SIZE);
        self.right_page_size = right.max(MIN_PAGE_SIZE);
        self.clamp_detail_scroll();
    }

    pub(super) fn clamp_detail_scroll_to_lines(&mut self, line_count: usize) {
        let max_scroll = line_count.saturating_sub(self.right_page_size) as u16;
        self.detail_scroll = self.detail_scroll.min(max_scroll);
    }

    pub(super) fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Left => PaneFocus::Right,
            PaneFocus::Right => PaneFocus::Left,
        };
    }

    pub(super) fn focus_left(&mut self) {
        self.focus = PaneFocus::Left;
    }

    pub(super) fn focus_right(&mut self) {
        self.focus = PaneFocus::Right;
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
        }
    }

    pub(super) fn move_focused_up(&mut self) {
        match self.focus {
            PaneFocus::Left => self.previous(),
            PaneFocus::Right => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
                self.clamp_detail_scroll();
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
        self.detail_scroll = 0;
        self.searched_request = SearchRequest::Mode {
            mode: SearchMode::FreeText,
            query: String::new(),
            state_scope: CveStateScope::PublishedOnly,
        };
        self.exhausted = false;
        self.show_help = false;
        self.show_advanced = false;
        self.show_display = false;
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

    fn move_focused_page(&mut self, db: CveDatabase, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, Some(db)),
            PaneFocus::Right => self.move_detail_page(direction, amount),
        }
    }

    fn move_focused_page_without_db(&mut self, direction: PageDirection, amount: PageAmount) {
        match self.focus {
            PaneFocus::Left => self.move_candidate_page(direction, amount, None),
            PaneFocus::Right => self.move_detail_page(direction, amount),
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

    fn clamp_detail_scroll(&mut self) {
        self.detail_scroll = self.detail_scroll.min(self.max_detail_scroll());
    }

    fn max_detail_scroll(&self) -> u16 {
        let line_count = self.selected().map(detail_line_count).unwrap_or(1);
        line_count.saturating_sub(self.right_page_size) as u16
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

    fn clear_detail(&mut self) {
        self.detail_scroll = 0;
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

fn detail_line_count(cve: &CveSummaryWithDetail) -> usize {
    let description_lines = cve
        .summary
        .description_en
        .as_deref()
        .map(|description| description.lines().count().max(1))
        .unwrap_or(1);
    6 + description_lines
}

fn option_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
