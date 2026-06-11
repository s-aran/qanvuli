use super::common::connect_db;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use qanvuli_db::{CveAdvancedSearch, CveDatabase, CveSummary, CveSummarySortOrder};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

const TUI_LIMIT: u64 = 30;
const TUI_LOAD_MORE_LIMIT: u64 = 30;
const EVENT_POLL_MAX: Duration = Duration::from_millis(50);

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(value_name = "QUERY")]
    query: Option<String>,
    #[arg(long, default_value_t = TUI_LIMIT)]
    limit: u64,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new(args.query.unwrap_or_default(), args.limit);
    if !app.query.is_empty() {
        app.start_search(db.clone());
    }

    let result = run_loop(&mut terminal.terminal, &db, &mut app).await;
    terminal.leave()?;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    db: &CveDatabase,
    app: &mut App,
) -> Result<(), String> {
    loop {
        app.poll_search().await?;
        if app.searching() {
            tokio::task::yield_now().await;
        }

        terminal
            .draw(|frame| draw(frame, app))
            .map_err(|err| format!("failed to draw TUI: {err}"))?;

        if !event::poll(EVENT_POLL_MAX)
            .map_err(|err| format!("failed to poll terminal event: {err}"))?
        {
            continue;
        }

        let Event::Key(key) =
            event::read().map_err(|err| format!("failed to read terminal event: {err}"))?
        else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }

        if app.show_help {
            match key.code {
                KeyCode::Esc => app.show_help = false,
                KeyCode::Char('c') | KeyCode::Char('d')
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                {
                    break;
                }
                _ => {}
            }
            continue;
        }

        if app.show_advanced {
            match key.code {
                KeyCode::Esc => app.show_advanced = false,
                KeyCode::Enter => {
                    app.start_advanced_search(db.clone());
                    app.show_advanced = false;
                }
                KeyCode::Backspace => app.advanced.backspace(),
                KeyCode::Char('c') | KeyCode::Char('d')
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                {
                    break;
                }
                KeyCode::Char(ch) => app.advanced.push(ch),
                KeyCode::Tab => app.advanced.next_field(),
                KeyCode::BackTab => app.advanced.previous_field(),
                KeyCode::Down => app.advanced.next_field(),
                KeyCode::Up => app.advanced.previous_field(),
                KeyCode::Right => app.advanced.next_sort_order(),
                KeyCode::Left => app.advanced.previous_sort_order(),
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Esc => {}
            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
            KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
            KeyCode::F(1) => app.show_help = true,
            KeyCode::F(3) => app.show_advanced = true,
            KeyCode::Enter => app.start_search(db.clone()),
            KeyCode::BackTab => app.next_search_mode(),
            KeyCode::Backspace => {
                app.query.pop();
                app.apply_prefix_mode();
            }
            KeyCode::Char(ch) => {
                app.query.push(ch);
                app.apply_prefix_mode();
            }
            KeyCode::Down => app.next_or_load_more(db.clone()),
            KeyCode::Up => app.previous(),
            _ => {}
        }
    }

    app.abort_search();
    Ok(())
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(frame.area());
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(chunks[0]);

    let input_title = if app.searching() {
        format!("Search - searching {}", app.spinner())
    } else {
        format!("Search - limit {}", app.limit)
    };
    let input = Paragraph::new(app.query.as_str())
        .block(
            Block::default()
                .title(input_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.search_mode.color())),
        )
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(input, left[0]);

    let items = app
        .results
        .iter()
        .map(|cve| {
            ListItem::new(vec![
                Line::from(Span::raw(cve.cve_id.clone())),
                Line::from(Span::raw(cve.title.clone())),
            ])
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title(format!("Candidates ({})", app.results.len()))
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, left[1], &mut app.list_state);

    let footer = Paragraph::new(app.search_mode.footer_text()).style(
        Style::default()
            .fg(app.search_mode.color())
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(footer, left[2]);

    let detail = app
        .selected()
        .map(detail_lines)
        .unwrap_or_else(|| vec![Line::from("No results")]);
    let detail = Paragraph::new(detail)
        .block(Block::default().title("CVE").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, chunks[1]);

    if app.show_help {
        draw_help(frame);
    }
    if app.show_advanced {
        draw_advanced(frame, app);
    }
}

fn draw_help(frame: &mut ratatui::Frame<'_>) {
    let area = centered_rect(56, 34, frame.area());
    let help = Paragraph::new(vec![
        Line::from("Enter  Search current input"),
        Line::from("F3     Open advanced search"),
        Line::from("Shift+Tab Switch search mode"),
        Line::from("Up/Down Move selected CVE"),
        Line::from("F1     Show this help"),
        Line::from("Esc    Close this help"),
        Line::from("Ctrl-C Quit"),
        Line::from("Ctrl-D Quit"),
    ])
    .block(Block::default().title("Help").borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(help, area);
}

fn draw_advanced(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(70, 58, frame.area());
    let form = &app.advanced;
    let lines = vec![
        advanced_line(
            form,
            AdvancedField::PublishedFrom,
            "Published from",
            &form.published_from,
        ),
        advanced_line(
            form,
            AdvancedField::PublishedTo,
            "Published to",
            &form.published_to,
        ),
        advanced_line(form, AdvancedField::Cwe, "CWE", &form.cwe),
        advanced_line(form, AdvancedField::Product, "Product", &form.product),
        advanced_line(form, AdvancedField::Vendor, "Vendor", &form.vendor),
        advanced_line(
            form,
            AdvancedField::SortOrder,
            "Sort order",
            form.sort_order.label(),
        ),
        Line::from(""),
        Line::from(
            "Enter search  Esc close  Tab/Down next  Shift+Tab/Up previous  Left/Right sort",
        ),
    ];
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Advanced Search")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn advanced_line(
    form: &AdvancedForm,
    field: AdvancedField,
    label: &'static str,
    value: &str,
) -> Line<'static> {
    let active = form.active_field == field;
    let marker = if active { "> " } else { "  " };
    let style = if active {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(marker, style),
        Span::styled(format!("{label}: "), style),
        Span::raw(value.to_owned()),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn detail_lines(cve: &CveSummary) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.cve_id.clone()),
        ]),
        Line::from(vec![
            Span::styled("State: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.state.clone()),
        ]),
        Line::from(vec![
            Span::styled("Published: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.published_at.clone()),
        ]),
        Line::from(vec![
            Span::styled("Updated: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.updated_at.clone()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            cve.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(cve.description_en.clone().unwrap_or_default()),
    ]
}

struct App {
    query: String,
    search_mode: SearchMode,
    advanced: AdvancedForm,
    limit: u64,
    results: Vec<CveSummary>,
    list_state: ListState,
    search: Option<PendingSearch>,
    search_started_at: Option<Instant>,
    searched_request: SearchRequest,
    exhausted: bool,
    show_help: bool,
    show_advanced: bool,
}

struct PendingSearch {
    kind: SearchKind,
    handle: JoinHandle<Result<Vec<CveSummary>, String>>,
}

enum SearchKind {
    Replace,
    Append { select_offset: usize },
}

#[derive(Clone, Debug)]
enum SearchRequest {
    Mode { mode: SearchMode, query: String },
    Advanced(CveAdvancedSearch),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

#[derive(Clone, Debug)]
struct AdvancedForm {
    published_from: String,
    published_to: String,
    cwe: String,
    product: String,
    vendor: String,
    sort_order: CveSummarySortOrder,
    active_field: AdvancedField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdvancedField {
    PublishedFrom,
    PublishedTo,
    Cwe,
    Product,
    Vendor,
    SortOrder,
}

impl App {
    fn new(query: String, limit: u64) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        let search_mode = SearchMode::from_query_prefix(&query).unwrap_or(SearchMode::FreeText);
        Self {
            query,
            search_mode,
            advanced: AdvancedForm::default(),
            limit,
            results: Vec::new(),
            list_state,
            search: None,
            search_started_at: None,
            searched_request: SearchRequest::Mode {
                mode: search_mode,
                query: String::new(),
            },
            exhausted: false,
            show_help: false,
            show_advanced: false,
        }
    }

    fn start_search(&mut self, db: CveDatabase) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }

        self.apply_prefix_mode();
        let request = SearchRequest::Mode {
            mode: self.search_mode,
            query: self.query.clone(),
        };
        let limit = self.limit;
        self.searched_request = request.clone();
        self.exhausted = false;
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

    fn start_advanced_search(&mut self, db: CveDatabase) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }

        let request = SearchRequest::Advanced(self.advanced.to_search_options());
        self.searched_request = request.clone();
        self.exhausted = false;
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

    fn start_load_more(&mut self, db: CveDatabase) {
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

    async fn poll_search(&mut self) -> Result<(), String> {
        let Some(search) = self.search.as_ref() else {
            return Ok(());
        };
        if !search.handle.is_finished() {
            return Ok(());
        }

        let search = self.search.take().expect("search handle disappeared");
        let kind = search.kind;
        let rows = search
            .handle
            .await
            .map_err(|err| format!("failed to join search task: {err}"))??;
        self.search_started_at = None;
        match kind {
            SearchKind::Replace => {
                self.exhausted = rows.len() < self.limit as usize;
                self.results = rows;
                if self.results.is_empty() {
                    self.list_state.select(None);
                } else {
                    self.list_state.select(Some(0));
                }
            }
            SearchKind::Append { select_offset } => {
                self.exhausted = rows.len() < TUI_LOAD_MORE_LIMIT as usize;
                self.results.extend(rows);
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

    fn searching(&self) -> bool {
        self.search.is_some()
    }

    fn abort_search(&mut self) {
        if let Some(search) = self.search.take() {
            search.handle.abort();
        }
        self.search_started_at = None;
    }

    fn spinner(&self) -> &'static str {
        const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
        let frame = self
            .search_started_at
            .map(|started_at| (started_at.elapsed().as_millis() / 150) as usize)
            .unwrap_or(0);
        FRAMES[frame % FRAMES.len()]
    }

    fn selected(&self) -> Option<&CveSummary> {
        self.list_state
            .selected()
            .and_then(|index| self.results.get(index))
    }

    fn next_or_load_more(&mut self, db: CveDatabase) {
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

    fn previous(&mut self) {
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

    fn next_search_mode(&mut self) {
        self.search_mode = self.search_mode.next();
    }

    fn apply_prefix_mode(&mut self) {
        if let Some(mode) = SearchMode::from_query_prefix(&self.query) {
            self.search_mode = mode;
        }
    }
}

async fn run_search_request(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, String> {
    match request {
        SearchRequest::Mode { mode, query } => mode.search(&db, &query, limit, offset).await,
        SearchRequest::Advanced(options) => db
            .search_cve_summaries_advanced(&options, limit, offset)
            .await
            .map_err(|err| err.to_string()),
    }
}

impl SearchMode {
    fn next(self) -> Self {
        match self {
            Self::FreeText => Self::Product,
            Self::Product => Self::Vendor,
            Self::Vendor => Self::Cwe,
            Self::Cwe => Self::Cve,
            Self::Cve => Self::FreeText,
        }
    }

    fn from_query_prefix(query: &str) -> Option<Self> {
        let query = query.trim_start();
        if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CWE-"))
        {
            Some(Self::Cwe)
        } else if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CVE-"))
        {
            Some(Self::Cve)
        } else {
            None
        }
    }

    async fn search(
        self,
        db: &CveDatabase,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, String> {
        match self {
            Self::FreeText => {
                db.search_cve_summaries_free_text(query, limit, offset)
                    .await
            }
            Self::Product => {
                db.search_cve_summaries_by_vendor_product(None, Some(query), limit, offset)
                    .await
            }
            Self::Vendor => {
                db.search_cve_summaries_by_vendor_product(Some(query), None, limit, offset)
                    .await
            }
            Self::Cwe => {
                db.search_cve_summaries_by_cwe(&[query.to_owned()], limit, offset)
                    .await
            }
            Self::Cve => {
                db.search_cve_summaries_by_cve_id_prefix(query, limit, offset)
                    .await
            }
        }
        .map_err(|err| err.to_string())
    }

    fn footer_text(self) -> &'static str {
        match self {
            Self::FreeText => "Mode: free text",
            Self::Product => "Mode: product",
            Self::Vendor => "Mode: vendor",
            Self::Cwe => "Mode: CWE",
            Self::Cve => "Mode: CVE prefix",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::FreeText => Color::Cyan,
            Self::Product => Color::Green,
            Self::Vendor => Color::Magenta,
            Self::Cwe => Color::Yellow,
            Self::Cve => Color::Blue,
        }
    }
}

impl Default for AdvancedForm {
    fn default() -> Self {
        Self {
            published_from: String::new(),
            published_to: String::new(),
            cwe: String::new(),
            product: String::new(),
            vendor: String::new(),
            sort_order: CveSummarySortOrder::PublishedDesc,
            active_field: AdvancedField::PublishedFrom,
        }
    }
}

impl AdvancedForm {
    fn push(&mut self, ch: char) {
        if let Some(field) = self.active_text_mut() {
            field.push(ch);
        }
    }

    fn backspace(&mut self) {
        if let Some(field) = self.active_text_mut() {
            field.pop();
        }
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            AdvancedField::PublishedFrom => Some(&mut self.published_from),
            AdvancedField::PublishedTo => Some(&mut self.published_to),
            AdvancedField::Cwe => Some(&mut self.cwe),
            AdvancedField::Product => Some(&mut self.product),
            AdvancedField::Vendor => Some(&mut self.vendor),
            AdvancedField::SortOrder => None,
        }
    }

    fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    fn next_sort_order(&mut self) {
        if self.active_field == AdvancedField::SortOrder {
            self.sort_order = self.sort_order.next();
        }
    }

    fn previous_sort_order(&mut self) {
        if self.active_field == AdvancedField::SortOrder {
            self.sort_order = self.sort_order.previous();
        }
    }

    fn to_search_options(&self) -> CveAdvancedSearch {
        CveAdvancedSearch {
            published_from: option_string(&self.published_from),
            published_to: option_string(&self.published_to),
            cwe: option_string(&self.cwe),
            product: option_string(&self.product),
            vendor: option_string(&self.vendor),
            sort_order: self.sort_order,
        }
    }
}

impl AdvancedField {
    fn next(self) -> Self {
        match self {
            Self::PublishedFrom => Self::PublishedTo,
            Self::PublishedTo => Self::Cwe,
            Self::Cwe => Self::Product,
            Self::Product => Self::Vendor,
            Self::Vendor => Self::SortOrder,
            Self::SortOrder => Self::PublishedFrom,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::PublishedFrom => Self::SortOrder,
            Self::PublishedTo => Self::PublishedFrom,
            Self::Cwe => Self::PublishedTo,
            Self::Product => Self::Cwe,
            Self::Vendor => Self::Product,
            Self::SortOrder => Self::Vendor,
        }
    }
}

trait SortOrderUi {
    fn next(self) -> Self;
    fn previous(self) -> Self;
    fn label(self) -> &'static str;
}

impl SortOrderUi for CveSummarySortOrder {
    fn next(self) -> Self {
        match self {
            Self::PublishedAsc => Self::PublishedDesc,
            Self::PublishedDesc => Self::CveIdAsc,
            Self::CveIdAsc => Self::CveIdDesc,
            Self::CveIdDesc => Self::RelationRankAsc,
            Self::RelationRankAsc => Self::RelationRankDesc,
            Self::RelationRankDesc => Self::ScoreAsc,
            Self::ScoreAsc => Self::ScoreDesc,
            Self::ScoreDesc => Self::PublishedAsc,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::PublishedAsc => Self::ScoreDesc,
            Self::PublishedDesc => Self::PublishedAsc,
            Self::CveIdAsc => Self::PublishedDesc,
            Self::CveIdDesc => Self::CveIdAsc,
            Self::RelationRankAsc => Self::CveIdDesc,
            Self::RelationRankDesc => Self::RelationRankAsc,
            Self::ScoreAsc => Self::RelationRankDesc,
            Self::ScoreDesc => Self::ScoreAsc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PublishedAsc => "published asc",
            Self::PublishedDesc => "published desc",
            Self::CveIdAsc => "a-z asc",
            Self::CveIdDesc => "a-z desc",
            Self::RelationRankAsc => "relation rank asc",
            Self::RelationRankDesc => "relation rank desc",
            Self::ScoreAsc => "score asc",
            Self::ScoreDesc => "score desc",
        }
    }
}

fn option_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|err| format!("failed to enable raw mode: {err}"))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)
            .map_err(|err| format!("failed to enter alternate screen: {err}"))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal =
            Terminal::new(backend).map_err(|err| format!("failed to init TUI: {err}"))?;
        Ok(Self {
            terminal,
            active: true,
        })
    }

    fn leave(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        disable_raw_mode().map_err(|err| format!("failed to disable raw mode: {err}"))?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)
            .map_err(|err| format!("failed to leave alternate screen: {err}"))?;
        self.terminal
            .show_cursor()
            .map_err(|err| format!("failed to show cursor: {err}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}
