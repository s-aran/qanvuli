use super::{
    EVENT_POLL_MAX, TUI_LIMIT,
    app::{App, MaintenanceChoice, MaintenanceOperation, ViewMode},
    common::input::{is_ctrl, is_ctrl_quit},
    db::connection,
    display::DisplayTab,
    form::AdvancedField,
    modes,
    terminal::TerminalGuard,
    ui::draw,
    utils::task::{maintenance_progress_channel, spawn_maintenance_task},
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use qanvuli_app_commands::{init, update};
use qanvuli_core::database::CveDatabase;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;

/// CLI arguments for `qanvuli tui`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(value_name = "QUERY")]
    query: Option<String>,
    #[arg(long, default_value_t = TUI_LIMIT)]
    limit: u64,
}

/// Opens the interactive terminal UI for local CVE search and maintenance.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let mut db = Some(connection::connect(db_url).await?);
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new(args.query.unwrap_or_default(), args.limit);
    if let Some(db) = db.as_ref() {
        update_db_as_of(&mut app, db).await;
    }
    if !app.query.is_empty()
        && let Some(db) = db.as_ref()
    {
        app.start_search(db.clone());
    }

    let result = run_loop(&mut terminal.terminal, db_url, &mut db, &mut app).await;
    terminal.leave()?;
    if let Some(db) = db.take() {
        connection::close(db).await?;
    }
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    db_url: &str,
    db: &mut Option<CveDatabase>,
    app: &mut App,
) -> Result<(), String> {
    loop {
        app.poll_search().await?;
        app.poll_count().await;
        app.poll_raw_json().await;
        app.poll_enrichment().await;
        app.poll_cwe_search().await;
        app.poll_scope_candidates().await;
        app.ensure_loaded_enrichment(db.as_ref().cloned());
        if app.poll_maintenance().await {
            refresh_db_after_maintenance(db_url, db, app).await;
        }
        if app.has_background_task() {
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

        if app.maintenance_running() && is_ctrl(&key, 'c') {
            break;
        }
        if app.maintenance_running() {
            continue;
        }

        if is_ctrl(&key, 'l') {
            terminal
                .clear()
                .map_err(|err| format!("failed to clear TUI: {err}"))?;
            app.reset_screen();
            continue;
        }

        if app.show_timeout_prompt {
            match key.code {
                KeyCode::Enter => app.confirm_timeout_choice(),
                KeyCode::Esc => app.cancel_timed_out_search(),
                KeyCode::Left => app.select_timeout_continue(),
                KeyCode::Right => app.select_timeout_cancel(),
                KeyCode::Tab | KeyCode::BackTab => app.toggle_timeout_choice(),
                KeyCode::Char('c') if is_ctrl(&key, 'c') => break,
                KeyCode::Char('c') => app.select_timeout_continue(),
                KeyCode::Char('x') => app.select_timeout_cancel(),
                _ => {}
            }
            continue;
        }

        if app.show_help {
            match key.code {
                KeyCode::Esc => app.show_help = false,
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                _ => {}
            }
            continue;
        }

        if app.show_advanced {
            match key.code {
                KeyCode::Esc => app.show_advanced = false,
                KeyCode::Enter => {
                    if let Some(db) = db.as_ref() {
                        app.start_advanced_search(db.clone());
                    }
                    app.show_advanced = false;
                }
                KeyCode::Backspace => {
                    app.advanced.backspace();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char(' ') if app.advanced.active_field_accepts_text() => {
                    app.advanced.push(' ');
                    app.sync_main_from_advanced();
                }
                KeyCode::Char(' ') => {
                    app.advanced.toggle_current();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                KeyCode::Tab | KeyCode::Down => app.advanced.next_field(),
                KeyCode::BackTab | KeyCode::Up => app.advanced.previous_field(),
                KeyCode::Char(']') if app.advanced.active_field == AdvancedField::Query => {
                    app.advanced.query_mode = app.advanced.query_mode.next();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char('[') if app.advanced.active_field == AdvancedField::Query => {
                    app.advanced.query_mode = app.advanced.query_mode.previous();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char(']') => {
                    app.advanced.next_value();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char('[') => {
                    app.advanced.previous_value();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char(ch) => {
                    app.advanced.push(ch);
                    app.sync_main_from_advanced();
                }
                _ => {}
            }
            continue;
        }

        if app.show_display {
            if app.display.tab == DisplayTab::Sources {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => app.show_display = false,
                    KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                    KeyCode::Left => app.display.previous_tab(),
                    KeyCode::Right => app.display.next_tab(),
                    KeyCode::Backspace => app.advanced.backspace_scope_filter(),
                    KeyCode::Char(' ') => app.advanced.toggle_scope_current(),
                    KeyCode::Char('a') => app.advanced.select_all_scope(),
                    KeyCode::Char('x') => app.advanced.clear_all_scope(),
                    KeyCode::Char(ch) => app.advanced.push_scope_filter(ch),
                    KeyCode::Tab | KeyCode::Down => app.advanced.next_scope(),
                    KeyCode::BackTab | KeyCode::Up => app.advanced.previous_scope(),
                    KeyCode::PageDown => app.advanced.page_down_scope(),
                    KeyCode::PageUp => app.advanced.page_up_scope(),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => app.show_display = false,
                    KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                    KeyCode::Tab => app.display.next_field(),
                    KeyCode::BackTab => app.display.previous_field(),
                    KeyCode::Down => app.display.next_field(),
                    KeyCode::Up => app.display.previous_field(),
                    KeyCode::Right => app.display.next_tab(),
                    KeyCode::Left => app.display.previous_tab(),
                    KeyCode::Char(']') => app.display.next_value(),
                    KeyCode::Char('[') => app.display.previous_value(),
                    _ => {}
                }
            }
            continue;
        }

        if app.show_maintenance {
            match key.code {
                KeyCode::Esc => app.close_maintenance(),
                KeyCode::Enter => {
                    start_selected_maintenance(db_url, db, app).await;
                }
                KeyCode::Char('c') if is_ctrl(&key, 'c') => break,
                KeyCode::Tab | KeyCode::Down | KeyCode::Right => {
                    app.next_maintenance_choice();
                }
                KeyCode::BackTab | KeyCode::Up | KeyCode::Left => {
                    app.previous_maintenance_choice();
                }
                KeyCode::Char(' ') | KeyCode::Char('k') => {
                    app.toggle_maintenance_keep_downloads();
                }
                KeyCode::Char('i') => app.maintenance_choice = MaintenanceChoice::Init,
                KeyCode::Char('u') => app.maintenance_choice = MaintenanceChoice::Update,
                KeyCode::Char('c') => app.maintenance_choice = MaintenanceChoice::Cancel,
                _ => {}
            }
            continue;
        }

        if app.detail_search_input {
            match key.code {
                KeyCode::Esc => app.close_detail_search(),
                KeyCode::Enter => app.close_detail_search(),
                KeyCode::Backspace => app.backspace_detail_search(),
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                KeyCode::Char(ch) => app.push_detail_search(ch),
                _ => {}
            }
            continue;
        }

        if app.show_cwe_status {
            match key.code {
                KeyCode::Esc => app.close_cwe_status_popup(),
                KeyCode::Enter => {
                    if !app.activate_cwe_status_control(db.as_ref().cloned()) {
                        app.close_cwe_status_popup();
                    }
                }
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                KeyCode::Down | KeyCode::Tab => app.next_cwe_status(),
                KeyCode::Up | KeyCode::BackTab => app.previous_cwe_status(),
                KeyCode::Char(' ') => app.toggle_current_cwe_status(db.as_ref().cloned()),
                KeyCode::Char('a') => app.select_all_cwe_statuses(db.as_ref().cloned()),
                KeyCode::Char('x') => app.clear_all_cwe_statuses(db.as_ref().cloned()),
                _ => {}
            }
            continue;
        }

        if app.view_mode == ViewMode::RawJson {
            if modes::raw_json::handler::handle_key(
                app,
                db.as_ref().cloned(),
                &key,
                terminal.size().ok(),
            ) {
                break;
            }
            continue;
        }

        if app.view_mode == ViewMode::CweList {
            if modes::cwe::handler::handle_key(
                app,
                db.as_ref().cloned(),
                &key,
                terminal.size().ok(),
            ) {
                break;
            }
            continue;
        }

        if modes::main::handler::handle_key(app, db.as_ref().cloned(), &key) {
            break;
        }
    }

    app.abort_search();
    Ok(())
}

async fn start_selected_maintenance(db_url: &str, db: &mut Option<CveDatabase>, app: &mut App) {
    let keep_downloads = app.maintenance_keep_downloads;
    match app.maintenance_choice {
        MaintenanceChoice::Cancel => app.close_maintenance(),
        MaintenanceChoice::Update => {
            if let Err(err) = close_db_before_maintenance(db, app, "update").await {
                app.status_message = Some(err);
                app.close_maintenance();
                return;
            }
            let db_url = db_url.to_owned();
            let (progress, progress_rx) = maintenance_progress_channel();
            app.start_maintenance(
                MaintenanceOperation::Update,
                progress_rx,
                spawn_maintenance_task(async move {
                    update::run_default_with_progress_and_keep(&db_url, progress, keep_downloads)
                        .await
                }),
            );
        }
        MaintenanceChoice::Init => {
            if let Err(err) = close_db_before_maintenance(db, app, "init").await {
                app.status_message = Some(err);
                app.close_maintenance();
                return;
            }
            let db_url = db_url.to_owned();
            let (progress, progress_rx) = maintenance_progress_channel();
            app.start_maintenance(
                MaintenanceOperation::Init,
                progress_rx,
                spawn_maintenance_task(async move {
                    init::run_default_with_progress_and_keep(&db_url, progress, keep_downloads)
                        .await
                }),
            );
        }
    }
}

async fn close_db_before_maintenance(
    db: &mut Option<CveDatabase>,
    app: &mut App,
    operation: &str,
) -> Result<(), String> {
    app.abort_search();
    if let Some(current_db) = db.take() {
        connection::close(current_db)
            .await
            .map_err(|err| format!("failed to close database before {operation}: {err}"))?;
    }
    app.results.clear();
    app.osv_results.clear();
    app.enrichment.clear();
    app.total_results = None;
    Ok(())
}

async fn refresh_db_after_maintenance(db_url: &str, db: &mut Option<CveDatabase>, app: &mut App) {
    if let Some(current_db) = db.take()
        && let Err(err) = connection::close(current_db).await
    {
        app.status_message = Some(format!("failed to close stale database connection: {err}"));
    }
    match connection::connect(db_url).await {
        Ok(reconnected) => {
            update_db_as_of(app, &reconnected).await;
            *db = Some(reconnected);
        }
        Err(err) => {
            app.status_message = Some(format!("{err}; database is unavailable"));
        }
    }
}

async fn update_db_as_of(app: &mut App, db: &CveDatabase) {
    match connection::latest_data_timestamp(db).await {
        Ok(value) => app.db_as_of = value,
        Err(err) => {
            app.status_message = Some(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn close_db_before_maintenance_drops_connection_and_clears_search_state() {
        let mut db = Some(CveDatabase::connect("sqlite::memory:").await.unwrap());
        let mut app = App::new("django".to_owned(), 30);
        app.total_results = Some(42);
        app.status_message = Some("existing status".to_owned());

        close_db_before_maintenance(&mut db, &mut app, "update")
            .await
            .unwrap();

        assert!(db.is_none());
        assert!(app.results.is_empty());
        assert!(app.enrichment.is_empty());
        assert_eq!(app.total_results, None);
    }

    #[tokio::test]
    async fn poll_maintenance_consumes_success_and_requests_refresh() {
        let (_progress_tx, progress_rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = mpsc::unbounded_channel();
        let mut app = App::new(String::new(), 30);
        app.start_maintenance(MaintenanceOperation::Update, progress_rx, result_rx);
        result_tx.send(Ok(())).unwrap();

        assert!(app.poll_maintenance().await);
        assert!(!app.maintenance_running());
        assert_eq!(app.status_message.as_deref(), Some("update completed"));
        assert!(app.maintenance_progress.is_none());
        assert!(!app.show_maintenance);
    }

    #[tokio::test]
    async fn poll_maintenance_reports_failure_and_requests_refresh() {
        let (_progress_tx, progress_rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = mpsc::unbounded_channel();
        let mut app = App::new(String::new(), 30);
        app.start_maintenance(MaintenanceOperation::Init, progress_rx, result_rx);
        result_tx.send(Err("boom".to_owned())).unwrap();

        assert!(app.poll_maintenance().await);
        assert!(!app.maintenance_running());
        assert_eq!(app.status_message.as_deref(), Some("init failed: boom"));
        assert!(app.maintenance_progress.is_none());
        assert!(!app.show_maintenance);
    }
}
