use super::{
    EVENT_POLL_MAX, TUI_LIMIT,
    app::{App, MaintenanceChoice, MaintenanceOperation},
    form::AdvancedField,
    terminal::TerminalGuard,
    ui::draw,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use qanvuli_app_commands::{
    common::{IngestProgress, IngestProgressCallback, connect_db},
    init, update,
};
use qanvuli_db::CveDatabase;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{fs::File, future::Future, io, os::fd::AsRawFd, sync::Arc, thread};
use tokio::sync::mpsc;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(value_name = "QUERY")]
    query: Option<String>,
    #[arg(long, default_value_t = TUI_LIMIT)]
    limit: u64,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let mut db = Some(connect_db(db_url).await?);
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
        db.close()
            .await
            .map_err(|err| format!("failed to close database: {err}"))?;
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
        if app.poll_maintenance().await {
            refresh_db_after_maintenance(db_url, db, app).await;
        }
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
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                KeyCode::Char(ch) => {
                    app.advanced.push(ch);
                    app.sync_main_from_advanced();
                }
                KeyCode::Tab => app.advanced.next_field(),
                KeyCode::BackTab => app.advanced.previous_field(),
                KeyCode::Down => app.advanced.next_field(),
                KeyCode::Up => app.advanced.previous_field(),
                KeyCode::Right if app.advanced.active_field == AdvancedField::Query => {
                    app.advanced.query_mode = app.advanced.query_mode.next();
                    app.sync_main_from_advanced();
                }
                KeyCode::Left if app.advanced.active_field == AdvancedField::Query => {
                    app.advanced.query_mode = app.advanced.query_mode.previous();
                    app.sync_main_from_advanced();
                }
                KeyCode::Right => {
                    app.advanced.next_value();
                    app.sync_main_from_advanced();
                }
                KeyCode::Left => {
                    app.advanced.previous_value();
                    app.sync_main_from_advanced();
                }
                _ => {}
            }
            continue;
        }

        if app.show_display {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => app.show_display = false,
                KeyCode::Char('c') | KeyCode::Char('d') if is_ctrl_quit(&key) => break,
                KeyCode::Tab => app.display.next_field(),
                KeyCode::BackTab => app.display.previous_field(),
                KeyCode::Down => app.display.next_field(),
                KeyCode::Up => app.display.previous_field(),
                KeyCode::Right => app.display.next_value(),
                KeyCode::Left => app.display.previous_value(),
                _ => {}
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
                KeyCode::Char('i') => app.maintenance_choice = MaintenanceChoice::Init,
                KeyCode::Char('u') => app.maintenance_choice = MaintenanceChoice::Update,
                KeyCode::Char('c') => app.maintenance_choice = MaintenanceChoice::Cancel,
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Esc => {}
            KeyCode::Char('c') if is_ctrl(&key, 'c') => break,
            KeyCode::Char('u') if is_ctrl(&key, 'u') => {
                app.move_half_page_up();
            }
            KeyCode::Char('d') if is_ctrl(&key, 'd') => {
                if let Some(db) = db.as_ref() {
                    app.move_half_page_down(db.clone());
                }
            }
            KeyCode::Char('f') if is_ctrl(&key, 'f') => {
                if let Some(db) = db.as_ref() {
                    app.move_full_page_down(db.clone());
                }
            }
            KeyCode::Char('b') if is_ctrl(&key, 'b') => {
                app.move_full_page_up();
            }
            KeyCode::F(1) => app.show_help = true,
            KeyCode::F(2) => app.next_search_mode(),
            KeyCode::F(3) => app.open_advanced_search(),
            KeyCode::F(4) => app.open_display_settings(),
            KeyCode::F(5) => app.open_maintenance(),
            KeyCode::Enter => {
                if let Some(db) = db.as_ref() {
                    app.start_search(db.clone());
                }
            }
            KeyCode::Tab => app.toggle_focus(),
            KeyCode::BackTab => app.previous_focus(),
            KeyCode::Left => app.previous_search_mode(),
            KeyCode::Right => app.next_search_mode(),
            KeyCode::Backspace => {
                app.backspace_query();
            }
            KeyCode::Char(ch) => {
                app.push_query(ch);
            }
            KeyCode::Down => {
                if let Some(db) = db.as_ref() {
                    app.move_focused_down(db.clone());
                }
            }
            KeyCode::Up => app.move_focused_up(),
            _ => {}
        }
    }

    app.abort_search();
    Ok(())
}

fn is_ctrl(key: &KeyEvent, ch: char) -> bool {
    matches!(key.code, KeyCode::Char(value) if value == ch)
        && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn is_ctrl_quit(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('c' | 'd')) && key.modifiers.contains(KeyModifiers::CONTROL)
}

async fn start_selected_maintenance(db_url: &str, db: &mut Option<CveDatabase>, app: &mut App) {
    match app.maintenance_choice {
        MaintenanceChoice::Cancel => app.close_maintenance(),
        MaintenanceChoice::Update => {
            let db_url = db_url.to_owned();
            let (progress, progress_rx) = maintenance_progress_channel();
            app.start_maintenance(
                MaintenanceOperation::Update,
                progress_rx,
                spawn_maintenance_task(async move {
                    update::run_default_with_progress(&db_url, progress).await
                }),
            );
        }
        MaintenanceChoice::Init => {
            app.abort_search();
            if let Some(current_db) = db.take()
                && let Err(err) = current_db.close().await
            {
                app.status_message = Some(format!("failed to close database before init: {err}"));
                app.close_maintenance();
                return;
            }
            app.results.clear();
            app.total_results = None;
            let db_url = db_url.to_owned();
            let (progress, progress_rx) = maintenance_progress_channel();
            app.start_maintenance(
                MaintenanceOperation::Init,
                progress_rx,
                spawn_maintenance_task(async move {
                    init::run_default_with_progress(&db_url, progress).await
                }),
            );
        }
    }
}

fn maintenance_progress_channel() -> (
    IngestProgressCallback,
    mpsc::UnboundedReceiver<IngestProgress>,
) {
    let (progress_tx, progress_rx) = mpsc::unbounded_channel();
    let progress = Arc::new(move |progress| {
        let _ = progress_tx.send(progress);
    });
    (progress, progress_rx)
}

fn spawn_maintenance_task<F>(future: F) -> mpsc::UnboundedReceiver<Result<(), String>>
where
    F: Future<Output = Result<(), String>> + Send + 'static,
{
    let (result_tx, result_rx) = mpsc::unbounded_channel();
    thread::spawn(move || {
        let _stderr = StderrSilencer::new();
        let result = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(future),
            Err(err) => Err(format!("failed to build maintenance runtime: {err}")),
        };
        let _ = result_tx.send(result);
    });
    result_rx
}

struct StderrSilencer {
    saved: Option<i32>,
}

impl StderrSilencer {
    fn new() -> Self {
        let Ok(dev_null) = File::options().write(true).open("/dev/null") else {
            return Self { saved: None };
        };
        let saved = unsafe { dup(STDERR_FD) };
        if saved < 0 {
            return Self { saved: None };
        }
        if unsafe { dup2(dev_null.as_raw_fd(), STDERR_FD) } < 0 {
            unsafe {
                close(saved);
            }
            return Self { saved: None };
        }
        Self { saved: Some(saved) }
    }
}

impl Drop for StderrSilencer {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            unsafe {
                let _ = dup2(saved, STDERR_FD);
                close(saved);
            }
        }
    }
}

const STDERR_FD: i32 = 2;

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
}

async fn refresh_db_after_maintenance(db_url: &str, db: &mut Option<CveDatabase>, app: &mut App) {
    if db.is_some() {
        return;
    }
    match connect_db(db_url).await {
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
    match db.latest_cve_zip_datetime().await {
        Ok(Some(value)) => {
            app.db_as_of = Some(value);
        }
        Ok(None) => match db.latest_cve_updated_at().await {
            Ok(value) => {
                app.db_as_of = value;
            }
            Err(err) => {
                app.status_message = Some(format!("failed to read DB timestamp: {err}"));
            }
        },
        Err(err) => {
            app.status_message = Some(format!("failed to read CVE release timestamp: {err}"));
        }
    }
}
