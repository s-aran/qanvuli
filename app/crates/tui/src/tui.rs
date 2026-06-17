use super::{
    EVENT_POLL_MAX, TUI_LIMIT, app::App, form::AdvancedField, terminal::TerminalGuard, ui::draw,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use qanvuli_app_commands::common::connect_db;
use qanvuli_db::CveDatabase;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;

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

        if matches!(key.code, KeyCode::Char('l'))
            && key.modifiers.contains(event::KeyModifiers::CONTROL)
        {
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
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    break;
                }
                KeyCode::Char('c') => app.select_timeout_continue(),
                KeyCode::Char('x') => app.select_timeout_cancel(),
                _ => {}
            }
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
                KeyCode::Backspace => {
                    app.advanced.backspace();
                    app.sync_main_from_advanced();
                }
                KeyCode::Char('c') | KeyCode::Char('d')
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                {
                    break;
                }
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
                KeyCode::Char('c') | KeyCode::Char('d')
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                {
                    break;
                }
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

        match key.code {
            KeyCode::Esc => {}
            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
            KeyCode::Char('u') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                app.move_half_page_up();
            }
            KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                app.move_half_page_down(db.clone());
            }
            KeyCode::Char('f') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                app.move_full_page_down(db.clone());
            }
            KeyCode::Char('b') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                app.move_full_page_up();
            }
            KeyCode::F(1) => app.show_help = true,
            KeyCode::F(3) => app.open_advanced_search(),
            KeyCode::F(4) => app.open_display_settings(),
            KeyCode::Enter => app.start_search(db.clone()),
            KeyCode::Tab => app.toggle_focus(),
            KeyCode::Left => app.focus_left(),
            KeyCode::Right => app.focus_right(),
            KeyCode::BackTab => app.next_search_mode(),
            KeyCode::Backspace => {
                app.backspace_query();
            }
            KeyCode::Char(ch) => {
                app.push_query(ch);
            }
            KeyCode::Down => app.move_focused_down(db.clone()),
            KeyCode::Up => app.move_focused_up(),
            _ => {}
        }
    }

    app.abort_search();
    Ok(())
}
