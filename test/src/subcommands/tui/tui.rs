use super::{EVENT_POLL_MAX, TUI_LIMIT, app::App, terminal::TerminalGuard, ui::draw};
use crate::subcommands::common::connect_db;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
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
        app.poll_detail().await?;
        app.ensure_detail_for_selection(db.clone());
        if app.searching() || app.loading_detail() {
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
            KeyCode::F(3) => app.show_advanced = true,
            KeyCode::Enter => app.start_search(db.clone()),
            KeyCode::Tab => app.toggle_focus(),
            KeyCode::Left => app.focus_left(),
            KeyCode::Right => app.focus_right(),
            KeyCode::BackTab => app.next_search_mode(),
            KeyCode::Backspace => {
                app.query.pop();
                app.scroll_detail_to_top();
                app.apply_prefix_mode();
            }
            KeyCode::Char(ch) => {
                app.query.push(ch);
                app.scroll_detail_to_top();
                app.apply_prefix_mode();
            }
            KeyCode::Down => app.move_focused_down(db.clone()),
            KeyCode::Up => app.move_focused_up(),
            _ => {}
        }
    }

    app.abort_search();
    Ok(())
}
