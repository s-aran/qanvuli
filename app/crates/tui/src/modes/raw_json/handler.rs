use crate::{app::App, common::input::is_ctrl, utils::text::wrapped_line_count};
use crossterm::event::{KeyCode, KeyEvent};
use qanvuli_core::database::SqlxDatabase;
use ratatui::layout::Size;

pub(crate) fn handle_key(
    app: &mut App,
    db: Option<SqlxDatabase>,
    key: &KeyEvent,
    area: Option<Size>,
) -> bool {
    let page_size = area
        .map(|area| area.height.saturating_sub(3) as usize)
        .unwrap_or(1);
    let width = area
        .map(|area| area.width.saturating_sub(2) as usize)
        .unwrap_or(1);
    let line_count = app
        .raw_json
        .as_deref()
        .map(|value| wrapped_line_count(value, width))
        .unwrap_or(1);
    match key.code {
        KeyCode::Esc => app.toggle_raw_json_mode(None),
        KeyCode::F(8) => app.toggle_raw_json_mode(None),
        KeyCode::F(9) => app.toggle_cwe_list_mode(db),
        KeyCode::Char('/') => app.start_detail_search(),
        KeyCode::Char('c') if is_ctrl(key, 'c') => return true,
        KeyCode::Char('d') if is_ctrl(key, 'd') => app.move_raw_page_down(line_count, page_size),
        KeyCode::Char('u') if is_ctrl(key, 'u') => app.move_raw_page_up(page_size),
        KeyCode::Char('f') if is_ctrl(key, 'f') => {
            app.move_raw_page_down(line_count, page_size.saturating_mul(2))
        }
        KeyCode::PageDown => app.move_raw_page_down(line_count, page_size),
        KeyCode::Char('b') if is_ctrl(key, 'b') => {
            app.move_raw_page_up(page_size.saturating_mul(2))
        }
        KeyCode::PageUp => app.move_raw_page_up(page_size),
        KeyCode::Down => app.move_raw_down(line_count, page_size),
        KeyCode::Up => app.move_raw_up(),
        _ => {}
    }
    false
}
