use crate::{
    app::{App, PaneFocus},
    common::input::is_ctrl,
    utils::text::wrapped_line_count,
};
use crossterm::event::{KeyCode, KeyEvent};
use qanvuli_core::database::{CweEntry, SqlxDatabase};
use ratatui::layout::Size;

pub(crate) fn handle_key(
    app: &mut App,
    db: Option<SqlxDatabase>,
    key: &KeyEvent,
    area: Option<Size>,
) -> bool {
    let page_size = area
        .map(|area| area.height.saturating_sub(6) as usize)
        .unwrap_or(1);
    let detail_page_size = area
        .map(|area| area.height.saturating_sub(6) as usize)
        .unwrap_or(1);
    let detail_width = area
        .map(|area| {
            area.width
                .saturating_mul(62)
                .saturating_div(100)
                .saturating_sub(2) as usize
        })
        .unwrap_or(1);
    let detail_line_count = app
        .selected_cwe()
        .map(|cwe| cwe_detail_line_count(cwe, detail_width))
        .unwrap_or(1);
    match key.code {
        KeyCode::Esc => app.toggle_cwe_list_mode(None),
        KeyCode::F(9) => app.toggle_cwe_list_mode(None),
        KeyCode::F(8) => app.toggle_raw_json_mode(db),
        KeyCode::Char('/') => app.start_detail_search(),
        KeyCode::Char('c') if is_ctrl(key, 'c') => return true,
        KeyCode::Char('d') if is_ctrl(key, 'd') && app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_down(detail_line_count, detail_page_size)
        }
        KeyCode::Char('u') if is_ctrl(key, 'u') && app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_up(detail_page_size)
        }
        KeyCode::Char('d') if is_ctrl(key, 'd') => app.move_cwe_half_page_down(page_size),
        KeyCode::Char('u') if is_ctrl(key, 'u') => app.move_cwe_half_page_up(page_size),
        KeyCode::Char('f') if is_ctrl(key, 'f') && app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_down(detail_line_count, detail_page_size.saturating_mul(2))
        }
        KeyCode::PageDown if app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_down(detail_line_count, detail_page_size)
        }
        KeyCode::Char('b') if is_ctrl(key, 'b') && app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_up(detail_page_size.saturating_mul(2))
        }
        KeyCode::PageUp if app.focus == PaneFocus::Right => {
            app.move_cwe_detail_page_up(detail_page_size)
        }
        KeyCode::Char('f') if is_ctrl(key, 'f') => app.move_cwe_full_page_down(page_size),
        KeyCode::Char('b') if is_ctrl(key, 'b') => app.move_cwe_full_page_up(page_size),
        KeyCode::PageDown => app.move_cwe_full_page_down(page_size),
        KeyCode::PageUp => app.move_cwe_full_page_up(page_size),
        KeyCode::F(4) => app.open_cwe_status_popup(),
        KeyCode::Backspace => app.backspace_cwe_query(db),
        KeyCode::Tab | KeyCode::BackTab => app.toggle_cwe_focus(),
        KeyCode::Left => app.move_cwe_to_parent(page_size),
        KeyCode::Right => app.move_cwe_to_relation_return(page_size),
        KeyCode::Char('[') => app.move_cwe_to_previous_sibling(page_size),
        KeyCode::Char(']') => app.move_cwe_to_next_sibling(page_size),
        KeyCode::Char(ch) => app.push_cwe_query(ch, db),
        KeyCode::Down if app.focus == PaneFocus::Right => {
            app.move_cwe_detail_down(detail_line_count, detail_page_size)
        }
        KeyCode::Up if app.focus == PaneFocus::Right => app.move_cwe_detail_up(),
        KeyCode::Down => app.move_cwe_down(page_size),
        KeyCode::Up => app.move_cwe_up(page_size),
        _ => {}
    }
    false
}

fn cwe_detail_line_count(cwe: &CweEntry, width: usize) -> usize {
    let text = cwe_detail_text(cwe);
    wrapped_line_count(&text, width)
}

fn cwe_detail_text(cwe: &CweEntry) -> String {
    format!(
        "CWE-{}\nStatus: {}\nParent: {}\nSiblings: {}\nChildren: {}\n\n{}",
        cwe.id,
        cwe.status.as_deref().unwrap_or("-"),
        cwe.parent_count,
        cwe.sibling_count,
        cwe.child_count,
        cwe.description.as_deref().unwrap_or("")
    )
}
