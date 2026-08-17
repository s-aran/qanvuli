use crate::{
    app::{App, PaneFocus},
    common::input::is_ctrl,
};
use crossterm::event::{KeyCode, KeyEvent};
use qanvuli_core::database::SqlxDatabase;
use ratatui::layout::Size;

pub(crate) fn handle_key(
    app: &mut App,
    db: Option<SqlxDatabase>,
    key: &KeyEvent,
    area: Option<Size>,
) -> bool {
    let page = area
        .map(|size| size.height.saturating_sub(6) as usize)
        .unwrap_or(1)
        .max(1);
    match key.code {
        KeyCode::Esc | KeyCode::F(10) => app.toggle_capec_list_mode(None),
        KeyCode::F(9) => app.toggle_cwe_list_mode(db),
        KeyCode::F(4) => app.open_capec_filter(),
        KeyCode::F(1) | KeyCode::Char('?') => app.show_help = true,
        KeyCode::Enter => {
            app.open_capec_taxonomy(db);
        }
        KeyCode::Char('/') => app.start_detail_search(),
        KeyCode::Char('c') if is_ctrl(key, 'c') => return true,
        KeyCode::Tab | KeyCode::BackTab => app.toggle_focus(),
        KeyCode::Left if app.focus == PaneFocus::Left => app.move_capec_to_parent(page),
        KeyCode::Right if app.focus == PaneFocus::Left => app.move_capec_to_relation_return(page),
        KeyCode::Char('[') if app.focus == PaneFocus::Left => app.move_capec_sibling(false, page),
        KeyCode::Char(']') if app.focus == PaneFocus::Left => app.move_capec_sibling(true, page),
        KeyCode::Backspace if app.focus == PaneFocus::Left => app.backspace_capec_query(db),
        KeyCode::Char(ch) if app.focus == PaneFocus::Left => app.push_capec_query(ch, db),
        KeyCode::Down if app.focus == PaneFocus::Left => app.move_capec(true, page, 1),
        KeyCode::Up if app.focus == PaneFocus::Left => app.move_capec(false, page, 1),
        KeyCode::PageDown if app.focus == PaneFocus::Left => app.move_capec(true, page, page),
        KeyCode::PageUp if app.focus == PaneFocus::Left => app.move_capec(false, page, page),
        KeyCode::Down => app.capec_detail_scroll = app.capec_detail_scroll.saturating_add(1),
        KeyCode::Up => app.capec_detail_scroll = app.capec_detail_scroll.saturating_sub(1),
        KeyCode::PageDown => {
            app.capec_detail_scroll = app.capec_detail_scroll.saturating_add(page as u16)
        }
        KeyCode::PageUp => {
            app.capec_detail_scroll = app.capec_detail_scroll.saturating_sub(page as u16)
        }
        KeyCode::Char('d') if is_ctrl(key, 'd') => {
            app.capec_detail_scroll = app.capec_detail_scroll.saturating_add((page / 2) as u16)
        }
        KeyCode::Char('u') if is_ctrl(key, 'u') => {
            app.capec_detail_scroll = app.capec_detail_scroll.saturating_sub((page / 2) as u16)
        }
        _ => {}
    }
    false
}
