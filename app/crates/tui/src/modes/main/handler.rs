use crate::{app::App, common::input::is_ctrl};
use crossterm::event::{KeyCode, KeyEvent};
use qanvuli_db::CveDatabase;

pub(crate) fn handle_key(app: &mut App, db: Option<CveDatabase>, key: &KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {}
        KeyCode::Char('c') if is_ctrl(key, 'c') => return true,
        KeyCode::Char('u') if is_ctrl(key, 'u') => {
            app.move_half_page_up();
        }
        KeyCode::Char('d') if is_ctrl(key, 'd') => {
            if let Some(db) = db {
                app.move_half_page_down(db);
            }
        }
        KeyCode::Char('f') if is_ctrl(key, 'f') => {
            if let Some(db) = db {
                app.move_full_page_down(db);
            }
        }
        KeyCode::Char('b') if is_ctrl(key, 'b') => {
            app.move_full_page_up();
        }
        KeyCode::F(1) => app.show_help = true,
        KeyCode::F(2) => app.next_search_mode(),
        KeyCode::F(3) => app.open_advanced_search(),
        KeyCode::F(4) => app.open_display_settings(),
        KeyCode::F(5) => app.open_maintenance(),
        KeyCode::F(8) => app.toggle_raw_json_mode(db),
        KeyCode::F(9) => app.toggle_cwe_list_mode(db),
        KeyCode::Char('/') => app.start_detail_search(),
        KeyCode::Enter => {
            if let Some(db) = db {
                app.start_search(db);
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
            if let Some(db) = db {
                app.move_focused_down(db);
            }
        }
        KeyCode::Up => app.move_focused_up(),
        _ => {}
    }
    false
}
