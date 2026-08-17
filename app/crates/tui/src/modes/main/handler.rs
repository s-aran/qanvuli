use crate::{
    app::{App, PaneFocus},
    common::input::is_ctrl,
};
use crossterm::event::{KeyCode, KeyEvent};
use qanvuli_core::database::CveDatabase;

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
        KeyCode::PageDown => {
            if let Some(db) = db {
                app.move_full_page_down(db);
            }
        }
        KeyCode::Char('b') if is_ctrl(key, 'b') => {
            app.move_full_page_up();
        }
        KeyCode::PageUp => app.move_full_page_up(),
        KeyCode::F(1) | KeyCode::Char('?') => app.show_help = true,
        KeyCode::F(2) => app.next_search_mode(),
        KeyCode::F(3) => {
            app.open_advanced_search(db);
        }
        KeyCode::F(4) => {
            app.open_display_settings();
            app.load_scope_candidates(db);
        }
        KeyCode::F(5) => app.open_maintenance(),
        KeyCode::F(8) => app.toggle_raw_json_mode(db),
        KeyCode::F(9) => app.toggle_cwe_list_mode(db),
        KeyCode::F(10) => app.toggle_capec_list_mode(db),
        KeyCode::Char('/') => app.start_detail_search(),
        KeyCode::Enter => {
            if let Some(db) = db {
                app.start_search(db);
            }
        }
        KeyCode::Tab => app.toggle_focus(),
        KeyCode::BackTab => app.previous_focus(),
        KeyCode::Left if app.focus == PaneFocus::Right => app.previous_right_tab(),
        KeyCode::Right if app.focus == PaneFocus::Right => app.next_right_tab(),
        KeyCode::Left => app.previous_search_mode(),
        KeyCode::Right => app.next_search_mode(),
        KeyCode::Backspace if app.focus == PaneFocus::Left => {
            app.backspace_query();
        }
        KeyCode::Char(ch) if app.focus == PaneFocus::Left => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    #[test]
    fn typing_while_reading_the_right_pane_does_not_edit_the_query() {
        let mut app = App::new("stable".to_owned(), 25);
        app.focus = PaneFocus::Right;

        handle_key(
            &mut app,
            None,
            &KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        );
        assert_eq!(app.query, "stable");

        handle_key(
            &mut app,
            None,
            &KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        );

        assert_eq!(app.query, "stable");
    }

    #[test]
    fn question_mark_opens_help() {
        let mut app = App::new(String::new(), 25);

        handle_key(
            &mut app,
            None,
            &KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );

        assert!(app.show_help);
        assert!(app.query.is_empty());
    }
}
