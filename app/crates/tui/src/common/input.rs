use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub(crate) fn is_ctrl(key: &KeyEvent, ch: char) -> bool {
    matches!(key.code, KeyCode::Char(value) if value == ch)
        && key.modifiers.contains(KeyModifiers::CONTROL)
}

pub(crate) fn is_ctrl_quit(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('c' | 'd')) && key.modifiers.contains(KeyModifiers::CONTROL)
}
