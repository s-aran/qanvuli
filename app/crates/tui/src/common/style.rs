use ratatui::style::{Color, Style};

pub(crate) fn focus_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}
