mod candidates;
pub(crate) mod detail;
pub(crate) mod handler;
mod keyword;
mod metadata;
pub(crate) mod right;
pub(crate) mod status;

use crate::traits::{keyword::KeywordInput, list::ResultList, status::StatusLine};
use crate::{
    app::{App, PaneFocus},
    common::DetailSearch,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::Paragraph,
};

pub(crate) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App, detail_search: &DetailSearch) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let compact = frame.area().width < 100;
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main[1]);
    let list_area = if compact { main[1] } else { chunks[0] };
    let detail_area = if compact { main[1] } else { chunks[1] };
    app.set_page_sizes(
        list_area.height.saturating_sub(2) as usize,
        detail_area.height.saturating_sub(5) as usize,
        detail_area.height.saturating_sub(3) as usize,
        detail_area.width.saturating_sub(4) as usize,
        detail_area.width.saturating_sub(2) as usize,
    );

    keyword::MainKeywordInput.render(frame, app, main[0]);
    if !compact || app.main.focus == PaneFocus::Left {
        candidates::CandidateList.render(frame, app, list_area);
    }

    let footer = Paragraph::new(status::MainStatusLine.text(app));
    frame.render_widget(footer, main[2]);
    let hints = if app.overlay.detail_search_input {
        "Enter/Esc close"
    } else if frame.area().width < 80 {
        "Tab pane | F1 help | Ctrl-C quit"
    } else if app.main.focus == PaneFocus::Right {
        "Tab results | ↑↓ scroll | ←→ tabs | / find | F1 help | Ctrl-C quit"
    } else if app.main.exact_match_focus {
        "Space toggle exact | Tab details | Enter search | F1 help"
    } else if app.main.exact_match_available() {
        "Enter search | ↑↓ select | Tab exact match | F2 mode | F3 filters | F1 help"
    } else {
        "Enter search | ↑↓ select | Tab details | F2 mode | F3 filters | F4 sort | F1 help"
    };
    let hints = if app.overlay.detail_search_input {
        format!("{hints} | /{}", app.overlay.detail_search_query)
    } else {
        hints.to_owned()
    };
    frame.render_widget(
        Paragraph::new(hints).style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        main[3],
    );

    if !compact || app.main.focus == PaneFocus::Right {
        right::render(frame, app, detail_search, detail_area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn screen(width: u16, height: u16, focus: PaneFocus) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut app = App::new(String::new(), 25);
        app.main.focus = focus;
        terminal
            .draw(|frame| draw(frame, &mut app, &DetailSearch::new("")))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn narrow_screen_shows_the_focused_pane_and_navigation() {
        let results = screen(80, 24, PaneFocus::Left);
        assert!(results.contains("Results 0/0"));
        assert!(results.contains("Tab details"));
        let details = screen(80, 24, PaneFocus::Right);
        assert!(!details.contains("Results 0/0"));
        assert!(details.contains("Tab results"));
        assert!(details.contains("Metadata"));
    }

    #[test]
    fn wide_screen_keeps_both_panes_visible() {
        let rendered = screen(120, 30, PaneFocus::Left);
        assert!(rendered.contains("Results 0/0"));
        assert!(rendered.contains("Metadata"));
        assert!(rendered.contains("Type a keyword or CVE ID"));
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        for (width, height) in [(1, 1), (15, 4), (40, 10)] {
            screen(width, height, PaneFocus::Left);
            screen(width, height, PaneFocus::Right);
        }
    }
}
