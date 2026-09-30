use crate::{
    app::{App, PaneFocus},
    traits::keyword::KeywordInput,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub(super) struct MainKeywordInput;

impl KeywordInput for MainKeywordInput {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let input_title = format!(
            "Search [{}] - limit {}",
            app.main.search_mode.footer_text(),
            app.main.limit
        );
        let query_focused = app.main.focus == PaneFocus::Left && !app.main.exact_match_focus;
        let cursor = if query_focused { "▏" } else { "" };
        let block = Block::default()
            .title(input_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.main.search_mode.color()));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if app.main.exact_match_available() {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(0), Constraint::Length(15)])
                .split(inner);
            frame.render_widget(
                Paragraph::new(format!("{}{cursor}", app.main.query))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                chunks[0],
            );
            let marker = if app.main.exact_match { "[x]" } else { "[ ]" };
            let style = if app.main.focus == PaneFocus::Left && app.main.exact_match_focus {
                Style::default()
                    .fg(Color::Black)
                    .bg(app.main.search_mode.color())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(marker, style),
                    Span::raw(" Exact match"),
                ])),
                chunks[1],
            );
        } else {
            frame.render_widget(
                Paragraph::new(format!("{}{cursor}", app.main.query))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                inner,
            );
        }
    }
}
