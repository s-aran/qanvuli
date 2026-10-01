use crate::{
    app::{App, PaneFocus},
    common::focus_style,
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
            .border_style(focus_style(app.main.focus == PaneFocus::Left));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if app.main.exact_match_available() {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(0), Constraint::Length(15)])
                .split(inner);
            frame.render_widget(
                Paragraph::new(visible_query(&app.main.query, cursor, chunks[0].width))
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
                Paragraph::new(visible_query(&app.main.query, cursor, inner.width))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                inner,
            );
        }
    }
}

fn visible_query(query: &str, cursor: &str, width: u16) -> String {
    if query.is_empty() && width >= 30 {
        return format!("{cursor}Type a keyword or CVE ID");
    }
    let text = format!("{query}{cursor}");
    if Line::from(text.as_str()).width() <= usize::from(width) {
        return text;
    }
    let mut start = text.len();
    let mut used = 1; // Reserve a cell for the truncation marker.
    for (index, ch) in text.char_indices().rev() {
        let cells = Line::from(ch.to_string()).width();
        if used + cells > usize::from(width) {
            break;
        }
        used += cells;
        start = index;
    }
    if width == 0 {
        String::new()
    } else {
        format!("…{}", &text[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_queries_keep_the_cursor_visible_without_splitting_utf8() {
        assert_eq!(visible_query("abcdef", "▏", 5), "…def▏");
        assert_eq!(visible_query("あいうえお", "▏", 6), "…えお▏");
        assert_eq!(visible_query("abc", "▏", 0), "");
        assert_eq!(visible_query("abc", "▏", 4), "abc▏");
    }
}
