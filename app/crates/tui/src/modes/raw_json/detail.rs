use crate::{
    app::App,
    common::{DetailSearch, highlighted_line},
    traits::detail::DetailPanel,
    utils::text::wrapped_line_count,
};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(super) struct RawJsonDetailPanel;

impl RawJsonDetailPanel {
    pub(super) fn at_eof(&self, app: &App, area: Rect) -> bool {
        let text = raw_json_text(app);
        let content_width = area.width.saturating_sub(2) as usize;
        let page_size = area.height.saturating_sub(2) as usize;
        let line_count = wrapped_line_count(text, content_width);
        app.raw_scroll as usize >= line_count.saturating_sub(page_size.max(1))
    }
}

impl DetailPanel for RawJsonDetailPanel {
    fn render(
        &self,
        frame: &mut ratatui::Frame<'_>,
        app: &mut App,
        detail_search: &DetailSearch,
        area: Rect,
    ) {
        let title = app
            .selected()
            .map(|cve| cve.summary.cve_id.as_str())
            .or_else(|| app.selected_osv().map(|osv| osv.osv_id.as_str()))
            .unwrap_or("CVE");
        let paragraph = Paragraph::new(json_lines(raw_json_text(app), detail_search))
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .scroll((app.raw_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }
}

fn raw_json_text(app: &App) -> &str {
    app.raw_json.as_deref().unwrap_or("Loading")
}

fn json_lines(text: &str, detail_search: &DetailSearch) -> Vec<Line<'static>> {
    if detail_search.enabled() {
        return text
            .lines()
            .map(|line| highlighted_line(line, detail_search))
            .collect();
    }
    if serde_json::from_str::<serde_json::Value>(text).is_err() {
        return text
            .lines()
            .map(|line| Line::from(line.to_owned()))
            .collect();
    }
    text.lines().map(highlight_json_line).collect()
}

fn highlight_json_line(line: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        match ch {
            '"' => {
                let end = json_string_end(line, &mut chars);
                let token = &line[start..end];
                let style = if is_json_key(line, end) {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Green)
                };
                spans.push(Span::styled(token.to_owned(), style));
            }
            '-' | '0'..='9' => {
                let end = json_number_end(line, start);
                spans.push(Span::styled(
                    line[start..end].to_owned(),
                    Style::default().fg(Color::Magenta),
                ));
                while chars.peek().is_some_and(|(index, _)| *index < end) {
                    chars.next();
                }
            }
            't' | 'f' | 'n' => {
                let end = json_literal_end(line, start);
                spans.push(Span::styled(
                    line[start..end].to_owned(),
                    Style::default().fg(Color::Yellow),
                ));
                while chars.peek().is_some_and(|(index, _)| *index < end) {
                    chars.next();
                }
            }
            '{' | '}' | '[' | ']' | ':' | ',' => {
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            _ => spans.push(Span::raw(ch.to_string())),
        }
    }
    Line::from(spans)
}

fn json_string_end(
    line: &str,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> usize {
    let mut escaped = false;
    for (index, ch) in chars.by_ref() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return index + ch.len_utf8();
        }
    }
    line.len()
}

fn is_json_key(line: &str, end: usize) -> bool {
    line[end..].trim_start().starts_with(':')
}

fn json_number_end(line: &str, start: usize) -> usize {
    line[start..]
        .find(|ch: char| !matches!(ch, '-' | '+' | '.' | '0'..='9' | 'e' | 'E'))
        .map(|offset| start + offset)
        .unwrap_or(line.len())
}

fn json_literal_end(line: &str, start: usize) -> usize {
    line[start..]
        .find(|ch: char| !ch.is_ascii_alphabetic())
        .map(|offset| start + offset)
        .unwrap_or(line.len())
}
