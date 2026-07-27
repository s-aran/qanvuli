use super::DetailSearch;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

pub(crate) fn highlighted_line(text: &str, detail_search: &DetailSearch) -> Line<'static> {
    let Some(regex) = &detail_search.regex else {
        return Line::from(text.to_owned());
    };
    let mut spans = Vec::new();
    let mut last = 0;
    for matched in regex.find_iter(text) {
        if matched.start() == matched.end() {
            continue;
        }
        if last < matched.start() {
            spans.push(Span::raw(text[last..matched.start()].to_owned()));
        }
        spans.push(Span::styled(
            text[matched.start()..matched.end()].to_owned(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        last = matched.end();
    }
    if last < text.len() {
        spans.push(Span::raw(text[last..].to_owned()));
    }
    if spans.is_empty() {
        Line::from(text.to_owned())
    } else {
        Line::from(spans)
    }
}
