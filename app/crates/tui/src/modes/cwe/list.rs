use crate::{
    app::{App, PaneFocus},
    common::focus_style,
    traits::list::ResultList,
    utils::text::normalize_spaces,
};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub(super) struct CweList;

impl ResultList for CweList {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let items = if app.cwe_searching() {
            vec![Line::from("Loading")]
        } else if app.cwe_results.is_empty() {
            vec![Line::from("No CWE")]
        } else {
            app.cwe_results
                .iter()
                .enumerate()
                .map(|(index, cwe)| {
                    let description = cwe
                        .description
                        .as_deref()
                        .map(normalize_spaces)
                        .unwrap_or_default();
                    let status = cwe.status.as_deref().unwrap_or("-");
                    let style = if index == app.cwe_selected {
                        Style::default().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!("CWE-{} [{status}] {description}", cwe.id),
                        style,
                    ))
                })
                .collect::<Vec<_>>()
        };
        let list = Paragraph::new(items)
            .block(
                Block::default()
                    .title(format!("CWE ({})", app.cwe_results.len()))
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.focus == PaneFocus::Left)),
            )
            .scroll((app.cwe_scroll, 0));
        frame.render_widget(list, area);
    }
}
