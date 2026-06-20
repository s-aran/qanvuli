use crate::{
    app::{App, PaneFocus},
    common::focus_style,
    traits::list::ResultList,
};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

pub(super) struct CandidateList;

impl ResultList for CandidateList {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let items = app
            .results
            .iter()
            .map(|cve| {
                ListItem::new(vec![
                    Line::from(Span::raw(cve.summary.cve_id.clone())),
                    Line::from(Span::raw(cve.summary.title.clone())),
                ])
            })
            .collect::<Vec<_>>();
        let list = List::new(items)
            .block(
                Block::default()
                    .title(format!(
                        "Candidates ({}/{})",
                        app.results.len(),
                        app.total_results
                            .map(|total| total.to_string())
                            .unwrap_or_else(|| "-".to_owned())
                    ))
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.focus == PaneFocus::Left)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut app.list_state);
    }
}
