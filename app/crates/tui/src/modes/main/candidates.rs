use crate::{
    app::{App, PaneFocus},
    common::focus_style,
    db::search::SearchCandidate,
    display::SortField,
    traits::list::ResultList,
    utils::datetime::format_timestamp,
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
        let items = (0..app.candidate_count())
            .filter_map(|index| app.candidate(index))
            .map(|candidate| {
                let sort_key = candidate_sort_key(app, candidate);
                match candidate {
                    SearchCandidate::Cve(cve) => ListItem::new(vec![
                        Line::from(Span::raw(cve.summary.cve_id.clone())),
                        Line::from(Span::raw(candidate_subtitle(
                            sort_key,
                            cve.summary.title.clone(),
                        ))),
                    ]),
                    SearchCandidate::Osv(osv) => ListItem::new(vec![
                        Line::from(Span::raw(osv.osv_id.clone())),
                        Line::from(Span::raw(candidate_subtitle(
                            sort_key,
                            osv.summary
                                .clone()
                                .unwrap_or_else(|| "OSV advisory".to_owned()),
                        ))),
                    ]),
                }
            })
            .collect::<Vec<_>>();
        let list = List::new(items)
            .block(
                Block::default()
                    .title(format!(
                        "Candidates ({}/{})",
                        app.candidate_count(),
                        app.main
                            .total_results
                            .map(|total| total.to_string())
                            .unwrap_or_else(|| "?".to_owned())
                    ))
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.main.focus == PaneFocus::Left)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, area, &mut app.main.list_state);
    }
}

fn candidate_sort_key(app: &App, candidate: &SearchCandidate) -> Option<String> {
    let timestamp = match (app.main.display.sort_field, candidate) {
        (SortField::Published, SearchCandidate::Cve(cve)) => {
            Some(cve.summary.published_at.as_str())
        }
        (SortField::Published, SearchCandidate::Osv(osv)) => osv.published_at.as_deref(),
        (SortField::Updated, SearchCandidate::Cve(cve)) => Some(cve.summary.updated_at.as_str()),
        (SortField::Updated, SearchCandidate::Osv(osv)) => osv.modified_at.as_deref(),
        _ => None,
    };
    if let Some(timestamp) = timestamp {
        return Some(format_timestamp(timestamp, app.main.display.timezone));
    }
    if app.main.display.sort_field == SortField::Score {
        return Some(match candidate {
            SearchCandidate::Cve(cve) => cve
                .detail
                .cvss
                .iter()
                .filter_map(|score| score.base_score)
                .max_by(f64::total_cmp)
                .map(|score| format!("CVSS {score:.1}"))
                .unwrap_or_else(|| "CVSS -".to_owned()),
            SearchCandidate::Osv(_) => "CVSS -".to_owned(),
        });
    }
    None
}

fn candidate_subtitle(sort_key: Option<String>, title: String) -> String {
    match sort_key {
        Some(key) => format!("{key}  {title}"),
        None => title,
    }
}
