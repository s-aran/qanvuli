use crate::{
    app::{App, PaneFocus},
    common::focus_style,
    traits::list::ResultList,
    utils::text::normalize_spaces,
};
use qanvuli_db::CweEntry;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::collections::{HashMap, HashSet};

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
                    let prefix = cwe_tree_prefix(cwe, &app.cwe_results);
                    let style = if index == app.cwe_selected {
                        Style::default().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!("{prefix}CWE-{} [{status}] {description}", cwe.id),
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

fn cwe_tree_prefix(cwe: &CweEntry, cwes: &[CweEntry]) -> String {
    let ancestors = cwe_ancestor_ids(cwe, cwes);
    if ancestors.is_empty() {
        return String::new();
    }

    let by_id = cwes
        .iter()
        .map(|cwe| (cwe.id, cwe))
        .collect::<HashMap<_, _>>();
    let mut prefix = String::new();
    for ancestor_id in ancestors.iter().take(ancestors.len().saturating_sub(1)) {
        let continues = by_id
            .get(ancestor_id)
            .is_some_and(|ancestor| has_later_sibling(ancestor, cwes));
        prefix.push_str(if continues { "|  " } else { "   " });
    }
    prefix.push_str(if has_later_sibling(cwe, cwes) {
        "|- "
    } else {
        "`- "
    });
    prefix
}

fn cwe_ancestor_ids(cwe: &CweEntry, cwes: &[CweEntry]) -> Vec<i32> {
    let by_id = cwes
        .iter()
        .map(|cwe| (cwe.id, cwe))
        .collect::<HashMap<_, _>>();
    let mut ancestors = Vec::new();
    let mut current = cwe;
    let mut seen = HashSet::new();
    while let Some(parent_id) = current.parent_id {
        let Some(parent) = by_id.get(&parent_id) else {
            break;
        };
        if !seen.insert(parent.id) {
            break;
        }
        ancestors.push(parent.id);
        current = parent;
    }
    ancestors.reverse();
    ancestors
}

fn has_later_sibling(cwe: &CweEntry, cwes: &[CweEntry]) -> bool {
    cwes.iter()
        .any(|candidate| candidate.parent_id == cwe.parent_id && candidate.id > cwe.id)
}
