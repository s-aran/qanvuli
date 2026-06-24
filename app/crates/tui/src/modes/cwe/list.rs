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

struct CweTreePrefixes {
    by_id: HashMap<i32, CweTreePrefixEntry>,
}

struct CweTreePrefixEntry {
    prefix: String,
}

impl ResultList for CweList {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let block = Block::default()
            .title(format!("CWE ({})", app.cwe_results.len()))
            .borders(Borders::ALL)
            .border_style(focus_style(app.focus == PaneFocus::Left));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let items = if app.cwe_searching() {
            vec![Line::from("Loading")]
        } else if app.cwe_results.is_empty() {
            vec![Line::from("No CWE")]
        } else {
            let prefixes = CweTreePrefixes::new(&app.cwe_results);
            let start = (app.cwe_scroll as usize).min(app.cwe_results.len());
            let end = start
                .saturating_add(inner.height as usize)
                .min(app.cwe_results.len());
            app.cwe_results
                .get(start..end)
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(index, cwe)| {
                    let index = start + index;
                    let description = cwe
                        .description
                        .as_deref()
                        .map(normalize_spaces)
                        .unwrap_or_default();
                    let status = cwe.status.as_deref().unwrap_or("-");
                    let prefix = prefixes.prefix(cwe);
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
        frame.render_widget(Paragraph::new(items), inner);
    }
}

impl CweTreePrefixes {
    fn new(cwes: &[CweEntry]) -> Self {
        let parent_by_id = cwes
            .iter()
            .map(|cwe| (cwe.id, cwe.parent_id))
            .collect::<HashMap<_, _>>();
        let mut sibling_max_id_by_parent = HashMap::<Option<i32>, i32>::new();
        for cwe in cwes {
            sibling_max_id_by_parent
                .entry(cwe.parent_id)
                .and_modify(|id| *id = (*id).max(cwe.id))
                .or_insert(cwe.id);
        }

        let by_id = cwes
            .iter()
            .map(|cwe| {
                (
                    cwe.id,
                    CweTreePrefixEntry {
                        prefix: Self::build_prefix(cwe, &parent_by_id, &sibling_max_id_by_parent),
                    },
                )
            })
            .collect();

        Self { by_id }
    }

    fn prefix(&self, cwe: &CweEntry) -> &str {
        self.by_id
            .get(&cwe.id)
            .map(|entry| entry.prefix.as_str())
            .unwrap_or("")
    }

    fn build_prefix(
        cwe: &CweEntry,
        parent_by_id: &HashMap<i32, Option<i32>>,
        sibling_max_id_by_parent: &HashMap<Option<i32>, i32>,
    ) -> String {
        let ancestors = Self::ancestor_ids(cwe, parent_by_id);
        if ancestors.is_empty() {
            return String::new();
        }

        let mut prefix = String::new();
        for ancestor_id in ancestors.iter().take(ancestors.len().saturating_sub(1)) {
            let continues = parent_by_id.get(ancestor_id).is_some_and(|parent_id| {
                Self::has_later_sibling(*parent_id, *ancestor_id, sibling_max_id_by_parent)
            });
            prefix.push_str(if continues { "|  " } else { "   " });
        }
        prefix.push_str(
            if Self::has_later_sibling(cwe.parent_id, cwe.id, sibling_max_id_by_parent) {
                "|- "
            } else {
                "`- "
            },
        );
        prefix
    }

    fn ancestor_ids(cwe: &CweEntry, parent_by_id: &HashMap<i32, Option<i32>>) -> Vec<i32> {
        let mut ancestors = Vec::new();
        let mut current_parent_id = cwe.parent_id;
        let mut seen = HashSet::new();
        while let Some(parent_id) = current_parent_id {
            let Some(grandparent_id) = parent_by_id.get(&parent_id) else {
                break;
            };
            if !seen.insert(parent_id) {
                break;
            }
            ancestors.push(parent_id);
            current_parent_id = *grandparent_id;
        }
        ancestors.reverse();
        ancestors
    }

    fn has_later_sibling(
        parent_id: Option<i32>,
        id: i32,
        sibling_max_id_by_parent: &HashMap<Option<i32>, i32>,
    ) -> bool {
        sibling_max_id_by_parent
            .get(&parent_id)
            .is_some_and(|max_id| id < *max_id)
    }
}
