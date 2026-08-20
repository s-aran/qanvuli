use super::{detail, metadata};
use crate::{
    app::{App, PaneFocus, RightPaneTab},
    common::{DetailSearch, focus_style, highlighted_line},
    traits::detail::DetailPanel,
};
use qanvuli_core::database::EnrichedCveSummary;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
};

pub(super) fn render(
    frame: &mut ratatui::Frame<'_>,
    app: &mut App,
    detail_search: &DetailSearch,
    area: Rect,
) {
    if app.selected_osv().is_some() && app.main.right_tab == RightPaneTab::Osv {
        app.main.right_tab = RightPaneTab::Cve;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(app.main.focus == PaneFocus::Right));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);
    frame.render_widget(tab_title(app), rows[0]);

    match app.main.right_tab {
        RightPaneTab::Cve => detail::MainDetailPanel.render(frame, app, detail_search, rows[1]),
        tab => render_lines(
            frame,
            app,
            tab_lines(app, tab, detail_search, rows[1].width.max(1) as usize),
            rows[1],
        ),
    }
}

pub(crate) fn tab_lines(
    app: &App,
    tab: RightPaneTab,
    detail_search: &DetailSearch,
    width: usize,
) -> Vec<Line<'static>> {
    match tab {
        RightPaneTab::Cve => Vec::new(),
        RightPaneTab::Osv => osv_lines(app, detail_search, width),
        RightPaneTab::Metadata => {
            if let Some(osv) = app.selected_osv() {
                metadata::osv_metadata_lines(osv, detail_search)
            } else {
                metadata::metadata_lines(
                    app.selected().map(|cve| &cve.detail),
                    app.selected_metadata_capec_ids(),
                    detail_search,
                )
            }
        }
        RightPaneTab::Enrichment => enrichment_lines(app, detail_search),
    }
}

fn tab_title(app: &App) -> Tabs<'static> {
    let tabs = visible_tabs(app);
    let selected = tabs
        .iter()
        .position(|tab| *tab == app.main.right_tab)
        .unwrap_or_default();
    let titles = tabs
        .into_iter()
        .map(|tab| {
            let title = if tab == RightPaneTab::Cve && app.selected_osv().is_some() {
                "OSV"
            } else {
                tab.title()
            };
            if app.main.right_tab == tab {
                Line::from(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(title)
            }
        })
        .collect::<Vec<_>>();
    Tabs::new(titles).select(selected)
}

fn visible_tabs(app: &App) -> Vec<RightPaneTab> {
    [
        RightPaneTab::Cve,
        RightPaneTab::Osv,
        RightPaneTab::Metadata,
        RightPaneTab::Enrichment,
    ]
    .into_iter()
    .filter(|tab| *tab != RightPaneTab::Osv || app.selected_osv().is_none())
    .collect()
}

fn render_lines(
    frame: &mut ratatui::Frame<'_>,
    app: &mut App,
    lines: Vec<Line<'static>>,
    area: Rect,
) {
    app.clamp_metadata_scroll();
    let paragraph = Paragraph::new(lines)
        .scroll((app.main.metadata_scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn enrichment_lines(app: &App, detail_search: &DetailSearch) -> Vec<Line<'static>> {
    if let Some(osv) = app.selected_osv() {
        return vec![
            highlighted_line(&format!("Identifier: {}", osv.osv_id), detail_search),
            Line::from(""),
            Line::from("OSV-only advisory; no related CVE enrichment"),
        ];
    }
    let Some(cve) = app.selected() else {
        return vec![Line::from("No result")];
    };
    let Some(enrichment) = app.main.enrichment.get(&cve.summary.cve_id) else {
        return vec![
            highlighted_line(
                &format!("Identifier: {}", cve.summary.cve_id),
                detail_search,
            ),
            Line::from(""),
            Line::from("Loading enrichment summary..."),
        ];
    };
    render_enrichment(enrichment, detail_search)
}

pub(crate) fn osv_lines(
    app: &App,
    detail_search: &DetailSearch,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(cve) = app.selected() else {
        return vec![Line::from("No result")];
    };
    let Some(advisories) = app.main.linked_osv.get(&cve.summary.cve_id) else {
        return vec![Line::from("No linked OSV advisories")];
    };
    let mut lines = Vec::new();
    for (index, advisory) in advisories.iter().enumerate() {
        if index != 0 {
            lines.push(Line::from(""));
        }
        lines.push(highlighted_line(
            &format!("Identifier: {}", advisory.osv_id),
            detail_search,
        ));
        lines.extend(detail::osv_detail_lines(
            advisory,
            app.main.display.timezone,
            detail_search,
            width,
        ));
    }
    lines
}

fn render_enrichment(
    enrichment: &EnrichedCveSummary,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(highlighted_line(
        &format!("Identifier: {}", enrichment.cve_id),
        detail_search,
    ));
    lines.push(Line::from(""));
    lines.push(Line::from("Priority"));
    lines.push(highlighted_line(
        &format!(
            "  KEV: {}",
            if enrichment.kev_listed {
                "listed"
            } else {
                "not listed"
            }
        ),
        detail_search,
    ));
    if let (Some(epss), Some(percentile)) = (enrichment.epss, enrichment.epss_percentile) {
        lines.push(highlighted_line(
            &format!(
                "  EPSS: score={:.5} percentile={:.5} date={} model={}",
                epss,
                percentile,
                enrichment.epss_score_date.as_deref().unwrap_or("-"),
                enrichment.epss_model_version.as_deref().unwrap_or("-")
            ),
            detail_search,
        ));
    } else {
        lines.push(Line::from("  EPSS: not synced"));
    }
    if enrichment.ssvc_exploitation.is_some()
        || enrichment.ssvc_automatable.is_some()
        || enrichment.ssvc_technical_impact.is_some()
    {
        lines.push(highlighted_line(
            &format!(
                "  SSVC: exploitation={} automatable={} technical-impact={}",
                enrichment.ssvc_exploitation.as_deref().unwrap_or("-"),
                enrichment.ssvc_automatable.as_deref().unwrap_or("-"),
                enrichment.ssvc_technical_impact.as_deref().unwrap_or("-")
            ),
            detail_search,
        ));
    } else {
        lines.push(Line::from("  SSVC: not synced"));
    }
    if enrichment.kev_listed {
        lines.push(highlighted_line(
            &format!(
                "  KEV due={} ransomware={}",
                enrichment.kev_due_date.as_deref().unwrap_or("-"),
                enrichment
                    .kev_known_ransomware_campaign_use
                    .as_deref()
                    .unwrap_or("-")
            ),
            detail_search,
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Aliases"));
    let aliases = split_summary_list(&enrichment.aliases);
    if aliases.is_empty() {
        lines.push(Line::from("  none"));
    } else {
        for alias in &aliases {
            lines.push(highlighted_line(&format!("  {alias}"), detail_search));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("OSV Advisories"));
    let osv_summaries = split_summary_list(&enrichment.osv_summaries);
    if osv_summaries.is_empty() {
        lines.push(Line::from("  none"));
    } else {
        for summary in osv_summaries {
            lines.push(highlighted_line(&format!("  {summary}"), detail_search));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Affected Packages"));
    let packages = split_summary_list(&enrichment.affected_packages);
    if packages.is_empty() {
        lines.push(Line::from("  none"));
    } else {
        for package in packages {
            lines.push(highlighted_line(&format!("  {package}"), detail_search));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Evidence"));
    if !aliases.is_empty() {
        lines.push(Line::from("  alias_resolution source=OSV aliases"));
    }
    if enrichment.kev_listed {
        lines.push(Line::from("  kev_join source=CISA KEV"));
    }
    if enrichment.epss.is_some() {
        lines.push(Line::from("  epss_join source=FIRST EPSS"));
    }
    if enrichment.ssvc_exploitation.is_some() {
        lines.push(Line::from("  ssvc_join source=CVE ADP"));
    }
    if aliases.is_empty()
        && !enrichment.kev_listed
        && enrichment.epss.is_none()
        && enrichment.ssvc_exploitation.is_none()
    {
        lines.push(Line::from("  none"));
    }
    lines
}

fn split_summary_list(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::search::SearchCandidate;
    use qanvuli_core::database::OsvSummary;

    #[test]
    fn osv_result_hides_the_linked_osv_tab() {
        let mut app = App::new(String::new(), 25);
        app.main.candidates.push(SearchCandidate::Osv(OsvSummary {
            osv_id: "GHSA-2099-only".to_owned(),
            schema_version: None,
            published_at: None,
            modified_at: None,
            withdrawn_at: None,
            summary: None,
            details: None,
            package_summary: None,
        }));
        app.main.list_state.select(Some(0));

        assert_eq!(
            visible_tabs(&app),
            vec![
                RightPaneTab::Cve,
                RightPaneTab::Metadata,
                RightPaneTab::Enrichment
            ]
        );
        app.next_right_tab();
        assert_eq!(app.main.right_tab, RightPaneTab::Metadata);
        app.previous_right_tab();
        assert_eq!(app.main.right_tab, RightPaneTab::Cve);
    }
}
