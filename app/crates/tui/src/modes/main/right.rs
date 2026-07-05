use super::{detail, metadata};
use crate::{
    app::{App, PaneFocus, RightPaneTab},
    common::{DetailSearch, focus_style, highlighted_line},
    traits::detail::DetailPanel,
};
use qanvuli_db::EnrichedCveSummary;
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
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(app.focus == PaneFocus::Right));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);
    frame.render_widget(tab_title(app), rows[0]);

    match app.right_tab {
        RightPaneTab::Cve => detail::MainDetailPanel.render(frame, app, detail_search, rows[1]),
        RightPaneTab::Metadata => render_lines(
            frame,
            app,
            metadata::metadata_lines(app.selected().map(|cve| &cve.detail), detail_search),
            rows[1],
        ),
        RightPaneTab::Enrichment => {
            render_lines(frame, app, enrichment_lines(app, detail_search), rows[1])
        }
    }
}

fn tab_title(app: &App) -> Tabs<'static> {
    let titles = [
        RightPaneTab::Cve,
        RightPaneTab::Metadata,
        RightPaneTab::Enrichment,
    ]
    .into_iter()
    .map(|tab| {
        if app.right_tab == tab {
            Line::from(Span::styled(
                tab.title(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
        } else {
            Line::from(tab.title())
        }
    })
    .collect::<Vec<_>>();
    Tabs::new(titles).select(match app.right_tab {
        RightPaneTab::Cve => 0,
        RightPaneTab::Metadata => 1,
        RightPaneTab::Enrichment => 2,
    })
}

fn render_lines(
    frame: &mut ratatui::Frame<'_>,
    app: &mut App,
    lines: Vec<Line<'static>>,
    area: Rect,
) {
    app.clamp_metadata_scroll();
    let paragraph = Paragraph::new(lines)
        .scroll((app.metadata_scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn enrichment_lines(app: &App, detail_search: &DetailSearch) -> Vec<Line<'static>> {
    let Some(cve) = app.selected() else {
        return vec![Line::from("No result")];
    };
    let Some(enrichment) = app.enrichment.get(&cve.summary.cve_id) else {
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
    if aliases.is_empty() && !enrichment.kev_listed && enrichment.epss.is_none() {
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
