use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, focus_style, highlighted_line},
    utils::text::normalize_spaces,
};
use qanvuli_db::CveDetail;
use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(super) fn render(
    frame: &mut ratatui::Frame<'_>,
    app: &mut App,
    detail_search: &DetailSearch,
    area: Rect,
) {
    let metadata_lines = metadata_lines(app.selected().map(|cve| &cve.detail), detail_search);
    app.clamp_metadata_scroll();
    let metadata = Paragraph::new(metadata_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(focus_style(app.focus == PaneFocus::Metadata)),
        )
        .scroll((app.metadata_scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(metadata, area);
}

fn metadata_lines(detail: Option<&CveDetail>, detail_search: &DetailSearch) -> Vec<Line<'static>> {
    let Some(detail) = detail else {
        return vec![Line::from("Loading")];
    };
    let mut lines = Vec::new();
    if detail.cwes.is_empty() {
        lines.push(Line::from("No CWE"));
    } else {
        lines.extend(detail.cwes.iter().map(|cwe| {
            let description = cwe
                .description
                .as_deref()
                .map(normalize_spaces)
                .unwrap_or_default();
            highlighted_line(&format!("CWE-{} {}", cwe.id, description), detail_search)
        }));
    }
    lines.push(Line::from(""));
    if detail.cvss.is_empty() {
        lines.push(Line::from("No CVSS"));
    } else {
        lines.extend(detail.cvss.iter().map(|cvss| {
            let score = cvss
                .base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| "-".to_owned());
            let severity = cvss.base_severity.as_deref().unwrap_or("-");
            let vector = cvss.vector_string.as_deref().unwrap_or("");
            highlighted_line(
                &format!("{} {} {} {}", cvss.version, score, severity, vector),
                detail_search,
            )
        }));
    }
    lines.push(Line::from(""));
    if detail.affected.is_empty() {
        lines.push(Line::from("No affected component"));
    } else {
        lines.extend(detail.affected.iter().map(|affected| {
            let vendor = affected.vendor.as_deref().unwrap_or("-");
            let product = affected.product.as_deref().unwrap_or("-");
            let package = affected.package_name.as_deref().unwrap_or("-");
            let status = affected.default_status.as_deref().unwrap_or("-");
            let collection = affected.collection_url.as_deref().unwrap_or("");
            let suffix = if collection.is_empty() {
                String::new()
            } else {
                format!(" {}", collection)
            };
            highlighted_line(
                &format!("{vendor}/{product} pkg:{package} status:{status}{suffix}"),
                detail_search,
            )
        }));
    }
    lines
}
