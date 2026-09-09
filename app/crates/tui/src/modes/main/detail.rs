use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, Markup, focus_style, highlighted_line, markup_lines},
    display::TimeZone,
    traits::detail::DetailPanel,
    utils::datetime::format_timestamp,
};
use qanvuli_core::database::{
    CveAffectedDetail, CveSummaryWithDetail, OsvSummary, cve_state_label,
};
use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(super) struct MainDetailPanel;

impl DetailPanel for MainDetailPanel {
    fn render(
        &self,
        frame: &mut ratatui::Frame<'_>,
        app: &mut App,
        detail_search: &DetailSearch,
        area: Rect,
    ) {
        let content_width = area.width.saturating_sub(2).max(1) as usize;
        let detail = if let Some(cve) = app.selected() {
            detail_lines(cve, app.main.display.timezone, detail_search, content_width)
        } else if let Some(osv) = app.selected_osv() {
            osv_detail_lines(osv, app.main.display.timezone, detail_search, content_width)
        } else {
            vec![Line::from("No results")]
        };
        let line_count =
            crate::common::text::cached_line_count(&detail, content_width as u16, false);
        app.main.detail_scroll = app.main.detail_scroll.min(
            line_count
                .saturating_sub(app.main.right_page_size)
                .min(u16::MAX as usize) as u16,
        );
        let detail_title = if let Some(cve) = app.selected() {
            format!(
                "{} [{}]",
                cve.summary.cve_id,
                cve_state_label(cve.summary.state)
            )
        } else if let Some(osv) = app.selected_osv() {
            format!("{} [OSV]", osv.osv_id)
        } else {
            "Result".to_owned()
        };
        let detail = Paragraph::new(detail)
            .block(
                Block::default()
                    .title(detail_title)
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.main.focus == PaneFocus::Right)),
            )
            .scroll((app.main.detail_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, area);
    }
}

pub(crate) fn osv_detail_lines(
    osv: &OsvSummary,
    timezone: TimeZone,
    detail_search: &DetailSearch,
    width: usize,
) -> Vec<Line<'static>> {
    let timestamp = |label: &str, value: Option<&str>| {
        highlighted_line(
            &format!(
                "{label}: {}",
                value
                    .map(|value| format_timestamp(value, timezone))
                    .unwrap_or_else(|| "-".to_owned())
            ),
            detail_search,
        )
    };
    let mut lines = vec![
        highlighted_line(
            &format!("Product: {}", osv.package_summary.as_deref().unwrap_or("-")),
            detail_search,
        ),
        timestamp("Published", osv.published_at.as_deref()),
        timestamp("Updated", osv.modified_at.as_deref()),
        timestamp("Withdrawn", osv.withdrawn_at.as_deref()),
        Line::from(""),
    ];
    lines.extend(markup_lines(
        osv.summary.as_deref().unwrap_or("-"),
        width,
        Markup::Markdown,
        detail_search,
    ));
    lines.push(Line::from(""));
    lines.extend(markup_lines(
        osv.details.as_deref().unwrap_or("-"),
        width,
        Markup::Markdown,
        detail_search,
    ));
    lines
}

pub(crate) fn detail_lines(
    cve: &CveSummaryWithDetail,
    timezone: TimeZone,
    detail_search: &DetailSearch,
    width: usize,
) -> Vec<Line<'static>> {
    let summary = &cve.summary;
    let (products, vendors) = product_vendor_summaries(&cve.detail.affected);
    let mut lines = vec![
        highlighted_line(&format!("Product: {products}"), detail_search),
        highlighted_line(&format!("Vendor: {vendors}"), detail_search),
        highlighted_line(
            &format!(
                "Published: {}",
                format_timestamp(&summary.published_at, timezone)
            ),
            detail_search,
        ),
        highlighted_line(
            &format!(
                "Updated: {}",
                format_timestamp(&summary.updated_at, timezone)
            ),
            detail_search,
        ),
        Line::from(""),
        highlighted_line(&summary.title, detail_search),
        Line::from(""),
    ];
    lines.extend(markup_lines(
        summary.description_en.as_deref().unwrap_or_default(),
        width,
        Markup::Html,
        detail_search,
    ));
    lines
}

fn product_vendor_summaries(affected: &[CveAffectedDetail]) -> (String, String) {
    let mut products = Vec::new();
    let mut vendors = Vec::new();
    for affected in affected {
        let vendor = affected.vendor.as_deref().unwrap_or("-");
        let product = affected.product.as_deref().unwrap_or("-");
        if !products.contains(&product) {
            products.push(product);
        }
        if !vendors.contains(&vendor) {
            vendors.push(vendor);
        }
        if products.len() >= 3 && vendors.len() >= 3 {
            break;
        }
    }
    (
        summary_values(products, affected.len()),
        summary_values(vendors, affected.len()),
    )
}

fn summary_values(values: Vec<&str>, affected_count: usize) -> String {
    if values.is_empty() {
        return "-".to_owned();
    }
    let suffix = if affected_count > values.len() {
        " ..."
    } else {
        ""
    };
    format!("{}{suffix}", values.join(", "))
}
