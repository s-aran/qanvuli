use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, focus_style, highlighted_line},
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
        let detail = if let Some(cve) = app.selected() {
            detail_lines(cve, app.display.timezone, detail_search)
        } else if let Some(osv) = app.selected_osv() {
            osv_detail_lines(osv, app.display.timezone, detail_search)
        } else {
            vec![Line::from("No results")]
        };
        app.clamp_detail_scroll();
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
                    .border_style(focus_style(app.focus == PaneFocus::Right)),
            )
            .scroll((app.detail_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, area);
    }
}

pub(crate) fn osv_detail_lines(
    osv: &OsvSummary,
    timezone: TimeZone,
    detail_search: &DetailSearch,
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
    vec![
        highlighted_line(
            &format!("Product: {}", osv.package_summary.as_deref().unwrap_or("-")),
            detail_search,
        ),
        timestamp("Published", osv.published_at.as_deref()),
        timestamp("Updated", osv.modified_at.as_deref()),
        timestamp("Withdrawn", osv.withdrawn_at.as_deref()),
        Line::from(""),
        // summary
        highlighted_line(
            &format!("{}", osv.summary.as_deref().unwrap_or("-")),
            detail_search,
        ),
        Line::from(""),
        // details
        highlighted_line(
            &format!("{}", osv.details.as_deref().unwrap_or("-")),
            detail_search,
        ),
    ]
}

pub(crate) fn detail_lines(
    cve: &CveSummaryWithDetail,
    timezone: TimeZone,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let summary = &cve.summary;
    let (products, vendors) = product_vendor_summaries(&cve.detail.affected);
    vec![
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
        highlighted_line(
            summary.description_en.as_deref().unwrap_or_default(),
            detail_search,
        ),
    ]
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
