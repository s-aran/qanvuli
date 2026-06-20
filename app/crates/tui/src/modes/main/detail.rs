use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, focus_style, highlighted_line},
    display::TimeZone,
    traits::detail::DetailPanel,
    utils::datetime::format_timestamp,
};
use qanvuli_db::{CveAffectedDetail, CveSummaryWithDetail, cve_state_label};
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
        let detail = app
            .selected()
            .map(|cve| detail_lines(cve, app.display.timezone, detail_search))
            .unwrap_or_else(|| vec![Line::from("No results")]);
        app.clamp_detail_scroll();
        let detail_title = app
            .selected()
            .map(|cve| {
                format!(
                    "{} [{}]",
                    cve.summary.cve_id,
                    cve_state_label(cve.summary.state)
                )
            })
            .unwrap_or_else(|| "CVE".to_owned());
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

fn detail_lines(
    cve: &CveSummaryWithDetail,
    timezone: TimeZone,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let summary = &cve.summary;
    vec![
        highlighted_line(&product_vendor_summary(&cve.detail.affected), detail_search),
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

fn product_vendor_summary(affected: &[CveAffectedDetail]) -> String {
    let mut values = Vec::new();
    for affected in affected {
        let vendor = affected.vendor.as_deref().unwrap_or("-");
        let product = affected.product.as_deref().unwrap_or("-");
        let value = format!("{product} / {vendor}");
        if !values.contains(&value) {
            values.push(value);
        }
        if values.len() >= 3 {
            break;
        }
    }
    if values.is_empty() {
        "-".to_owned()
    } else {
        let suffix = if affected.len() > values.len() {
            " ..."
        } else {
            ""
        };
        format!("{}{suffix}", values.join(", "))
    }
}
