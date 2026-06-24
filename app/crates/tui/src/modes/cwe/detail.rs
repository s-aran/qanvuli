use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, focus_style, highlighted_line, status::detail_search_title_suffix},
    traits::detail::DetailPanel,
};
use qanvuli_db::CweEntry;
use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(super) struct CweDetailPanel;

impl DetailPanel for CweDetailPanel {
    fn render(
        &self,
        frame: &mut ratatui::Frame<'_>,
        app: &mut App,
        detail_search: &DetailSearch,
        area: Rect,
    ) {
        let detail = app
            .selected_cwe()
            .map(|cwe| cwe_detail_lines(cwe, detail_search))
            .unwrap_or_else(|| vec![Line::from("No CWE selected")]);
        let title = app
            .selected_cwe()
            .map(|cwe| format!("CWE-{} detail{}", cwe.id, detail_search_title_suffix(app)))
            .unwrap_or_else(|| format!("CWE detail{}", detail_search_title_suffix(app)));
        let detail = Paragraph::new(detail)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.focus == PaneFocus::Right)),
            )
            .scroll((app.cwe_detail_scroll, 0))
            .wrap(Wrap { trim: true });
        frame.render_widget(detail, area);
    }
}

fn cwe_detail_lines(cwe: &CweEntry, detail_search: &DetailSearch) -> Vec<Line<'static>> {
    let mut lines = vec![
        highlighted_line(&format!("CWE-{}", cwe.id), detail_search),
        highlighted_line(
            &format!("Status: {}", cwe.status.as_deref().unwrap_or("-")),
            detail_search,
        ),
        highlighted_line(&format!("Parent: {}", cwe.parent_count), detail_search),
        highlighted_line(&format!("Siblings: {}", cwe.sibling_count), detail_search),
        highlighted_line(&format!("Children: {}", cwe.child_count), detail_search),
        Line::from(""),
    ];
    lines.extend(
        cwe.description
            .as_deref()
            .unwrap_or("")
            .lines()
            .map(|line| highlighted_line(line, detail_search)),
    );
    lines
}
