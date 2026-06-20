use crate::{
    app::{App, CWE_STATUSES},
    common::{centered_rect, components::Checkbox},
    traits::component::LineComponent,
};
use ratatui::{
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

pub(super) fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(48, 34, frame.area());
    let mut lines = vec![Line::from("Select CWE Status values.")];
    lines.push(Line::from(""));
    for (index, status) in CWE_STATUSES.iter().enumerate() {
        lines.push(
            Checkbox {
                label: status.label().to_owned(),
                checked: app.cwe_status_filter[index],
                active: app.cwe_status_cursor == index,
                active_color: Color::Yellow,
            }
            .line(),
        );
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Space toggle  Enter/Esc close"));
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title("CWE Status Filter")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}
