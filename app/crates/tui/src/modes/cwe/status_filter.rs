use crate::{
    app::{App, CWE_CAPEC_CURSOR, CWE_STATUSES},
    common::{
        centered_rect,
        components::{ActionButton, ButtonRow, Checkbox},
    },
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
    lines.push(Line::from(format!(
        "{}CAPEC ID: {}",
        if app.cwe_status_cursor == CWE_CAPEC_CURSOR {
            "> "
        } else {
            "  "
        },
        app.cwe_capec_filter
    )));
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
    lines.push(
        ButtonRow {
            buttons: vec![
                ActionButton {
                    label: "Select All",
                    active: app.cwe_status_cursor == CWE_STATUSES.len(),
                },
                ActionButton {
                    label: "Clear All",
                    active: app.cwe_status_cursor == CWE_STATUSES.len() + 1,
                },
            ],
        }
        .line(),
    );
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Space toggle/apply  Enter apply/close  A all  X clear",
    ));
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
