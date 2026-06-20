pub(crate) mod detail;
pub(crate) mod handler;
pub(crate) mod status;

use crate::{
    app::App,
    common::DetailSearch,
    traits::{detail::DetailPanel, status::StatusLine},
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::Paragraph,
};

pub(crate) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App, detail_search: &DetailSearch) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());
    let at_eof = detail::RawJsonDetailPanel.at_eof(app, main[0]);
    detail::RawJsonDetailPanel.render(frame, app, detail_search, main[0]);

    frame.render_widget(
        Paragraph::new(status::RawJsonStatusLine { at_eof }.text(app))
            .style(Style::default().fg(Color::Yellow)),
        main[1],
    );
}
