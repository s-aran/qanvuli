mod detail;
pub(crate) mod handler;
pub(crate) mod keyword;
mod list;
pub(crate) mod status;
mod status_filter;

use crate::traits::{
    detail::DetailPanel, keyword::KeywordInput, list::ResultList, status::StatusLine,
};
use crate::{app::App, common::DetailSearch};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::Paragraph,
};

pub(crate) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App, detail_search: &DetailSearch) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(main[1]);

    keyword::CweKeywordInput.render(frame, app, main[0]);
    list::CweList.render(frame, app, body[0]);
    detail::CweDetailPanel.render(frame, app, detail_search, body[1]);

    frame.render_widget(Paragraph::new(status::CweStatusLine.text(app)), main[2]);
    if app.show_cwe_status {
        status_filter::render(frame, app);
    }
}
