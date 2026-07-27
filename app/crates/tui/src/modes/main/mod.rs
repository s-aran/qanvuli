mod candidates;
pub(crate) mod detail;
pub(crate) mod handler;
mod keyword;
mod metadata;
pub(crate) mod right;
pub(crate) mod status;

use crate::traits::{keyword::KeywordInput, list::ResultList, status::StatusLine};
use crate::{app::App, common::DetailSearch};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    widgets::Paragraph,
};

pub(crate) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App, detail_search: &DetailSearch) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(main[0]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(chunks[0]);
    app.set_page_sizes(
        left[1].height.saturating_sub(2) as usize,
        chunks[1].height.saturating_sub(5) as usize,
        chunks[1].height.saturating_sub(3) as usize,
        chunks[1].width.saturating_sub(4) as usize,
        chunks[1].width.saturating_sub(2) as usize,
    );

    keyword::MainKeywordInput.render(frame, app, left[0]);
    candidates::CandidateList.render(frame, app, left[1]);

    let footer = Paragraph::new(status::MainStatusLine.text(app)).style(
        Style::default()
            .fg(app.search_mode.color())
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(footer, main[1]);

    right::render(frame, app, detail_search, chunks[1]);
}
