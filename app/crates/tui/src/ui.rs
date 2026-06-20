use crate::{
    common::{DetailSearch, popups},
    modes,
};

use super::app::{App, ViewMode};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let detail_search = DetailSearch::new(&app.detail_search_query);
    app.detail_search_error = detail_search.error.clone();

    match app.view_mode {
        ViewMode::Normal => modes::main::draw(frame, app, &detail_search),
        ViewMode::RawJson => modes::raw_json::draw(frame, app, &detail_search),
        ViewMode::CweList => modes::cwe::draw(frame, app, &detail_search),
    }

    if app.show_help {
        popups::draw_help(frame);
    }
    if app.show_advanced {
        popups::draw_advanced(frame, app);
    }
    if app.show_display {
        popups::draw_display(frame, app);
    }
    if app.show_timeout_prompt {
        popups::draw_timeout_prompt(frame, app);
    }
    if app.show_maintenance {
        popups::draw_maintenance(frame, app);
    }
}
