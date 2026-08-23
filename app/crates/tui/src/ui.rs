use crate::{
    common::{DetailSearch, popups},
    modes,
};

use super::app::{App, ViewMode};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let detail_search = DetailSearch::new(&app.overlay.detail_search_query);
    app.overlay.detail_search_error = detail_search.error.clone();

    match app.raw.view_mode {
        ViewMode::Normal => modes::main::draw(frame, app, &detail_search),
        ViewMode::RawJson => modes::raw_json::draw(frame, app, &detail_search),
        ViewMode::CweList => modes::cwe::draw(frame, app, &detail_search),
        ViewMode::CapecList => modes::capec::draw(frame, app, &detail_search),
    }

    if app.overlay.show_help {
        popups::draw_help(frame);
    }
    if app.overlay.show_advanced {
        popups::draw_advanced(frame, app);
    }
    if app.overlay.show_display {
        popups::draw_display(frame, app);
    }
    if app.overlay.show_timeout_prompt {
        popups::draw_timeout_prompt(frame, app);
    }
    if app.overlay.show_maintenance {
        popups::draw_maintenance(frame, app);
    }
}
