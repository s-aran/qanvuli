use crate::{
    app::App, common::status::detail_search_status, form::StateScopeUi, traits::status::StatusLine,
    utils::datetime::format_timestamp,
};

pub(crate) struct MainStatusLine;

impl StatusLine for MainStatusLine {
    fn text(&self, app: &App) -> String {
        let status = app
            .maintenance_status()
            .or(app.overlay.status_message.as_deref())
            .unwrap_or_else(|| app.detail_status());
        let db_as_of = app
            .main
            .db_as_of
            .as_deref()
            .map(|value| format_timestamp(value, app.main.display.timezone))
            .unwrap_or_else(|| "-".to_owned());
        let activity = if app.searching() {
            app.search_spinner().to_owned()
        } else {
            status.to_owned()
        };
        format!(
            "F1/? help | Enter search | {activity} | {}/{} | {} | DB {db_as_of} {} | {}",
            app.main.display.sort_field.label(),
            app.main.display.sort_direction.label(),
            app.main.state_scope.label(),
            app.main.display.timezone.label(),
            detail_search_status(app)
        )
    }
}
