use crate::{
    app::App, common::status::detail_search_status, form::StateScopeUi, traits::status::StatusLine,
    utils::datetime::format_timestamp,
};

pub(crate) struct MainStatusLine;

impl StatusLine for MainStatusLine {
    fn text(&self, app: &App) -> String {
        let status = app
            .maintenance_status()
            .or(app.status_message.as_deref())
            .unwrap_or_else(|| app.detail_status());
        let db_as_of = app
            .db_as_of
            .as_deref()
            .map(|value| format_timestamp(value, app.display.timezone))
            .unwrap_or_else(|| "-".to_owned());
        let activity = if app.searching() {
            app.search_spinner().to_owned()
        } else {
            status.to_owned()
        };
        format!(
            "{} | {} {} | {} | DB: {} | {} | {}",
            activity,
            app.display.sort_field.label(),
            app.display.sort_direction.label(),
            app.state_scope.label(),
            db_as_of,
            app.display.timezone.label(),
            detail_search_status(app)
        )
    }
}
