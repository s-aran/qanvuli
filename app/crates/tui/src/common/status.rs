use crate::app::App;

pub(crate) fn detail_search_status(app: &App) -> String {
    if app.overlay.detail_search_input {
        format!("/{}", app.overlay.detail_search_query)
    } else if let Some(error) = &app.overlay.detail_search_error {
        error.clone()
    } else if app.overlay.detail_search_query.is_empty() {
        "no detail search".to_owned()
    } else {
        format!("regex: /{}", app.overlay.detail_search_query)
    }
}

pub(crate) fn detail_search_title_suffix(app: &App) -> String {
    if app.overlay.detail_search_query.is_empty() {
        String::new()
    } else {
        format!(" /{}", app.overlay.detail_search_query)
    }
}
