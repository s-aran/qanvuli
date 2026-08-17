use crate::{app::App, common::status::detail_search_status, traits::status::StatusLine};

pub(crate) struct CweStatusLine;

impl StatusLine for CweStatusLine {
    fn text(&self, app: &App) -> String {
        format!(
            "Esc/F9 close | F1/? help | F4 filter | Left parent | Right return | [ ] siblings | / find | Tab pane | {}",
            detail_search_status(app)
        )
    }
}
