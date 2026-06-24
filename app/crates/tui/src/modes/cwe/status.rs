use crate::{app::App, common::status::detail_search_status, traits::status::StatusLine};

pub(crate) struct CweStatusLine;

impl StatusLine for CweStatusLine {
    fn text(&self, app: &App) -> String {
        format!(
            "F4 status | Left parent | Right return | [ ] siblings | / search detail | Tab focus | {}",
            detail_search_status(app)
        )
    }
}
