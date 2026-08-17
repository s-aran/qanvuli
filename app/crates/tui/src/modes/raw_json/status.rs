use crate::{app::App, common::status::detail_search_status, traits::status::StatusLine};

pub(crate) struct RawJsonStatusLine {
    pub(crate) at_eof: bool,
}

impl StatusLine for RawJsonStatusLine {
    fn text(&self, app: &App) -> String {
        let position = if self.at_eof { "EOF" } else { "-" };
        format!(
            "Esc/F8 close | F1/? help | {position} | {}",
            detail_search_status(app)
        )
    }
}
