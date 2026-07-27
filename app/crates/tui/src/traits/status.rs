use crate::app::App;

pub(crate) trait StatusLine {
    fn text(&self, app: &App) -> String;
}
