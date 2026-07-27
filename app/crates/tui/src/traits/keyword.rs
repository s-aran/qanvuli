use crate::app::App;
use ratatui::layout::Rect;

pub(crate) trait KeywordInput {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect);
}
