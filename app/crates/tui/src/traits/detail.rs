use crate::{app::App, common::DetailSearch};
use ratatui::layout::Rect;

pub(crate) trait DetailPanel {
    fn render(
        &self,
        frame: &mut ratatui::Frame<'_>,
        app: &mut App,
        detail_search: &DetailSearch,
        area: Rect,
    );
}
