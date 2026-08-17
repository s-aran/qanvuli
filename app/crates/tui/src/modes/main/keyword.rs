use crate::{
    app::{App, PaneFocus},
    traits::keyword::KeywordInput,
};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph},
};

pub(super) struct MainKeywordInput;

impl KeywordInput for MainKeywordInput {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let input_title = format!(
            "Search [{}] - limit {}",
            app.search_mode.footer_text(),
            app.limit
        );
        let cursor = if app.focus == PaneFocus::Left {
            "▏"
        } else {
            ""
        };
        let input = Paragraph::new(format!("{}{cursor}", app.query))
            .block(
                Block::default()
                    .title(input_title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.search_mode.color())),
            )
            .style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(input, area);
    }
}
