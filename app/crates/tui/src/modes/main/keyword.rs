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
            app.main.search_mode.footer_text(),
            app.main.limit
        );
        let cursor = if app.main.focus == PaneFocus::Left {
            "▏"
        } else {
            ""
        };
        let input = Paragraph::new(format!("{}{cursor}", app.main.query))
            .block(
                Block::default()
                    .title(input_title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.main.search_mode.color())),
            )
            .style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_widget(input, area);
    }
}
