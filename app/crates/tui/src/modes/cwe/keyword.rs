use crate::{app::App, traits::keyword::KeywordInput};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

pub(super) struct CweKeywordInput;

impl KeywordInput for CweKeywordInput {
    fn render(&self, frame: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
        let input = Paragraph::new(app.cwe_query.as_str()).block(
            Block::default()
                .title(format!("CWE Search [Status: {}]", app.cwe_status_summary()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
        frame.render_widget(input, area);
    }
}
