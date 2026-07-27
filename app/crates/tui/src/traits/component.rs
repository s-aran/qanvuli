use ratatui::text::Line;

pub(crate) trait LineComponent {
    fn line(&self) -> Line<'static>;
}
