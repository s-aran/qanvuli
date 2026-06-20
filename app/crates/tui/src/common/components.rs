use crate::traits::component::LineComponent;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

pub(crate) struct ActionButton {
    pub(crate) label: &'static str,
    pub(crate) active: bool,
}

impl LineComponent for ActionButton {
    fn line(&self) -> Line<'static> {
        Line::from(Span::styled(
            format!("[ {} ]", self.label),
            selected_style(self.active, Color::Yellow),
        ))
    }
}

pub(crate) struct ButtonRow {
    pub(crate) buttons: Vec<ActionButton>,
}

impl LineComponent for ButtonRow {
    fn line(&self) -> Line<'static> {
        let mut spans = Vec::new();
        for (index, button) in self.buttons.iter().enumerate() {
            if index > 0 {
                spans.push(Span::raw("  "));
            }
            spans.extend(button.line().spans);
        }
        Line::from(spans)
    }
}

pub(crate) struct Checkbox {
    pub(crate) label: String,
    pub(crate) checked: bool,
    pub(crate) active: bool,
    pub(crate) active_color: Color,
}

impl LineComponent for Checkbox {
    fn line(&self) -> Line<'static> {
        let marker = if self.checked { "[x]" } else { "[ ]" };
        let style = active_style(self.active, self.active_color);
        Line::from(vec![
            Span::styled(marker, style),
            Span::raw(format!(" {}", self.label)),
        ])
    }
}

pub(crate) struct RadioOption {
    pub(crate) label: &'static str,
    pub(crate) selected: bool,
    pub(crate) active_color: Color,
}

impl LineComponent for RadioOption {
    fn line(&self) -> Line<'static> {
        let marker = if self.selected { "(*) " } else { "( ) " };
        let style = active_style(self.selected, self.active_color);
        Line::from(vec![
            Span::styled(marker, style),
            Span::styled(self.label.to_owned(), style),
        ])
    }
}

pub(crate) struct SelectableField {
    pub(crate) label: &'static str,
    pub(crate) value: String,
    pub(crate) active: bool,
    pub(crate) active_color: Color,
}

impl LineComponent for SelectableField {
    fn line(&self) -> Line<'static> {
        let style = active_style(self.active, self.active_color);
        Line::from(vec![
            Span::styled(format!("{}: ", self.label), style),
            Span::raw(self.value.clone()),
        ])
    }
}

fn selected_style(active: bool, active_color: Color) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(active_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn active_style(active: bool, active_color: Color) -> Style {
    if active {
        Style::default()
            .fg(active_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}
