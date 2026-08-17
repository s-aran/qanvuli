use ratatui::layout::Rect;

pub(crate) fn centered_size(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_popup_size_is_centered_and_clamped_to_the_terminal() {
        assert_eq!(
            centered_size(60, 20, Rect::new(0, 0, 80, 24)),
            Rect::new(10, 2, 60, 20)
        );
        assert_eq!(
            centered_size(60, 20, Rect::new(3, 4, 40, 12)),
            Rect::new(3, 4, 40, 12)
        );
    }
}
