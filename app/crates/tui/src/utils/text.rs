pub(crate) fn normalize_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn progress_ratio(written: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (written as f64 / total as f64).clamp(0.0, 1.0)
    }
}

pub(crate) fn wrapped_line_count(value: &str, width: usize) -> usize {
    Paragraph::new(value)
        .wrap(Wrap { trim: false })
        .line_count(width.clamp(1, u16::MAX as usize) as u16)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::wrapped_line_count;

    #[test]
    fn counts_terminal_cells_instead_of_unicode_scalar_values() {
        assert_eq!(wrapped_line_count("あいうえお", 4), 3);
    }

    #[test]
    fn counts_wrapped_words_the_same_way_as_the_paragraph_widget() {
        assert_eq!(wrapped_line_count("one two three", 7), 3);
    }
}
use ratatui::widgets::{Paragraph, Wrap};
