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
    let width = width.max(1);
    value
        .lines()
        .map(|line| (line.chars().count().max(1) + width - 1) / width)
        .sum::<usize>()
        .max(1)
}
