use super::DetailSearch;
use html2text::render::RichAnnotation;
use ratada::markdown::{StyleSheet, render_block};
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

pub(crate) fn highlighted_line(text: &str, detail_search: &DetailSearch) -> Line<'static> {
    highlight_rich_line(Line::from(text.to_owned()), detail_search)
}

#[derive(Clone, Copy)]
pub(crate) enum Markup {
    Html,
    Markdown,
}

pub(crate) fn markup_lines(
    text: &str,
    width: usize,
    markup: Markup,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let width = width.max(1);
    let lines = match markup {
        Markup::Html => html_lines(text, width).unwrap_or_else(|| plain_lines(text)),
        Markup::Markdown => markdown_lines(text, width),
    };
    lines
        .into_iter()
        .map(|line| highlight_rich_line(line, detail_search))
        .collect()
}

fn plain_lines(text: &str) -> Vec<Line<'static>> {
    text.lines()
        .map(|line| Line::from(line.to_owned()))
        .collect()
}

fn markdown_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    let sheet = StyleSheet {
        preserve_line_breaks: true,
        ..StyleSheet::default()
    };
    render_block(text, width, &sheet)
}

fn html_lines(text: &str, width: usize) -> Option<Vec<Line<'static>>> {
    let lines = html2text::from_read_rich(text.as_bytes(), width).ok()?;
    Some(
        lines
            .iter()
            .map(|line| {
                Line::from(
                    line.tagged_strings()
                        .map(|tagged| Span::styled(tagged.s.clone(), html_style(&tagged.tag)))
                        .collect::<Vec<_>>(),
                )
            })
            .collect(),
    )
}

fn html_style(annotations: &[RichAnnotation]) -> Style {
    annotations
        .iter()
        .fold(Style::default(), |style, annotation| {
            let annotation_style = match annotation {
                RichAnnotation::Default => Style::default(),
                RichAnnotation::Link(_) => Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::UNDERLINED),
                RichAnnotation::Image(_) => Style::default().fg(Color::Cyan),
                RichAnnotation::Emphasis => Style::default().add_modifier(Modifier::ITALIC),
                RichAnnotation::Strong => Style::default().add_modifier(Modifier::BOLD),
                RichAnnotation::Strikeout => Style::default().add_modifier(Modifier::CROSSED_OUT),
                RichAnnotation::Code => Style::default().fg(Color::Yellow),
                RichAnnotation::Preformat(continuation) => Style::default().fg(if *continuation {
                    Color::LightMagenta
                } else {
                    Color::Magenta
                }),
                RichAnnotation::Colour(colour) => {
                    Style::default().fg(Color::Rgb(colour.r, colour.g, colour.b))
                }
                RichAnnotation::BgColour(colour) => {
                    Style::default().bg(Color::Rgb(colour.r, colour.g, colour.b))
                }
                _ => Style::default(),
            };
            style.patch(annotation_style)
        })
}

fn highlight_rich_line(line: Line<'static>, detail_search: &DetailSearch) -> Line<'static> {
    let Some(regex) = &detail_search.regex else {
        return line;
    };
    let text = line
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    let matches = regex
        .find_iter(&text)
        .filter(|matched| matched.start() != matched.end())
        .map(|matched| matched.start()..matched.end())
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return line;
    }

    let mut spans = Vec::new();
    let mut span_start = 0;
    for span in line.spans {
        let span_text = span.content.as_ref();
        let span_end = span_start + span_text.len();
        let mut cursor = 0;
        for matched in matches
            .iter()
            .filter(|matched| matched.start < span_end && matched.end > span_start)
        {
            let start = matched.start.saturating_sub(span_start);
            let end = matched.end.min(span_end) - span_start;
            if cursor < start {
                spans.push(Span::styled(
                    span_text[cursor..start].to_owned(),
                    span.style,
                ));
            }
            if start < end {
                spans.push(Span::styled(
                    span_text[start..end].to_owned(),
                    span.style.patch(search_match_style()),
                ));
            }
            cursor = end;
        }
        if cursor < span_text.len() {
            spans.push(Span::styled(span_text[cursor..].to_owned(), span.style));
        }
        span_start = span_end;
    }

    Line {
        style: line.style,
        alignment: line.alignment,
        spans,
    }
}

fn search_match_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::{DetailSearch, Markup, highlight_rich_line, markup_lines};
    use ratatui::{
        style::{Color, Modifier, Style},
        text::{Line, Span},
    };

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn renders_markdown_without_markup_symbols() {
        let lines = markup_lines(
            "# Heading\n\n**important**",
            40,
            Markup::Markdown,
            &DetailSearch::new(""),
        );

        assert_eq!(text(&lines), "Headingimportant");
        assert!(lines.iter().flat_map(|line| &line.spans).any(|span| {
            span.content.contains("important") && span.style.add_modifier.contains(Modifier::BOLD)
        }));
    }

    #[test]
    fn renders_html_with_rich_annotations() {
        let lines = markup_lines(
            "<p><strong>important</strong> <a href='https://example.com'>link</a></p>",
            40,
            Markup::Html,
            &DetailSearch::new(""),
        );

        assert_eq!(text(&lines).trim(), "important link");
        assert!(lines.iter().flat_map(|line| &line.spans).any(|span| {
            span.content.contains("important") && span.style.add_modifier.contains(Modifier::BOLD)
        }));
        assert!(lines.iter().flat_map(|line| &line.spans).any(|span| {
            span.content.contains("link") && span.style.add_modifier.contains(Modifier::UNDERLINED)
        }));
    }

    #[test]
    fn wraps_rich_text_to_the_requested_terminal_width() {
        for (source, markup) in [
            (
                "A **long Markdown** sentence that must wrap.",
                Markup::Markdown,
            ),
            (
                "<p>A <strong>long HTML</strong> sentence that must wrap.</p>",
                Markup::Html,
            ),
        ] {
            let lines = markup_lines(source, 12, markup, &DetailSearch::new(""));

            assert!(lines.len() > 1, "source was not wrapped: {source}");
            assert!(
                lines.iter().all(|line| line.width() <= 12),
                "source exceeded the requested width: {source}"
            );
        }
    }

    #[test]
    fn markdown_can_contain_html_inside_a_code_fence() {
        let source = "## Details\n\n```html\n<p>example</p>\n```";
        let lines = markup_lines(source, 40, Markup::Markdown, &DetailSearch::new(""));
        let rendered = text(&lines);

        assert!(rendered.contains("Details"));
        assert!(rendered.contains("<p>example</p>"));
        assert!(!rendered.contains("##"));
        assert!(!rendered.contains("```"));
        assert!(lines.iter().flat_map(|line| &line.spans).any(|span| {
            span.content.contains("Details") && span.style.add_modifier.contains(Modifier::BOLD)
        }));
    }

    #[test]
    fn search_highlight_is_overlaid_across_style_boundaries() {
        let line = Line::from(vec![
            Span::styled("nee", Style::default().fg(Color::Blue)),
            Span::styled("dle", Style::default().add_modifier(Modifier::ITALIC)),
        ]);
        let line = highlight_rich_line(line, &DetailSearch::new("eedl"));
        let highlighted = line
            .spans
            .iter()
            .filter(|span| span.style.bg == Some(Color::Yellow))
            .collect::<Vec<_>>();

        assert_eq!(highlighted.len(), 2);
        assert_eq!(highlighted[0].content, "ee");
        assert_eq!(highlighted[1].content, "dl");
        assert_eq!(highlighted[0].style.fg, Some(Color::Black));
        assert!(highlighted[1].style.add_modifier.contains(Modifier::ITALIC));
    }
}
