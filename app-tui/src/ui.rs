use super::{
    app::{App, PaneFocus},
    form::{AdvancedField, AdvancedForm, SortOrderUi, StateScopeUi},
};
use qanvuli_db::{CveDetail, CveSummary, cve_state_label};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(frame.area());
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(chunks[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(68),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(chunks[1]);
    app.set_page_sizes(
        left[1].height.saturating_sub(2) as usize,
        right[0].height.saturating_sub(2) as usize,
    );

    let input_title = if app.searching() {
        format!("Search - searching {}", app.spinner())
    } else {
        format!("Search - limit {}", app.limit)
    };
    let input = Paragraph::new(app.query.as_str())
        .block(
            Block::default()
                .title(input_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.search_mode.color())),
        )
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(input, left[0]);

    let items = app
        .results
        .iter()
        .map(|cve| {
            ListItem::new(vec![
                Line::from(Span::raw(cve.cve_id.clone())),
                Line::from(Span::raw(cve.title.clone())),
            ])
        })
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Candidates ({}/{})",
                    app.results.len(),
                    app.total_results
                        .map(|total| total.to_string())
                        .unwrap_or_else(|| "-".to_owned())
                ))
                .borders(Borders::ALL)
                .border_style(focus_style(app.focus == PaneFocus::Left)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, left[1], &mut app.list_state);

    let footer = Paragraph::new(format!(
        "{} | State: {}",
        app.search_mode.footer_text(),
        app.state_scope.label()
    ))
    .style(
        Style::default()
            .fg(app.search_mode.color())
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(footer, left[2]);

    let detail = app
        .selected()
        .map(detail_lines)
        .unwrap_or_else(|| vec![Line::from("No results")]);
    app.clamp_detail_scroll_to_lines(detail.len());
    let detail_title = app
        .selected()
        .map(|cve| cve.cve_id.as_str())
        .unwrap_or("CVE");
    let detail = Paragraph::new(detail)
        .block(
            Block::default()
                .title(detail_title)
                .borders(Borders::ALL)
                .border_style(focus_style(app.focus == PaneFocus::Right)),
        )
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, right[0]);

    let metadata = Paragraph::new(metadata_lines(app.detail.as_ref()))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(metadata, right[1]);

    let status = Paragraph::new(app.detail_status()).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(status, right[2]);

    if app.show_help {
        draw_help(frame);
    }
    if app.show_advanced {
        draw_advanced(frame, app);
    }
}

fn focus_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

fn draw_help(frame: &mut ratatui::Frame<'_>) {
    let area = centered_rect(60, 42, frame.area());
    let help = Paragraph::new(vec![
        Line::from("Enter  Search current input"),
        Line::from("Tab    Switch pane focus"),
        Line::from("F3     Open advanced search"),
        Line::from("F4     Toggle PUBLISHED only / include REJECTED"),
        Line::from("Shift+Tab Switch search mode"),
        Line::from("Left/Right Switch pane focus"),
        Line::from("Up/Down Move focused pane"),
        Line::from("Ctrl-U/D Half-page up/down focused pane"),
        Line::from("Ctrl-B/F Full-page up/down focused pane"),
        Line::from("F1     Show this help"),
        Line::from("Esc    Close this help"),
        Line::from("Ctrl-C Quit"),
    ])
    .block(Block::default().title("Help").borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(help, area);
}

fn draw_advanced(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(70, 58, frame.area());
    let form = &app.advanced;
    let lines = vec![
        advanced_line(
            form,
            AdvancedField::Query,
            "Input AND",
            &format!("{} {}", form.query_mode.footer_text(), form.query),
        ),
        advanced_line(
            form,
            AdvancedField::PublishedFrom,
            "Published from",
            &form.published_from,
        ),
        advanced_line(
            form,
            AdvancedField::PublishedTo,
            "Published to",
            &form.published_to,
        ),
        advanced_line(form, AdvancedField::Cwe, "CWE", &form.cwe),
        advanced_line(form, AdvancedField::Product, "Product", &form.product),
        advanced_line(form, AdvancedField::Vendor, "Vendor", &form.vendor),
        advanced_line(
            form,
            AdvancedField::StateScope,
            "State",
            form.state_scope.label(),
        ),
        advanced_line(
            form,
            AdvancedField::SortOrder,
            "Sort order",
            form.sort_order.label(),
        ),
        Line::from(""),
        Line::from(
            "Enter search  Esc close  Tab/Down next  Shift+Tab/Up previous  Left/Right state/sort",
        ),
    ];
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Advanced Search")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn advanced_line(
    form: &AdvancedForm,
    field: AdvancedField,
    label: &'static str,
    value: &str,
) -> Line<'static> {
    let active = form.active_field == field;
    let marker = if active { "> " } else { "  " };
    let style = if active {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(marker, style),
        Span::styled(format!("{label}: "), style),
        Span::raw(value.to_owned()),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn detail_lines(cve: &CveSummary) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled("State: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve_state_label(cve.state)),
        ]),
        Line::from(vec![
            Span::styled("Published: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.published_at.clone()),
        ]),
        Line::from(vec![
            Span::styled("Updated: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cve.updated_at.clone()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            cve.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(cve.description_en.clone().unwrap_or_default()),
    ]
}

fn metadata_lines(detail: Option<&CveDetail>) -> Vec<Line<'static>> {
    let Some(detail) = detail else {
        return vec![Line::from("Loading")];
    };
    let mut lines = Vec::new();
    if detail.cwes.is_empty() {
        lines.push(Line::from("No CWE"));
    } else {
        lines.extend(detail.cwes.iter().map(|cwe| {
            let description = cwe.description.as_deref().unwrap_or_default();
            Line::from(format!("CWE-{} {}", cwe.id, description))
        }));
    }
    lines.push(Line::from(""));
    if detail.cvss.is_empty() {
        lines.push(Line::from("No CVSS"));
    } else {
        lines.extend(detail.cvss.iter().map(|cvss| {
            let score = cvss
                .base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| "-".to_owned());
            let severity = cvss.base_severity.as_deref().unwrap_or("-");
            let vector = cvss.vector_string.as_deref().unwrap_or("");
            Line::from(format!(
                "{} {} {} {}",
                cvss.version, score, severity, vector
            ))
        }));
    }
    lines.push(Line::from(""));
    if detail.affected.is_empty() {
        lines.push(Line::from("No affected component"));
    } else {
        lines.extend(detail.affected.iter().map(|affected| {
            let vendor = affected.vendor.as_deref().unwrap_or("-");
            let product = affected.product.as_deref().unwrap_or("-");
            let package = affected.package_name.as_deref().unwrap_or("-");
            let status = affected.default_status.as_deref().unwrap_or("-");
            let collection = affected.collection_url.as_deref().unwrap_or("");
            let suffix = if collection.is_empty() {
                String::new()
            } else {
                format!(" {}", collection)
            };
            Line::from(format!(
                "{vendor}/{product} pkg:{package} status:{status}{suffix}"
            ))
        }));
    }
    lines
}
