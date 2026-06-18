use super::{
    app::{App, MaintenanceChoice, PaneFocus, TimeoutChoice},
    display::{DisplayField, DisplaySettings, TimeZone},
    form::{AdvancedField, AdvancedForm, StateScopeUi},
};
use chrono::{DateTime, FixedOffset};
use qanvuli_db::{CveAffectedDetail, CveDetail, CveSummaryWithDetail, cve_state_label};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(main[0]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(chunks[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(68), Constraint::Min(4)])
        .split(chunks[1]);
    app.set_page_sizes(
        left[1].height.saturating_sub(2) as usize,
        right[0].height.saturating_sub(2) as usize,
    );

    let input_title = if app.searching() {
        format!(
            "Search [{}] - searching {}",
            app.search_mode.footer_text(),
            app.spinner()
        )
    } else {
        format!(
            "Search [{}] - limit {}",
            app.search_mode.footer_text(),
            app.limit
        )
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
                Line::from(Span::raw(cve.summary.cve_id.clone())),
                Line::from(Span::raw(cve.summary.title.clone())),
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

    let footer = Paragraph::new(main_footer(app)).style(
        Style::default()
            .fg(app.search_mode.color())
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(footer, main[1]);

    let detail = app
        .selected()
        .map(|cve| detail_lines(cve, app.display.timezone))
        .unwrap_or_else(|| vec![Line::from("No results")]);
    app.clamp_detail_scroll_to_lines(detail.len());
    let detail_title = app
        .selected()
        .map(|cve| {
            format!(
                "{} [{}]",
                cve.summary.cve_id,
                cve_state_label(cve.summary.state)
            )
        })
        .unwrap_or_else(|| "CVE".to_owned());
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

    let metadata = Paragraph::new(metadata_lines(app.selected().map(|cve| &cve.detail)))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(metadata, right[1]);

    if app.show_help {
        draw_help(frame);
    }
    if app.show_advanced {
        draw_advanced(frame, app);
    }
    if app.show_display {
        draw_display(frame, app);
    }
    if app.show_timeout_prompt {
        draw_timeout_prompt(frame, app);
    }
    if app.show_maintenance {
        draw_maintenance(frame, app);
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
        Line::from("F4     Open display settings"),
        Line::from("F5     Open database maintenance"),
        Line::from("Shift+Tab Switch search mode"),
        Line::from("Left/Right Switch pane focus"),
        Line::from("Up/Down Move focused pane"),
        Line::from("Ctrl-U/D Half-page up/down focused pane"),
        Line::from("Ctrl-B/F Full-page up/down focused pane"),
        Line::from("F1     Show this help"),
        Line::from("Esc    Close this help"),
        Line::from("Ctrl-L Reset screen and popup settings"),
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
        Line::from(""),
        Line::from(
            "Enter search  Esc close  Tab/Down next  Shift+Tab/Up previous  Left/Right mode/state",
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

fn draw_display(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(56, 34, frame.area());
    let display = &app.display;
    let lines = vec![
        display_line(
            display,
            DisplayField::SortField,
            "Sort item",
            display.sort_field.label(),
        ),
        display_line(
            display,
            DisplayField::SortDirection,
            "Sort direction",
            display.sort_direction.label(),
        ),
        display_line(
            display,
            DisplayField::TimeZone,
            "Timezone",
            display.timezone.label(),
        ),
        Line::from(""),
        Line::from("Enter/Esc close  Tab/Down next  Shift+Tab/Up previous  Left/Right change"),
    ];
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Display Settings")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn draw_timeout_prompt(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(56, 26, frame.area());
    let continue_style = choice_style(app.timeout_choice == TimeoutChoice::Continue);
    let cancel_style = choice_style(app.timeout_choice == TimeoutChoice::Cancel);
    let lines = vec![
        Line::from("Search is taking longer than expected."),
        Line::from("Continue waiting or cancel the running search?"),
        Line::from(""),
        Line::from(vec![
            Span::styled("[ Continue ]", continue_style),
            Span::raw("  "),
            Span::styled("[ Cancel ]", cancel_style),
        ]),
        Line::from(""),
        Line::from("Enter confirm  Left/Right choose  Esc cancel"),
    ];
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!("Search Timeout ({})", app.detail_status()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn draw_maintenance(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(56, 28, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Database Maintenance")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    if app.maintenance_running() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(4),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner);
        let progress = app.maintenance_progress.as_ref();
        let total = progress.map(|progress| progress.total_files).unwrap_or(0);
        let written = progress.map(|progress| progress.written_files).unwrap_or(0);
        let failed = progress.map(|progress| progress.failed_files).unwrap_or(0);
        let phase = progress
            .map(|progress| progress.phase.as_str())
            .unwrap_or("starting");
        let label = progress
            .map(|progress| progress.label.as_str())
            .unwrap_or("maintenance");
        let asset = progress
            .map(|progress| progress.asset.as_str())
            .filter(|asset| !asset.is_empty())
            .unwrap_or("-");
        let lines = vec![
            Line::from(format!("{label}: {phase}")),
            Line::from(format!("asset: {asset}")),
            Line::from(format!("written: {written}/{total}  failed: {failed}")),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[0]);
        let ratio = progress_ratio(written, total);
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Magenta))
            .ratio(ratio)
            .label(format!("{:.0}%", ratio * 100.0));
        frame.render_widget(gauge, chunks[1]);
        return;
    }

    let lines = vec![
        Line::from("Select a database maintenance operation."),
        Line::from(""),
        maintenance_line(app, MaintenanceChoice::Init, "Initialize"),
        maintenance_line(app, MaintenanceChoice::Update, "Update"),
        maintenance_line(app, MaintenanceChoice::Cancel, "Cancel"),
        Line::from(""),
        Line::from("Enter run  Esc close  Up/Down choose  I/U/C choose"),
    ];
    let popup = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(popup, area);
}

fn choice_style(active: bool) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
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

fn display_line(
    display: &DisplaySettings,
    field: DisplayField,
    label: &'static str,
    value: &str,
) -> Line<'static> {
    let active = display.active_field == field;
    let marker = if active { "> " } else { "  " };
    let style = if active {
        Style::default()
            .fg(Color::Cyan)
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

fn maintenance_line(app: &App, choice: MaintenanceChoice, label: &'static str) -> Line<'static> {
    let active = app.maintenance_choice == choice;
    let marker = if active { "(*) " } else { "( ) " };
    let style = if active {
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(marker, style),
        Span::styled(label.to_owned(), style),
    ])
}

fn progress_ratio(written: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (written as f64 / total as f64).clamp(0.0, 1.0)
    }
}

fn main_footer(app: &App) -> String {
    let status = app
        .maintenance_status()
        .or(app.status_message.as_deref())
        .unwrap_or_else(|| app.detail_status());
    let db_as_of = app.db_as_of.as_deref().unwrap_or("-");
    format!(
        "{} | {} {} | {} | DB: {} | {}",
        app.state_scope.label(),
        app.display.sort_field.label(),
        app.display.sort_direction.label(),
        app.display.timezone.label(),
        db_as_of,
        status
    )
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

fn detail_lines(cve: &CveSummaryWithDetail, timezone: TimeZone) -> Vec<Line<'static>> {
    let summary = &cve.summary;
    vec![
        Line::from(Span::styled(
            product_vendor_summary(&cve.detail.affected),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(vec![
            Span::styled("Published: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_timestamp(&summary.published_at, timezone)),
        ]),
        Line::from(vec![
            Span::styled("Updated: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_timestamp(&summary.updated_at, timezone)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            summary.title.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(summary.description_en.clone().unwrap_or_default()),
    ]
}

fn product_vendor_summary(affected: &[CveAffectedDetail]) -> String {
    let mut values = Vec::new();
    for affected in affected {
        let vendor = affected.vendor.as_deref().unwrap_or("-");
        let product = affected.product.as_deref().unwrap_or("-");
        let value = format!("{product} / {vendor}");
        if !values.contains(&value) {
            values.push(value);
        }
        if values.len() >= 3 {
            break;
        }
    }
    if values.is_empty() {
        "-".to_owned()
    } else {
        let suffix = if affected.len() > values.len() {
            " ..."
        } else {
            ""
        };
        format!("{}{suffix}", values.join(", "))
    }
}

fn format_timestamp(value: &str, timezone: TimeZone) -> String {
    let Ok(datetime) = DateTime::parse_from_rfc3339(value) else {
        return value.to_owned();
    };
    let Some(offset) = timezone_offset(timezone) else {
        return value.to_owned();
    };
    datetime
        .with_timezone(&offset)
        .format("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

fn timezone_offset(timezone: TimeZone) -> Option<FixedOffset> {
    match timezone {
        TimeZone::Utc => FixedOffset::east_opt(0),
        TimeZone::Jst => FixedOffset::east_opt(9 * 60 * 60),
        TimeZone::Pst => FixedOffset::west_opt(8 * 60 * 60),
    }
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
