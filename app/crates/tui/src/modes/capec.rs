pub(crate) mod handler;

use crate::{
    app::{App, PaneFocus},
    common::{DetailSearch, focus_style, highlighted_line},
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

pub(crate) fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App, search: &DetailSearch) {
    let main = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());
    let body =
        Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)]).split(main[1]);

    frame.render_widget(
        Paragraph::new(format!(
            "{}{}",
            app.capec.query,
            if app.main.focus == PaneFocus::Left {
                "▏"
            } else {
                ""
            }
        ))
        .block(
            Block::default()
                .title(format!(
                    "CAPEC Search [Status: {} Type: {} CWE: {}]",
                    shown(&app.capec.status_filter),
                    shown(&app.capec.type_filter),
                    shown(&app.capec.cwe_filter)
                ))
                .borders(Borders::ALL),
        ),
        main[0],
    );
    draw_list(frame, app, body[0]);
    draw_detail(frame, app, search, body[1]);
    frame.render_widget(
        Paragraph::new(
            "Esc/F10 Close  F1/? Help  F4 Filters  ← Parent  → Return  [ ] Siblings  Tab Pane  / Find",
        ),
        main[2],
    );
    if app.capec.show_filter {
        draw_filter(frame, app);
    }
    if app.capec.show_taxonomy {
        draw_taxonomy(frame, app);
    }
}

fn draw_list(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let block = Block::default()
        .title(format!("CAPEC ({})", app.capec.results.len()))
        .borders(Borders::ALL)
        .border_style(focus_style(app.main.focus == PaneFocus::Left));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let start = (app.capec.scroll as usize).min(app.capec.results.len());
    let lines = app
        .capec
        .results
        .iter()
        .skip(start)
        .take(inner.height as usize)
        .enumerate()
        .map(|(offset, capec)| {
            let style = if start + offset == app.capec.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            // A multi-parent attack pattern has one row per display path.
            let branch = app
                .capec
                .tree_prefixes
                .get(start + offset)
                .map(String::as_str)
                .unwrap_or("");
            Line::from(Span::styled(
                format!(
                    "{branch}CAPEC-{} [{}] {}",
                    capec.id, capec.status, capec.name
                ),
                style,
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(if lines.is_empty() {
            vec![Line::from("No CAPEC")]
        } else {
            lines
        }),
        inner,
    );
}

fn draw_detail(frame: &mut ratatui::Frame<'_>, app: &App, search: &DetailSearch, area: Rect) {
    let lines = app.selected_capec().map_or_else(
        || vec![Line::from("No CAPEC selected")],
        |capec| {
            let mut lines = vec![
                highlighted_line(&format!("CAPEC-{} {}", capec.id, capec.name), search),
                highlighted_line(
                    &format!("Status: {}  Type: {}", capec.status, capec.abstraction),
                    search,
                ),
                highlighted_line(&format!("Parents: {}", join_ids(&capec.parent_ids)), search),
                highlighted_line(&format!("CWE: {}", join_ids(&capec.cwe_ids)), search),
                highlighted_line(
                    &format!("Categories: {}", join_ids(&capec.category_ids)),
                    search,
                ),
                highlighted_line(&format!("Views: {}", join_ids(&capec.view_ids)), search),
                Line::from(""),
            ];
            lines.extend(
                capec
                    .description
                    .lines()
                    .map(|line| highlighted_line(line, search)),
            );
            if let Some(extended) = capec.extended_description.as_deref() {
                lines.push(Line::from(""));
                lines.extend(extended.lines().map(|line| highlighted_line(line, search)));
            }
            if let Some(detail) = app
                .capec
                .taxonomy
                .as_ref()
                .filter(|detail| detail.entry.id == capec.id)
            {
                lines.push(Line::from(""));
                lines.push(highlighted_line("Sources", search));
                if detail.references.is_empty() {
                    lines.push(Line::from("  none"));
                }
                lines.extend(detail.references.iter().map(|reference| {
                    highlighted_line(
                        &format!(
                            "  {} {} {}",
                            reference.reference_id,
                            reference.title,
                            reference.url.as_deref().unwrap_or("")
                        ),
                        search,
                    )
                }));
            }
            lines
        },
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("CAPEC detail")
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.main.focus == PaneFocus::Right)),
            )
            .scroll((app.capec.detail_scroll, 0))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_filter(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered(60, 9, frame.area());
    frame.render_widget(Clear, area);
    let values = [
        ("Status", &app.capec.status_filter),
        ("Type", &app.capec.type_filter),
        ("CWE ID", &app.capec.cwe_filter),
    ];
    let lines = values
        .iter()
        .enumerate()
        .map(|(index, (label, value))| {
            Line::from(Span::styled(
                format!("{label}: {value}"),
                if index == app.capec.filter_field {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            ))
        })
        .chain([Line::from("Enter Apply  Esc Cancel")])
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("CAPEC Filters")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_taxonomy(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered(
        frame.area().width.saturating_mul(80) / 100,
        frame.area().height.saturating_mul(80) / 100,
        frame.area(),
    );
    frame.render_widget(Clear, area);
    let tab = ["Category", "View"][app.capec.taxonomy_tab];
    let section = ["Overview", "Members", "Sources", "History"][app.capec.taxonomy_section];
    let mut lines = vec![Line::from(format!(
        "{tab} | {section}   Tab switch classification   ←/→ switch section"
    ))];
    lines.push(Line::from(""));
    if let Some(detail) = &app.capec.taxonomy {
        if app.capec.taxonomy_tab == 0 {
            if let Some(category) = detail.categories.get(app.capec.taxonomy_selected) {
                lines.push(Line::from(format!(
                    "Category-{} [{}] {}",
                    category.category.id, category.category.status, category.category.name
                )));
                append_category_section(&mut lines, category, app.capec.taxonomy_section);
            } else {
                lines.push(Line::from("No related Category"));
            }
        } else if let Some(view) = detail.views.get(app.capec.taxonomy_selected) {
            lines.push(Line::from(format!(
                "View-{} [{}] {}",
                view.view.id, view.view.status, view.view.name
            )));
            append_view_section(&mut lines, view, app.capec.taxonomy_section);
        } else {
            lines.push(Line::from("No related View"));
        }
    } else {
        lines.push(Line::from("Loading classification detail"));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "↑/↓ select  PgUp/PgDn or Ctrl+U/Ctrl+D scroll  Esc close",
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("CAPEC Classification")
                    .borders(Borders::ALL),
            )
            .scroll((app.capec.taxonomy_scroll, 0))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn append_category_section(
    lines: &mut Vec<Line<'static>>,
    detail: &qanvuli_core::database::CapecCategoryDetail,
    section: usize,
) {
    match section {
        0 => {
            lines.push(Line::from(detail.category.summary.clone()));
            for note in &detail.notes {
                lines.push(Line::from(format!(
                    "{}: {}",
                    note.note_type, note.note_text
                )));
            }
            for mapping in &detail.taxonomy_mappings {
                lines.push(Line::from(format!(
                    "{}: {} {}",
                    mapping.taxonomy,
                    mapping.entry_id.as_deref().unwrap_or("-"),
                    mapping.entry_name.as_deref().unwrap_or("")
                )));
            }
        }
        1 => lines.push(Line::from(format!(
            "CAPEC members: {}",
            join_ids(&detail.member_ids)
        ))),
        2 => append_references(lines, &detail.references),
        _ => append_history(lines, &detail.history),
    }
}

fn append_view_section(
    lines: &mut Vec<Line<'static>>,
    detail: &qanvuli_core::database::CapecViewDetail,
    section: usize,
) {
    match section {
        0 => {
            lines.push(Line::from(format!("Type: {}", detail.view.view_type)));
            lines.push(Line::from(detail.view.objective.clone()));
            if let Some(filter) = &detail.view.filter {
                lines.push(Line::from(format!("Filter: {filter}")));
            }
            for note in &detail.notes {
                lines.push(Line::from(format!(
                    "{}: {}",
                    note.note_type, note.note_text
                )));
            }
        }
        1 => {
            lines.push(Line::from(format!(
                "Categories: {}",
                join_ids(&detail.category_ids)
            )));
            lines.push(Line::from(format!(
                "CAPEC members: {}",
                join_ids(&detail.capec_ids)
            )));
        }
        2 => append_references(lines, &detail.references),
        _ => append_history(lines, &detail.history),
    }
}

fn append_references(
    lines: &mut Vec<Line<'static>>,
    references: &[qanvuli_core::database::CapecReference],
) {
    if references.is_empty() {
        lines.push(Line::from("No sources"));
    }
    for reference in references {
        lines.push(Line::from(format!(
            "{} {} {}",
            reference.reference_id,
            reference.title,
            reference.url.as_deref().unwrap_or("")
        )));
    }
}

fn append_history(
    lines: &mut Vec<Line<'static>>,
    history: &[qanvuli_core::database::CapecHistory],
) {
    if history.is_empty() {
        lines.push(Line::from("No history"));
    }
    for event in history {
        lines.push(Line::from(format!(
            "{} {} {}",
            event.event_date,
            event.event_type,
            event.comment.as_deref().unwrap_or("")
        )));
    }
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    )
}

fn join_ids(ids: &[i32]) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn shown(value: &str) -> &str {
    if value.is_empty() { "*" } else { value }
}
