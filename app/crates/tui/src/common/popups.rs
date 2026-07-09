use crate::{
    app::{App, MaintenanceChoice, TimeoutChoice},
    common::{
        centered_rect,
        components::{ActionButton, ButtonRow, Checkbox, RadioOption, SelectableField},
    },
    display::{DisplayField, DisplaySettings},
    form::{AdvancedField, AdvancedForm, StateScopeUi},
    traits::component::LineComponent,
    utils::text::progress_ratio,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Gauge, Paragraph, Wrap},
};

pub(crate) fn draw_help(frame: &mut ratatui::Frame<'_>) {
    let area = centered_rect(60, 42, frame.area());
    let help = Paragraph::new(vec![
        Line::from("Enter  Search current input"),
        Line::from("Tab    Next pane focus"),
        Line::from("Shift+Tab Previous pane focus"),
        Line::from("F2     Switch search mode"),
        Line::from("Left/Right Switch search mode"),
        Line::from("F3     Open advanced search"),
        Line::from("F4     Open display settings"),
        Line::from("F5     Open database maintenance"),
        Line::from("F8     Toggle raw CVE JSON"),
        Line::from("F9     Toggle CWE list"),
        Line::from("/      Search visible detail with regex"),
        Line::from("F4     Open CWE status filter in CWE mode"),
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

pub(crate) fn draw_advanced(frame: &mut ratatui::Frame<'_>, app: &App) {
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
        advanced_checkbox(
            form,
            AdvancedField::ProductExact,
            "Product exact match",
            form.product_exact,
        ),
        advanced_line(form, AdvancedField::Vendor, "Vendor", &form.vendor),
        advanced_checkbox(
            form,
            AdvancedField::VendorExact,
            "Vendor exact match",
            form.vendor_exact,
        ),
        advanced_line(
            form,
            AdvancedField::StateScope,
            "State",
            form.state_scope.label(),
        ),
        Line::from(""),
        Line::from(
            "Enter search  Esc close  Space toggle exact  Tab/Down next  Shift+Tab/Up previous",
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

pub(crate) fn draw_display(frame: &mut ratatui::Frame<'_>, app: &App) {
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

pub(crate) fn draw_timeout_prompt(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(56, 26, frame.area());
    let lines = vec![
        Line::from("Search is taking longer than expected."),
        Line::from("Continue waiting or cancel the running search?"),
        Line::from(""),
        ButtonRow {
            buttons: vec![
                ActionButton {
                    label: "Continue",
                    active: app.timeout_choice == TimeoutChoice::Continue,
                },
                ActionButton {
                    label: "Cancel",
                    active: app.timeout_choice == TimeoutChoice::Cancel,
                },
            ],
        }
        .line(),
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

pub(crate) fn draw_maintenance(frame: &mut ratatui::Frame<'_>, app: &App) {
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
        RadioOption {
            label: "Initialize",
            selected: app.maintenance_choice == MaintenanceChoice::Init,
            active_color: Color::Magenta,
        }
        .line(),
        RadioOption {
            label: "Update",
            selected: app.maintenance_choice == MaintenanceChoice::Update,
            active_color: Color::Magenta,
        }
        .line(),
        RadioOption {
            label: "Cancel",
            selected: app.maintenance_choice == MaintenanceChoice::Cancel,
            active_color: Color::Magenta,
        }
        .line(),
        Line::from(""),
        Checkbox {
            label: "Keep downloaded zip files".to_owned(),
            checked: app.maintenance_keep_downloads,
            active: false,
            active_color: Color::Magenta,
        }
        .line(),
        Line::from(""),
        Line::from("Enter run  Space/K keep  Esc close  Up/Down choose  I/U/C choose"),
    ];
    let popup = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    frame.render_widget(popup, area);
}

fn advanced_line(
    form: &AdvancedForm,
    field: AdvancedField,
    label: &'static str,
    value: &str,
) -> Line<'static> {
    SelectableField {
        label,
        value: value.to_owned(),
        active: form.active_field == field,
        active_color: Color::Yellow,
    }
    .line()
}

fn advanced_checkbox(
    form: &AdvancedForm,
    field: AdvancedField,
    label: &'static str,
    checked: bool,
) -> Line<'static> {
    Checkbox {
        label: label.to_owned(),
        checked,
        active: form.active_field == field,
        active_color: Color::Yellow,
    }
    .line()
}

fn display_line(
    display: &DisplaySettings,
    field: DisplayField,
    label: &'static str,
    value: &str,
) -> Line<'static> {
    SelectableField {
        label,
        value: value.to_owned(),
        active: display.active_field == field,
        active_color: Color::Cyan,
    }
    .line()
}
