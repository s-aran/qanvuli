mod app;
mod display;
mod form;
mod mode;
mod search;
mod terminal;
mod tui;
mod ui;

pub use tui::{Args, run};

const TUI_LIMIT: u64 = 30;
const TUI_LOAD_MORE_LIMIT: u64 = 30;
const EVENT_POLL_MAX: std::time::Duration = std::time::Duration::from_millis(50);
