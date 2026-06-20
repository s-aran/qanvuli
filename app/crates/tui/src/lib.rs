mod app;
mod common;
mod db;
mod display;
mod form;
mod mode;
mod modes;
mod terminal;
mod traits;
mod tui;
mod ui;
mod utils;

pub use tui::{Args, run};

const TUI_LIMIT: u64 = 30;
const TUI_LOAD_MORE_LIMIT: u64 = 30;
const EVENT_POLL_MAX: std::time::Duration = std::time::Duration::from_millis(50);
const SEARCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
