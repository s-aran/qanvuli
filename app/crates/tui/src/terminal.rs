use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, path::PathBuf};

pub(super) struct TuiLogGuard {
    _guard: qanvuli_utils::logging::LogFileGuard,
    pub(super) path: PathBuf,
}

impl TuiLogGuard {
    pub(super) fn redirect() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("qanvuli-tui-{}.log", std::process::id()));
        let guard = qanvuli_utils::logging::redirect_to_file(&path)
            .map_err(|err| format!("failed to redirect TUI logs to {}: {err}", path.display()))?;
        Ok(Self {
            _guard: guard,
            path,
        })
    }
}

pub(super) struct TerminalGuard {
    pub(super) terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalGuard {
    pub(super) fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|err| format!("failed to enable raw mode: {err}"))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)
            .map_err(|err| format!("failed to enter alternate screen: {err}"))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal =
            Terminal::new(backend).map_err(|err| format!("failed to init TUI: {err}"))?;
        Ok(Self {
            terminal,
            active: true,
        })
    }

    pub(super) fn leave(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        disable_raw_mode().map_err(|err| format!("failed to disable raw mode: {err}"))?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)
            .map_err(|err| format!("failed to leave alternate screen: {err}"))?;
        self.terminal
            .show_cursor()
            .map_err(|err| format!("failed to show cursor: {err}"))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}
