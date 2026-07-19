macro_rules! println {
    ($($arg:tt)*) => {
        qanvuli_utils::logging::stdout(format_args!($($arg)*))
    };
}

macro_rules! eprintln {
    ($($arg:tt)*) => {
        qanvuli_utils::logging::stderr(format_args!($($arg)*))
    };
}

pub mod common;
pub mod cwe;
pub mod db;
pub mod download_cve;
pub mod graph;
pub mod init;
pub mod query;
pub mod sbom;
pub mod search;
pub mod update;
