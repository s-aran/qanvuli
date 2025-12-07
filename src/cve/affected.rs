use serde::Deserialize;
use strum::{AsRefStr, EnumString};

use crate::cve::{cve_metadata::CveMetadata, program_routine::ProgramRoutine, version::Version};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum DefaultStatus {
    #[strum(serialize = "affected")]
    Affected,
    #[strum(serialize = "unaffected")]
    UnAffected,
    #[strum(serialize = "unknown")]
    Unknown,
}

#[derive(Debug, Deserialize)]
pub struct Affected {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub collection_url: Option<String>,
    pub package_name: Option<String>,
    pub cpes: Vec<String>,
    pub modules: Vec<String>,
    pub program_files: Vec<String>,
    pub program_routines: Vec<ProgramRoutine>,
    pub platforms: Vec<String>,
    pub repo: Option<String>,
    pub default_status: Option<DefaultStatus>,
    pub versions: Vec<Version>,
}
