use serde::Deserialize;
use serde_json::Value;
use strum::{AsRefStr, EnumString};

use crate::cve::published::{program_routine::ProgramRoutine, version::Version};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "lowercase")]
pub enum DefaultStatus {
    #[strum(serialize = "affected")]
    Affected,
    #[strum(serialize = "unaffected")]
    UnAffected,
    #[strum(serialize = "unknown")]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Affected {
    pub vendor: Option<String>,
    pub product: Option<Value>,
    pub collection_url: Option<String>,
    pub package_name: Option<String>,
    pub cpes: Option<Vec<String>>,
    pub modules: Option<Vec<String>>,
    pub program_files: Option<Vec<String>>,
    pub program_routines: Option<Vec<ProgramRoutine>>,
    pub platforms: Option<Vec<String>>,
    pub repo: Option<String>,
    pub default_status: Option<DefaultStatus>,
    pub versions: Option<Vec<Version>>,
}
