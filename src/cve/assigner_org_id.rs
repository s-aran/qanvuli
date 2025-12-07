use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CveState {
    #[strum(serialize = "RESERVED")]
    Reserved,
    #[strum(serialize = "PUBLISHED")]
    PUBLISHED,
    #[strum(serialize = "REJECTED")]
    REJECTED,
}

#[derive(Debug, Deserialize)]
pub struct AssignerOrgId {
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    pub date_updated: Option<DateTime<FixedOffset>>,
    pub serial: Option<usize>,
    pub date_reserved: Option<DateTime<FixedOffset>>,
    pub state: CveState,
}
