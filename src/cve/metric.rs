use serde::Deserialize;

use crate::cve::{
    cvss_v2_0::CvssV2_0, cvss_v3_0::CvssV3_0, cvss_v3_1::CvssV3_1, cvss_v4_0::CvssV4_0,
    other::Other, scenario::Scenario,
};

#[derive(Debug, Deserialize)]
pub struct Metric {
    pub format: String,
    pub scenarios: Vec<Scenario>,
    pub cvss_v4_0: Option<CvssV4_0>,
    pub cvss_v3_1: Option<CvssV3_1>,
    pub cvss_v3_0: Option<CvssV3_0>,
    pub cvss_v2_0: Option<CvssV2_0>,
    pub other: Option<Other>,
}
