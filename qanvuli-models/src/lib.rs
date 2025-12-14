pub mod cve;

use anyhow::{Error, Result, anyhow};
use cve::{
    base::{cve_metadata::CveState, root::CveRoot},
    published::root::CveRoot as PublishedCveRoot,
    rejected::root::CveRoot as RejectedCveRoot,
};
use qanvuli_utils::datetime_deserialize;

#[derive(Debug)]
pub enum CveStatusData {
    Published(PublishedCveRoot),
    Rejected(RejectedCveRoot),
}

pub fn parse_json(src: impl Into<String>) -> Result<CveStatusData, Error> {
    let buf = src.into();
    let cve: CveRoot = serde_json::from_str(&buf).unwrap();
    match cve.cve_metadata.state {
        CveState::Published => {
            let deserialized = match serde_json::from_str::<PublishedCveRoot>(&buf) {
                Ok(r) => r,
                Err(e) => return Err(anyhow!(e)),
            };
            Ok(CveStatusData::Published(deserialized))
        }
        CveState::Rejected => {
            let deserialized = match serde_json::from_str::<RejectedCveRoot>(&buf) {
                Ok(r) => r,
                Err(e) => return Err(anyhow!(e)),
            };
            Ok(CveStatusData::Rejected(deserialized))
        }
        CveState::Reserved => panic!("unexpected reserved state."),
    }
}

#[cfg(test)]
mod tests {
    use crate::cve::base::cve_metadata::CveState;
    use crate::cve::base::root::CveRoot;
    use crate::cve::published::root::CveRoot as PublishedCveRoot;
    use crate::cve::rejected::root::CveRoot as RejectedCveRoot;

    use super::*;

    use glob::MatchOptions;
    use glob::glob_with;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_json() {
        const DIR: &str = "deltaCves";
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/*.json", DIR);
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        for path in files {
            let p = path.unwrap().to_string_lossy().to_string();
            println!("{}", p);
            let mut file = File::open(p).expect("maybe not found");
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf);

            let _: cve::published::root::CveRoot = serde_json::from_str(&buf).unwrap();
        }
    }

    #[test]
    fn test_json_2() {
        const DIR: &str = "cves";
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/**/CVE-*.json", DIR);
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        for path in files {
            let p = path.unwrap().to_string_lossy().to_string();
            println!("{}", p);
            let mut file = File::open(p).expect("maybe not found");
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf);

            let cve: CveRoot = serde_json::from_str(&buf).unwrap();
            match cve.cve_metadata.state {
                CveState::Published => {
                    let _ = serde_json::from_str::<PublishedCveRoot>(&buf).unwrap();
                }
                CveState::Rejected => {
                    let _ = serde_json::from_str::<RejectedCveRoot>(&buf).unwrap();
                }
                CveState::Reserved => assert!(false),
            }
        }
    }
}
