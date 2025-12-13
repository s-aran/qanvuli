mod cve;
mod datetime_deserialize;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use crate::cve::base::cve_metadata::CveState;
    use crate::cve::base::root::CveRoot;
    use crate::cve::published::root::CveRoot as PublishedCveRoot;
    use crate::cve::rejected::root::CveRoot as RejectedCveRoot;

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

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
