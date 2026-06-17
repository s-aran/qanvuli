use std::{
    fs::File,
    io::{Read, Seek},
    path::PathBuf,
};

use anyhow::Error;
use glob::{MatchOptions, glob_with};
use regex::Regex;

pub trait FileStorageTrait {
    fn get_json_bytes(&mut self, path: impl Into<String>) -> Result<Vec<u8>, Error>;

    fn get_json(&mut self, path: impl Into<String>) -> Result<String, Error> {
        let bytes = self.get_json_bytes(path)?;
        Ok(String::from_utf8(bytes)?)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String>;
}

pub struct ActualStorage {
    base: PathBuf,
}

impl ActualStorage {
    pub fn new(path: PathBuf) -> Self {
        Self { base: path }
    }
}

impl FileStorageTrait for ActualStorage {
    fn get_json_bytes(&mut self, path: impl Into<String>) -> Result<Vec<u8>, Error> {
        // TODO: error handling
        let p = PathBuf::from(path.into());
        let mut file = File::open(p).expect("maybe not found");
        let mut buf = Vec::new();
        let _ = file.read_to_end(&mut buf);

        Ok(buf)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String> {
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/**/CVE-*.json", self.base.to_string_lossy().to_string());
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        files.map(|e| e.unwrap().to_string_lossy().to_owned().to_string())
    }
}

trait ReadSeek: Read + Seek + Send {}

impl<T> ReadSeek for T where T: Read + Seek + Send {}

pub struct ZipStorage {
    stream: zip::ZipArchive<Box<dyn ReadSeek>>,
}

impl ZipStorage {
    pub fn new(filename: impl Into<String>) -> Self {
        // TODO: error handling
        let filename = filename.into();
        let file = std::fs::File::open(&filename).unwrap();
        let reader = std::io::BufReader::new(file);
        let mut stream = zip::ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>).unwrap();
        if stream.len() == 1 {
            let name = stream.by_index(0).unwrap().name().to_owned();
            if name.ends_with(".zip") && !archive_has_cve_json(&stream) {
                let inner_filename = format!("{filename}.inner.zip");
                if std::fs::metadata(&inner_filename).is_err() {
                    eprintln!("extracting nested zip: {name} -> {inner_filename}");
                    let mut extracted = std::fs::File::create(&inner_filename).unwrap();
                    let mut entry = stream.by_index(0).unwrap();
                    std::io::copy(&mut entry, &mut extracted).unwrap();
                }

                let file = std::fs::File::open(inner_filename).unwrap();
                let reader = std::io::BufReader::new(file);
                let inner = zip::ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>).unwrap();
                return Self { stream: inner };
            }
        }

        Self { stream }
    }
}

impl FileStorageTrait for ZipStorage {
    fn get_json_bytes(&mut self, path: impl Into<String>) -> Result<Vec<u8>, Error> {
        // TODO: error handling
        let mut f = self.stream.by_name(path.into().as_str()).unwrap();
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);

        Ok(buf)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String> {
        let re = cve_json_regex();
        self.stream
            .file_names()
            .filter(move |e| {
                if let Some(r) = re.find(e) {
                    !r.is_empty()
                } else {
                    false
                }
            })
            .map(|e| e.to_owned())
    }
}

fn archive_has_cve_json(stream: &zip::ZipArchive<Box<dyn ReadSeek>>) -> bool {
    let re = cve_json_regex();
    stream.file_names().any(|name| re.is_match(name))
}

fn cve_json_regex() -> Regex {
    Regex::new(r"(^|.*/)CVE-[0-9]{4}-[0-9]+\.json$").unwrap()
}

#[cfg(test)]
mod tests {
    // use qanvuli_models::cve::base::cve_metadata::CveState;
    // use qanvuli_models::cve::base::root::CveRoot;
    // use qanvuli_models::cve::published::root::CveRoot as PublishedCveRoot;
    // use qanvuli_models::cve::rejected::root::CveRoot as RejectedCveRoot;

    // use super::*;

    // #[test]
    // fn test_zipfile() {
    //     const FILENAME: &str = "2025-12-14_all_CVEs_at_midnight.zip";
    //     const INNER_FILENAME: &str = "cve.zip";

    //     let file = std::fs::File::open(FILENAME).unwrap();
    //     let outer_reader = std::io::BufReader::new(file);
    //     let mut outer_archive = zip::ZipArchive::new(outer_reader).unwrap();

    //     if outer_archive.len() != 1 {
    //         panic!("no cve list zip");
    //     }

    //     let mut extracted = std::fs::File::create(INNER_FILENAME).unwrap();
    //     std::io::copy(&mut outer_archive.by_index(0).unwrap(), &mut extracted).unwrap();

    //     let mut storage = ZipStorage::new(INNER_FILENAME);
    //     let files = storage.enum_json_list().collect::<Vec<String>>();
    //     for f in files.iter() {
    //         assert!(storage.load_cve_json(f).is_ok());
    //     }

    //     assert!(files.len() > 0);

    //     // for i in 0..inner_archive.len() {
    //     //     let content = inner_archive.by_index(i).unwrap();
    //     //     let path = match content.enclosed_name() {
    //     //         Some(p) => p,
    //     //         None => {
    //     //             println!("path is none, {}", content.name());
    //     //             continue;
    //     //         }
    //     //     };

    //     //     if content.is_dir() {
    //     //         // println!("{}/", path.to_string_lossy());
    //     //         continue;
    //     //     } else {
    //     //         println!("{}", path.to_string_lossy());
    //     //     }
    //     // }
    // }

    // #[test]
    // fn test_json() {
    //     const DIR: &str = "deltaCves";
    //     let mut glob_options = MatchOptions::new();
    //     glob_options.case_sensitive = false;

    //     let base_path = format!("{}/*.json", DIR);
    //     let files = glob_with(base_path.as_str(), glob_options).unwrap();

    //     for path in files {
    //         let p = path.unwrap().to_string_lossy().to_string();
    //         println!("{}", p);
    //         let mut file = File::open(p).expect("maybe not found");
    //         let mut buf = String::new();
    //         let _ = file.read_to_string(&mut buf);

    //         let _: qanvuli_models::cve::published::root::CveRoot =
    //             serde_json::from_str(&buf).unwrap();
    //     }
    // }

    // #[test]
    // fn test_json_2() {
    //     let mut storage = ActualStorage::new(PathBuf::from("deltaCves"));
    //     let files = storage.enum_json_list().collect::<Vec<String>>();
    //     for p in files.iter() {
    //         println!("{}", p);
    //         assert!(storage.load_cve_json(p).is_ok());
    //     }

    //     assert!(files.len() > 0);
    // }
}
