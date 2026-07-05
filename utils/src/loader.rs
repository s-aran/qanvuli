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

    fn get_json_entry_bytes(&mut self, entry: &JsonEntry) -> Result<Vec<u8>, Error> {
        self.get_json_bytes(entry.path.clone())
    }

    fn get_json(&mut self, path: impl Into<String>) -> Result<String, Error> {
        let bytes = self.get_json_bytes(path)?;
        Ok(String::from_utf8(bytes)?)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String>;

    fn enum_json_entries(&self) -> Vec<JsonEntry> {
        self.enum_json_list()
            .map(|path| JsonEntry {
                path,
                index: None,
                filesystem_path: None,
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct JsonEntry {
    pub path: String,
    pub index: Option<usize>,
    pub filesystem_path: Option<PathBuf>,
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

        let base_path = format!("{}/**/CVE-*.json", self.base.to_string_lossy());
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        files.map(|e| e.unwrap().to_string_lossy().into_owned())
    }
}

trait ReadSeek: Read + Seek + Send {}

impl<T> ReadSeek for T where T: Read + Seek + Send {}

const ZIP_EXTRACTION_EXPANSION_FACTOR: u64 = 8;
const ZIP_EXTRACTION_FREE_SPACE_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

pub struct ZipStorage {
    stream: Option<zip::ZipArchive<Box<dyn ReadSeek>>>,
    extracted_dir: Option<PathBuf>,
    extracted_entries: Vec<JsonEntry>,
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
                let (extracted_dir, inner) = extract_nested_cve_zip(&mut stream, &name);
                return Self {
                    stream: Some(inner),
                    extracted_dir: Some(extracted_dir),
                    extracted_entries: Vec::new(),
                };
            }
        }

        Self {
            stream: Some(stream),
            extracted_dir: None,
            extracted_entries: Vec::new(),
        }
    }
}

impl FileStorageTrait for ZipStorage {
    fn get_json_bytes(&mut self, path: impl Into<String>) -> Result<Vec<u8>, Error> {
        let path = path.into();
        if let Some(filesystem_path) = self
            .extracted_entries
            .iter()
            .find(|entry| entry.path == path)
            .and_then(|entry| entry.filesystem_path.as_ref())
        {
            return Ok(std::fs::read(filesystem_path)?);
        }

        // TODO: error handling
        let mut f = self
            .stream
            .as_mut()
            .expect("zip stream must exist when archive was not extracted")
            .by_name(path.as_str())
            .unwrap();
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);

        Ok(buf)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String> {
        let re = cve_json_regex();
        let names: Vec<String> = if self.extracted_entries.is_empty() {
            self.stream
                .as_ref()
                .expect("zip stream must exist when archive was not extracted")
                .file_names()
                .filter(move |e| {
                    if let Some(r) = re.find(e) {
                        !r.is_empty()
                    } else {
                        false
                    }
                })
                .map(|e| e.to_owned())
                .collect()
        } else {
            self.extracted_entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect()
        };
        names.into_iter()
    }

    fn enum_json_entries(&self) -> Vec<JsonEntry> {
        if !self.extracted_entries.is_empty() {
            return self.extracted_entries.clone();
        }

        let re = cve_json_regex();
        let stream = self
            .stream
            .as_ref()
            .expect("zip stream must exist when archive was not extracted");
        (0..stream.len())
            .filter_map(|index| {
                let path = stream.name_for_index(index)?;
                if re.is_match(path) {
                    Some(JsonEntry {
                        path: path.to_owned(),
                        index: Some(index),
                        filesystem_path: None,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_json_entry_bytes(&mut self, entry: &JsonEntry) -> Result<Vec<u8>, Error> {
        if let Some(filesystem_path) = &entry.filesystem_path {
            return Ok(std::fs::read(filesystem_path)?);
        }

        let stream = self
            .stream
            .as_mut()
            .expect("zip stream must exist when archive was not extracted");
        let mut f = if let Some(index) = entry.index {
            stream.by_index(index).unwrap()
        } else {
            stream.by_name(entry.path.as_str()).unwrap()
        };
        let mut buf = Vec::with_capacity(f.size() as usize);
        let _ = f.read_to_end(&mut buf);

        Ok(buf)
    }
}

impl Drop for ZipStorage {
    fn drop(&mut self) {
        if let Some(path) = &self.extracted_dir {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn extract_nested_cve_zip(
    stream: &mut zip::ZipArchive<Box<dyn ReadSeek>>,
    nested_name: &str,
) -> (PathBuf, zip::ZipArchive<Box<dyn ReadSeek>>) {
    let nested_zip_size = stream.by_index(0).unwrap().size();
    let required_bytes = nested_zip_size
        .saturating_mul(ZIP_EXTRACTION_EXPANSION_FACTOR)
        .saturating_add(ZIP_EXTRACTION_FREE_SPACE_MARGIN_BYTES);
    let temp_dir = unique_temp_dir(required_bytes);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let inner_path = temp_dir.join("inner.zip");

    eprintln!(
        "extracting nested zip: {nested_name} -> {}",
        temp_dir.display()
    );
    {
        let mut extracted = std::fs::File::create(&inner_path).unwrap();
        let mut entry = stream.by_index(0).unwrap();
        std::io::copy(&mut entry, &mut extracted).unwrap();
    }

    let file = std::fs::File::open(&inner_path).unwrap();
    let reader = std::io::BufReader::new(file);
    let inner = zip::ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>).unwrap();

    (temp_dir, inner)
}

fn unique_temp_dir(required_bytes: u64) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    temporary_extraction_root(required_bytes)
        .join(format!("qanvuli-cve-zip-{}-{nanos}", std::process::id()))
}

fn temporary_extraction_root(required_bytes: u64) -> PathBuf {
    let temp_root = std::env::temp_dir();
    match available_storage_bytes(&temp_root) {
        Some(available) if available >= required_bytes => temp_root,
        Some(available) => {
            let binary_root = binary_directory();
            eprintln!(
                "temporary storage {} has only {} bytes available; need about {} bytes, using {}",
                temp_root.display(),
                available,
                required_bytes,
                binary_root.display()
            );
            binary_root
        }
        None => temp_root,
    }
}

fn binary_directory() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(target_os = "linux")]
fn available_storage_bytes(path: &std::path::Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_ulong};
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct Statvfs {
        f_bsize: c_ulong,
        f_frsize: c_ulong,
        f_blocks: c_ulong,
        f_bfree: c_ulong,
        f_bavail: c_ulong,
        f_files: c_ulong,
        f_ffree: c_ulong,
        f_favail: c_ulong,
        f_fsid: c_ulong,
        f_flag: c_ulong,
        f_namemax: c_ulong,
        __f_spare: [c_int; 6],
    }

    unsafe extern "C" {
        fn statvfs(path: *const c_char, buf: *mut Statvfs) -> c_int;
    }

    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<Statvfs>::uninit();
    let result = unsafe { statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return None;
    }

    let stat = unsafe { stat.assume_init() };
    let fragment_size = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    Some(stat.f_bavail.saturating_mul(fragment_size))
}

#[cfg(not(target_os = "linux"))]
fn available_storage_bytes(_path: &std::path::Path) -> Option<u64> {
    None
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
