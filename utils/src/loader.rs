use std::{
    fs::File,
    io::{Read, Seek},
    path::PathBuf,
};

use anyhow::{Context, Error, anyhow};
use glob::{MatchOptions, glob_with};

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
        let p = PathBuf::from(path.into());
        let mut file =
            File::open(&p).with_context(|| format!("failed to open JSON file {}", p.display()))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .with_context(|| format!("failed to read JSON file {}", p.display()))?;

        Ok(buf)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String> {
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/**/CVE-*.json", self.base.to_string_lossy());
        let files = glob_with(base_path.as_str(), glob_options)
            .map(|paths| {
                paths
                    .filter_map(Result::ok)
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        files.into_iter()
    }
}

trait ReadSeek: Read + Seek + Send {}

impl<T> ReadSeek for T where T: Read + Seek + Send {}

const ZIP_EXTRACTION_EXPANSION_FACTOR: u64 = 8;
const ZIP_EXTRACTION_FREE_SPACE_MARGIN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CVE_JSON_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_NESTED_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub struct ZipStorage {
    stream: Option<zip::ZipArchive<Box<dyn ReadSeek>>>,
    extracted_dir: Option<PathBuf>,
    extracted_entries: Vec<JsonEntry>,
    cleanup_extracted_dir_on_drop: bool,
}

impl ZipStorage {
    pub fn new(filename: impl Into<String>) -> Result<Self, Error> {
        let filename = filename.into();
        let file = std::fs::File::open(&filename)
            .with_context(|| format!("failed to open zip archive {filename}"))?;
        let reader = std::io::BufReader::new(file);
        let mut stream = zip::ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>)
            .with_context(|| format!("failed to read zip archive {filename}"))?;
        if stream.len() == 1 {
            let name = stream
                .by_index(0)
                .with_context(|| format!("failed to inspect first zip entry in {filename}"))?
                .name()
                .to_owned();
            if name.ends_with(".zip") && !archive_has_cve_json(&stream) {
                let (extracted_dir, inner) = extract_nested_cve_zip(&mut stream, &name)?;
                return Ok(Self {
                    stream: Some(inner),
                    extracted_dir: Some(extracted_dir),
                    extracted_entries: Vec::new(),
                    cleanup_extracted_dir_on_drop: true,
                });
            }
        }

        Ok(Self {
            stream: Some(stream),
            extracted_dir: None,
            extracted_entries: Vec::new(),
            cleanup_extracted_dir_on_drop: true,
        })
    }

    /// Keeps any temporary nested archive extraction directory after this storage is dropped.
    pub fn retain_extracted_dir(&mut self) {
        self.cleanup_extracted_dir_on_drop = false;
    }

    /// Returns the temporary nested archive extraction directory, if one was created.
    pub fn extracted_dir(&self) -> Option<&std::path::Path> {
        self.extracted_dir.as_deref()
    }

    /// Deletes the temporary nested archive extraction directory, if one was created.
    pub fn cleanup_extracted_dir(&mut self) -> Result<(), Error> {
        let Some(path) = self.extracted_dir.take() else {
            return Ok(());
        };
        std::fs::remove_dir_all(&path).with_context(|| {
            format!(
                "failed to remove temporary extraction directory {}",
                path.display()
            )
        })
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

        let mut f = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow!("zip stream is unavailable for {path}"))?
            .by_name(path.as_str())
            .with_context(|| format!("failed to find {path} in zip archive"))?;
        read_zip_entry_bytes(&mut f, &path)
    }

    fn enum_json_list(&self) -> impl Iterator<Item = String> {
        let names: Vec<String> = if self.extracted_entries.is_empty() {
            self.stream.as_ref().map_or_else(Vec::new, |stream| {
                stream
                    .file_names()
                    .filter(|path| is_cve_json_path(path))
                    .map(|e| e.to_owned())
                    .collect()
            })
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

        let Some(stream) = self.stream.as_ref() else {
            return Vec::new();
        };
        (0..stream.len())
            .filter_map(|index| {
                let path = stream.name_for_index(index)?;
                if is_cve_json_path(path) {
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
            .ok_or_else(|| anyhow!("zip stream is unavailable for {}", entry.path))?;
        let mut f = if let Some(index) = entry.index {
            stream
                .by_index(index)
                .with_context(|| format!("failed to find zip entry index {index}"))?
        } else {
            stream
                .by_name(entry.path.as_str())
                .with_context(|| format!("failed to find {} in zip archive", entry.path))?
        };
        read_zip_entry_bytes(&mut f, &entry.path)
    }
}

impl Drop for ZipStorage {
    fn drop(&mut self) {
        if self.cleanup_extracted_dir_on_drop
            && let Some(path) = &self.extracted_dir
        {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn extract_nested_cve_zip(
    stream: &mut zip::ZipArchive<Box<dyn ReadSeek>>,
    nested_name: &str,
) -> Result<(PathBuf, zip::ZipArchive<Box<dyn ReadSeek>>), Error> {
    let nested_zip_size = stream
        .by_index(0)
        .with_context(|| format!("failed to inspect nested zip entry {nested_name}"))?
        .size();
    if nested_zip_size > MAX_NESTED_ARCHIVE_BYTES {
        return Err(anyhow!(
            "nested zip entry {nested_name} is {nested_zip_size} bytes; maximum is {MAX_NESTED_ARCHIVE_BYTES} bytes"
        ));
    }
    let required_bytes = nested_zip_size
        .saturating_mul(ZIP_EXTRACTION_EXPANSION_FACTOR)
        .saturating_add(ZIP_EXTRACTION_FREE_SPACE_MARGIN_BYTES);
    let temp_dir = unique_temp_dir(required_bytes);
    std::fs::create_dir_all(&temp_dir).with_context(|| {
        format!(
            "failed to create temporary extraction directory {}",
            temp_dir.display()
        )
    })?;
    let inner_path = temp_dir.join("inner.zip");

    eprintln!(
        "extracting nested zip: {nested_name} -> {}",
        temp_dir.display()
    );
    {
        let mut extracted = std::fs::File::create(&inner_path).with_context(|| {
            format!("failed to create nested zip copy {}", inner_path.display())
        })?;
        let mut entry = stream
            .by_index(0)
            .with_context(|| format!("failed to open nested zip entry {nested_name}"))?;
        std::io::copy(&mut entry, &mut extracted)
            .with_context(|| format!("failed to extract nested zip entry {nested_name}"))?;
    }

    let file = std::fs::File::open(&inner_path).with_context(|| {
        format!(
            "failed to open extracted nested zip {}",
            inner_path.display()
        )
    })?;
    let reader = std::io::BufReader::new(file);
    let inner = zip::ZipArchive::new(Box::new(reader) as Box<dyn ReadSeek>).with_context(|| {
        format!(
            "failed to read extracted nested zip {}",
            inner_path.display()
        )
    })?;

    Ok((temp_dir, inner))
}

fn read_zip_entry_bytes(reader: &mut impl Read, path: &str) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CVE_JSON_ENTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {path} from zip archive"))?;
    if bytes.len() as u64 > MAX_CVE_JSON_ENTRY_BYTES {
        return Err(anyhow!(
            "zip entry {path} exceeds the {MAX_CVE_JSON_ENTRY_BYTES}-byte limit"
        ));
    }
    Ok(bytes)
}

fn unique_temp_dir(required_bytes: u64) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
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
    stream.file_names().any(is_cve_json_path)
}

fn is_cve_json_path(path: &str) -> bool {
    let Some(filename) = path.rsplit('/').next() else {
        return false;
    };
    let Some(stem) = filename.strip_suffix(".json") else {
        return false;
    };
    let Some(rest) = stem.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn nested_cve_zip_path(label: &str) -> PathBuf {
        let suffix = format!(
            "{label}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let inner_path = std::env::temp_dir().join(format!("qanvuli-inner-{suffix}.zip"));
        let outer_path = std::env::temp_dir().join(format!("qanvuli-outer-{suffix}.zip"));

        let inner_file = std::fs::File::create(&inner_path).unwrap();
        let mut inner = zip::ZipWriter::new(inner_file);
        inner
            .start_file("CVE-2024-1.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        inner.write_all(b"{}").unwrap();
        inner.finish().unwrap();

        let outer_file = std::fs::File::create(&outer_path).unwrap();
        let mut outer = zip::ZipWriter::new(outer_file);
        outer
            .start_file("cves.zip", zip::write::SimpleFileOptions::default())
            .unwrap();
        outer
            .write_all(&std::fs::read(&inner_path).unwrap())
            .unwrap();
        outer.finish().unwrap();
        std::fs::remove_file(inner_path).unwrap();
        outer_path
    }

    #[test]
    fn zip_storage_new_returns_error_for_missing_zip() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-missing-zip-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));

        let err = match ZipStorage::new(path.to_string_lossy().to_string()) {
            Ok(_) => panic!("missing zip unexpectedly opened"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to open zip archive"));
    }

    #[test]
    fn zip_storage_new_returns_error_for_invalid_zip() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-invalid-zip-{}-{}.zip",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, b"not a zip").unwrap();

        let err = match ZipStorage::new(path.to_string_lossy().to_string()) {
            Ok(_) => panic!("invalid zip unexpectedly opened"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to read zip archive"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cve_json_path_filter_matches_only_cve_json_filenames() {
        assert!(is_cve_json_path("nested/CVE-2024-12345.json"));
        assert!(is_cve_json_path("CVE-1999-1.json"));
        assert!(!is_cve_json_path("nested/GHSA-xxxx.json"));
        assert!(!is_cve_json_path("nested/CVE-20X4-12345.json"));
        assert!(!is_cve_json_path("nested/CVE-2024-.json"));
        assert!(!is_cve_json_path("nested/CVE-2024-12345.JSON"));
    }

    #[test]
    fn zip_entry_reader_rejects_oversized_json() {
        let mut reader = std::io::Cursor::new(vec![b'x'; MAX_CVE_JSON_ENTRY_BYTES as usize + 1]);

        let err = read_zip_entry_bytes(&mut reader, "CVE-2024-1.json").unwrap_err();

        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn retained_nested_extraction_survives_drop() {
        let outer_path = nested_cve_zip_path("retain");
        let extracted_dir = {
            let mut storage = ZipStorage::new(outer_path.to_string_lossy().to_string()).unwrap();
            storage.retain_extracted_dir();
            storage.extracted_dir().unwrap().to_path_buf()
        };

        assert!(extracted_dir.exists());
        std::fs::remove_dir_all(extracted_dir).unwrap();
        std::fs::remove_file(outer_path).unwrap();
    }

    #[test]
    fn nested_extraction_is_removed_by_default() {
        let outer_path = nested_cve_zip_path("cleanup");
        let extracted_dir = {
            let storage = ZipStorage::new(outer_path.to_string_lossy().to_string()).unwrap();
            storage.extracted_dir().unwrap().to_path_buf()
        };

        assert!(!extracted_dir.exists());
        std::fs::remove_file(outer_path).unwrap();
    }
}
