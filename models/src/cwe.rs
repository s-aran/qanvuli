pub mod common;
pub mod entry;
pub mod enumeration;
pub mod root;
pub mod structured_text;

use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use anyhow::{Context, Result, anyhow};

pub use root::WeaknessCatalog;

pub fn parse_cwe_catalog_xml(src: &str) -> Result<WeaknessCatalog> {
    quick_xml::de::from_str(src).context("failed to parse CWE catalog XML")
}

pub fn read_cwe_catalog_xml(path: impl AsRef<Path>) -> Result<WeaknessCatalog> {
    let path = path.as_ref();
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read CWE catalog XML {}", path.display()))?;
    parse_cwe_catalog_xml(&src)
}

pub fn read_cwe_catalog_zip(path: impl AsRef<Path>) -> Result<WeaknessCatalog> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("failed to open CWE catalog zip {}", path.display()))?;
    read_cwe_catalog_zip_reader(file)
        .with_context(|| format!("failed to read CWE catalog zip {}", path.display()))
}

pub fn read_cwe_catalog_zip_reader<R>(reader: R) -> Result<WeaknessCatalog>
where
    R: Read + Seek,
{
    let mut archive = zip::ZipArchive::new(reader).context("failed to open CWE catalog zip")?;
    let xml_index = (0..archive.len())
        .find(|index| {
            archive
                .by_index(*index)
                .map(|file| file.name().ends_with(".xml"))
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("CWE catalog zip does not contain an XML file"))?;

    let mut file = archive
        .by_index(xml_index)
        .context("failed to open CWE catalog XML entry")?;
    let mut src = String::new();
    file.read_to_string(&mut src)
        .context("failed to read CWE catalog XML entry")?;
    parse_cwe_catalog_xml(&src)
}
