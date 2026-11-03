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
                .map(|file| file.name().is_ok_and(|name| name.ends_with(".xml")))
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

#[cfg(test)]
mod schema8_tests {
    use super::*;

    #[test]
    fn parses_schema_8_fields() {
        let catalog =
            parse_cwe_catalog_xml(include_str!("../../fixtures/cwe/catalog-5.0-test.xml")).unwrap();
        assert_eq!(catalog.version, "5.0");
        let weakness = &catalog.weaknesses.as_ref().unwrap().weakness[0];
        assert!(weakness.technical_nuance.is_some());
        assert_eq!(
            weakness.dimensions.as_ref().unwrap().dimension[0].value,
            "Comparison"
        );
        assert!(
            weakness
                .related_weaknesses
                .as_ref()
                .unwrap()
                .related_weakness[0]
                .dimensions
                .is_some()
        );
        let platforms = weakness.applicable_platforms.as_ref().unwrap();
        assert!(platforms.language[0].note.is_some());
        assert!(platforms.operating_system[0].note.is_some());
        assert!(platforms.architecture[0].note.is_some());
        assert!(platforms.technology[0].note.is_some());
        assert_eq!(
            weakness.alternate_terms.as_ref().unwrap().alternate_term[0]
                .role
                .len(),
            2
        );
        let introduction = &weakness
            .modes_of_introduction
            .as_ref()
            .unwrap()
            .introduction[0];
        assert_eq!(introduction.phase.len(), 2);
        assert_eq!(introduction.custom_phase.len(), 2);
        assert!(matches!(
            introduction.custom_phase[0].phase,
            common::CustomPhaseValue::AI(enumeration::AIPhase::Training)
        ));
        assert!(matches!(
            introduction.custom_phase[1].phase,
            common::CustomPhaseValue::Hardware(enumeration::HardwarePhase::HardwareArchitecture)
        ));
        assert_eq!(
            weakness
                .detection_methods
                .as_ref()
                .unwrap()
                .detection_method[0]
                .custom_phase
                .len(),
            1
        );
        assert_eq!(
            weakness.potential_mitigations.as_ref().unwrap().mitigation[0]
                .custom_phase
                .len(),
            1
        );
        assert_eq!(
            weakness
                .observed_examples
                .as_ref()
                .unwrap()
                .observed_example[0]
                .rationale
                .len(),
            2
        );
        assert_eq!(
            weakness.notes.as_ref().unwrap().note[0].version.as_deref(),
            Some("5.0")
        );
        assert_eq!(weakness.content_history.submission.len(), 2);
        assert_eq!(
            weakness.content_history.submission[0].submission_name,
            ["A", "B"]
        );
        assert_eq!(
            weakness.content_history.contribution[0].contribution_name,
            ["A", "B"]
        );
        let grouping = &catalog.groupings.unwrap().grouping[0];
        assert_eq!(grouping.id, 101);
        assert!(
            grouping.relationships.as_ref().unwrap().has_member[0]
                .dimensions
                .is_some()
        );
        let reference = &catalog.external_references.unwrap().external_reference[0];
        assert_eq!(reference.media_type.len(), 2);
        assert_eq!(reference.rationale.len(), 2);
        assert!(reference.alt_url.is_some());
        assert!(reference.access_restrictions.is_some());
    }

    #[test]
    fn retains_legacy_catalog_support() {
        let catalog =
            parse_cwe_catalog_xml(include_str!("../../fixtures/cwe/catalog-test.xml")).unwrap();
        assert_eq!(catalog.weaknesses.unwrap().weakness.len(), 3);
        assert!(catalog.groupings.is_none());
        let xml = include_str!("../../fixtures/cwe/catalog-5.0-test.xml")
            .replace("<Groupings>", "<Categories>")
            .replace("</Groupings>", "</Categories>")
            .replace("<Grouping ", "<Category ")
            .replace("</Grouping>", "</Category>");
        // Categories remain accepted alongside the new grouping representation.
        let catalog = parse_cwe_catalog_xml(&xml).unwrap();
        assert_eq!(catalog.categories.unwrap().category[0].id, 101);
        assert!(catalog.groupings.is_none());
    }

    #[test]
    fn rejects_unknown_schema_fields() {
        let xml = include_str!("../../fixtures/cwe/catalog-5.0-test.xml")
            .replace("<Technical_Nuance>", "<Unknown>")
            .replace("</Technical_Nuance>", "</Unknown>");
        assert!(parse_cwe_catalog_xml(&xml).is_err());
    }

    #[test]
    #[ignore = "requires an official CWE 5.0 archive via CWE_5_CATALOG_ZIP"]
    fn official_cwe_5_catalog() {
        let path = std::env::var("CWE_5_CATALOG_ZIP").expect("set CWE_5_CATALOG_ZIP");
        let catalog = read_cwe_catalog_zip(path).unwrap();
        assert_eq!(catalog.version, "5.0");
        assert_eq!(catalog.weaknesses.unwrap().weakness.len(), 984);
        assert_eq!(catalog.groupings.unwrap().grouping.len(), 431);
        assert_eq!(catalog.views.unwrap().view.len(), 62);
        assert_eq!(
            catalog
                .external_references
                .unwrap()
                .external_reference
                .len(),
            1081
        );
    }
}
