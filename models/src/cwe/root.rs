use serde::Deserialize;

use crate::cwe::entry::{Category, ExternalReference, View, Weakness};

#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness_Catalog", deny_unknown_fields)]
pub struct WeaknessCatalog {
    #[serde(rename = "Weaknesses")]
    pub weaknesses: Option<Weaknesses>,
    #[serde(rename = "Categories")]
    pub categories: Option<Categories>,
    #[serde(rename = "Views")]
    pub views: Option<Views>,
    #[serde(rename = "External_References")]
    pub external_references: Option<ExternalReferences>,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: Option<String>,
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: Option<String>,
    #[serde(rename = "@xsi:schemaLocation")]
    pub xsi_schema_location: Option<String>,
    #[serde(rename = "@schemaLocation")]
    pub schema_location: Option<String>,
    #[serde(rename = "@xmlns:xhtml")]
    pub xmlns_xhtml: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
    #[serde(rename = "Weakness")]
    pub weakness: Vec<Weakness>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Categories {
    #[serde(rename = "Category")]
    pub category: Vec<Category>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Views {
    #[serde(rename = "View")]
    pub view: Vec<View>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReferences {
    #[serde(rename = "External_Reference")]
    pub external_reference: Vec<ExternalReference>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::cwe::common::{References, Relationships};

    #[test]
    fn deserialize_cwe_catalog_xml() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../collector/src/cwec_v4.20.xml");
        let src = std::fs::read_to_string(path).expect("CWE XML fixture should be readable");
        let catalog: WeaknessCatalog =
            quick_xml::de::from_str(&src).expect("CWE XML fixture should deserialize");

        assert_eq!(catalog.name, "CWE");
        assert_eq!(catalog.version, "4.20");

        let weaknesses = catalog
            .weaknesses
            .expect("weaknesses should exist")
            .weakness;
        let categories = catalog
            .categories
            .expect("categories should exist")
            .category;
        let views = catalog.views.expect("views should exist").view;
        let external_references = catalog
            .external_references
            .expect("external references should exist")
            .external_reference;

        println!(
            "catalog={} version={} date={} weaknesses={} categories={} views={} external_references={}",
            catalog.name,
            catalog.version,
            catalog.date,
            weaknesses.len(),
            categories.len(),
            views.len(),
            external_references.len()
        );

        let first = weaknesses.first().expect("at least one weakness");
        println!(
            "first weakness: CWE-{} {} {:?} {:?} {:?}",
            first.id, first.name, first.abstraction, first.structure, first.status
        );

        assert_eq!(first.id, 1004);
        assert_eq!(first.name, "Sensitive Cookie Without 'HttpOnly' Flag");
        assert!(weaknesses.len() > 900);
        assert!(!categories.is_empty());
        assert!(!views.is_empty());
        assert!(!external_references.is_empty());

        validate_catalog_contents(&weaknesses, &categories, &views, &external_references);
    }

    fn validate_catalog_contents(
        weaknesses: &[Weakness],
        categories: &[Category],
        views: &[View],
        external_references: &[ExternalReference],
    ) {
        let weakness_ids = unique_ids(weaknesses.iter().map(|weakness| weakness.id), "weakness");
        let category_ids = unique_ids(categories.iter().map(|category| category.id), "category");
        let view_ids = unique_ids(views.iter().map(|view| view.id), "view");
        let reference_ids = unique_strings(
            external_references
                .iter()
                .map(|reference| reference.reference_id.as_str()),
            "external reference",
        );

        let mut entry_ids = HashSet::new();
        entry_ids.extend(weakness_ids.iter().copied());
        entry_ids.extend(category_ids.iter().copied());
        entry_ids.extend(view_ids.iter().copied());

        let mut entry_names = HashSet::new();

        for weakness in weaknesses {
            assert!(
                entry_names.insert(weakness.name.as_str()),
                "duplicate entry name: {}",
                weakness.name
            );
            assert!(!weakness.name.trim().is_empty(), "empty weakness name");
            assert!(
                !weakness.description.trim().is_empty(),
                "empty description for CWE-{}",
                weakness.id
            );

            if let Some(related_weaknesses) = &weakness.related_weaknesses {
                for related in &related_weaknesses.related_weakness {
                    assert!(
                        entry_ids.contains(&related.cwe_id),
                        "CWE-{} references unknown related CWE_ID {}",
                        weakness.id,
                        related.cwe_id
                    );
                    assert!(
                        view_ids.contains(&related.view_id),
                        "CWE-{} references unknown related View_ID {}",
                        weakness.id,
                        related.view_id
                    );
                }
            }

            if let Some(examples) = &weakness.demonstrative_examples {
                for example in &examples.demonstrative_example {
                    validate_references(&example.references, &reference_ids);
                }
            }

            validate_references(&weakness.references, &reference_ids);
            validate_mapping_suggestions(weakness.id, &weakness.mapping_notes, &entry_ids);
        }

        for category in categories {
            assert!(
                entry_names.insert(category.name.as_str()),
                "duplicate entry name: {}",
                category.name
            );
            assert!(!category.name.trim().is_empty(), "empty category name");
            validate_relationships(&category.relationships, &entry_ids, &view_ids);
            validate_references(&category.references, &reference_ids);
            validate_mapping_suggestions(category.id, &category.mapping_notes, &entry_ids);
        }

        for view in views {
            assert!(
                entry_names.insert(view.name.as_str()),
                "duplicate entry name: {}",
                view.name
            );
            assert!(!view.name.trim().is_empty(), "empty view name");
            validate_relationships(&view.members, &entry_ids, &view_ids);
            validate_references(&view.references, &reference_ids);
            validate_mapping_suggestions(view.id, &view.mapping_notes, &entry_ids);
        }

        for reference in external_references {
            assert!(
                !reference.reference_id.trim().is_empty(),
                "empty external reference id"
            );
            assert!(
                !reference.title.trim().is_empty(),
                "empty title for external reference {}",
                reference.reference_id
            );
        }
    }

    fn unique_ids(values: impl Iterator<Item = i64>, label: &str) -> HashSet<i64> {
        let mut ids = HashSet::new();
        for id in values {
            assert!(ids.insert(id), "duplicate {label} id: {id}");
        }
        ids
    }

    fn unique_strings<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> HashSet<&'a str> {
        let mut strings = HashSet::new();
        for value in values {
            assert!(strings.insert(value), "duplicate {label} value: {value}");
        }
        strings
    }

    fn validate_relationships(
        relationships: &Option<Relationships>,
        entry_ids: &HashSet<i64>,
        view_ids: &HashSet<i64>,
    ) {
        let Some(relationships) = relationships else {
            return;
        };

        for member in relationships
            .member_of
            .iter()
            .chain(relationships.has_member.iter())
        {
            assert!(
                entry_ids.contains(&member.cwe_id),
                "relationship references unknown CWE_ID {}",
                member.cwe_id
            );
            assert!(
                view_ids.contains(&member.view_id),
                "relationship references unknown View_ID {}",
                member.view_id
            );
        }
    }

    fn validate_references<'a>(
        references: &Option<References>,
        external_reference_ids: &HashSet<&'a str>,
    ) {
        let Some(references) = references else {
            return;
        };

        for reference in &references.reference {
            assert!(
                external_reference_ids.contains(reference.external_reference_id.as_str()),
                "unknown external reference id {}",
                reference.external_reference_id
            );
        }
    }

    fn validate_mapping_suggestions(
        entry_id: i64,
        mapping_notes: &crate::cwe::common::MappingNotes,
        entry_ids: &HashSet<i64>,
    ) {
        let Some(suggestions) = &mapping_notes.suggestions else {
            return;
        };

        for suggestion in &suggestions.suggestion {
            assert!(
                entry_ids.contains(&suggestion.cwe_id),
                "CWE-{entry_id} suggests unknown CWE_ID {}",
                suggestion.cwe_id
            );
        }
    }
}
