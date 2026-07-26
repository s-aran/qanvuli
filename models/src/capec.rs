pub mod common;
pub mod entry;
pub mod enumeration;
pub mod root;
pub mod structured_text;

use std::path::Path;

use anyhow::{Context, Result};

pub use root::AttackPatternCatalog;

pub fn parse_capec_catalog_xml(src: &str) -> Result<AttackPatternCatalog> {
    quick_xml::de::from_str(src).context("failed to parse CAPEC catalog XML")
}

pub fn read_capec_catalog_xml(path: impl AsRef<Path>) -> Result<AttackPatternCatalog> {
    let path = path.as_ref();
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read CAPEC catalog XML {}", path.display()))?;
    parse_capec_catalog_xml(&src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relations_and_taxonomy() {
        let xml = r#"<?xml version="1.0"?>
<Attack_Pattern_Catalog Name="CAPEC" Version="3.9" Date="2023-01-24">
  <Attack_Patterns>
    <Attack_Pattern ID="1" Name="Example" Abstraction="Standard" Status="Stable">
      <Description>Example description</Description>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="2"/>
      </Related_Attack_Patterns>
      <Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses>
      <References><Reference External_Reference_ID="REF-1" Section="1"/></References>
    </Attack_Pattern>
  </Attack_Patterns>
  <Categories>
    <Category ID="100" Name="Category" Status="Stable">
      <Summary><p>Summary text</p></Summary>
      <Relationships><Has_Member CAPEC_ID="1"/></Relationships>
      <Content_History>
        <Submission><Submission_Name>Team</Submission_Name><Submission_Date>2020-01-01</Submission_Date></Submission>
      </Content_History>
    </Category>
  </Categories>
  <Views>
    <View ID="1000" Name="View" Type="Graph" Status="Stable">
      <Objective>Objective</Objective>
      <Members><Has_Member CAPEC_ID="100"/></Members>
    </View>
  </Views>
  <External_References>
    <External_Reference Reference_ID="REF-1"><Author>A</Author><Title>Title</Title></External_Reference>
  </External_References>
</Attack_Pattern_Catalog>"#;
        let catalog = parse_capec_catalog_xml(xml).unwrap();
        let pattern = &catalog.attack_patterns.unwrap().items[0];
        assert_eq!(pattern.description.plain_text(), "Example description");
        assert_eq!(
            pattern.related_weaknesses.as_ref().unwrap().items[0].cwe_id,
            79
        );
        assert_eq!(catalog.categories.unwrap().items[0].id, 100);
        assert_eq!(catalog.views.unwrap().items[0].id, 1000);
        assert_eq!(catalog.external_references.unwrap().items[0].authors, ["A"]);
    }

    #[test]
    #[ignore = "requires an official CAPEC fixture path"]
    fn parses_official_fixture() {
        let path = std::env::var("QANVULI_CAPEC_FIXTURE").unwrap();
        let xml = std::fs::read_to_string(path).unwrap();
        parse_capec_catalog_xml(&xml).unwrap();
    }
}
