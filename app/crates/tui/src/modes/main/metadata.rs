use crate::{
    common::{DetailSearch, highlighted_line},
    utils::text::normalize_spaces,
};
use qanvuli_core::database::{CveDetail, OsvSummary};
use qanvuli_core::model::explain_cvss_vector;
use ratatui::text::Line;

pub(super) fn metadata_lines(
    detail: Option<&CveDetail>,
    capec_ids: Option<&[i32]>,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let Some(detail) = detail else {
        return vec![Line::from("Loading")];
    };
    let mut lines = Vec::new();
    if detail.cwes.is_empty() {
        lines.push(Line::from("No CWE"));
    } else {
        lines.extend(detail.cwes.iter().map(|cwe| {
            let description = cwe
                .description
                .as_deref()
                .map(normalize_spaces)
                .unwrap_or_default();
            highlighted_line(&format!("CWE-{} {}", cwe.id, description), detail_search)
        }));
    }
    let capec = match capec_ids {
        None => "CAPEC: Loading".to_owned(),
        Some([]) => "CAPEC: -".to_owned(),
        Some(ids) => format!(
            "CAPEC: {}",
            ids.iter()
                .map(|id| format!("CAPEC-{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    lines.push(highlighted_line(&capec, detail_search));
    lines.push(Line::from(""));
    if detail.cvss.is_empty() {
        lines.push(Line::from("No CVSS"));
    } else {
        lines.extend(detail.cvss.iter().flat_map(|cvss| {
            let score = cvss
                .base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| "-".to_owned());
            let severity = cvss.base_severity.as_deref().unwrap_or("-");
            let vector = cvss.vector_string.as_deref().unwrap_or("");
            let mut cvss_lines = vec![highlighted_line(
                &format!("{} {} {} {}", cvss.version, score, severity, vector),
                detail_search,
            )];
            if let Some(vector) = &cvss.vector_string {
                cvss_lines.extend(cvss_vector_explanation_lines(
                    &cvss.version,
                    vector,
                    detail_search,
                ));
            }
            cvss_lines
        }));
    }
    lines.push(Line::from(""));
    if detail.affected.is_empty() {
        lines.push(Line::from("No affected component"));
    } else {
        lines.extend(detail.affected.iter().flat_map(|affected| {
            let vendor = affected.vendor.as_deref().unwrap_or("-");
            let product = affected.product.as_deref().unwrap_or("-");
            let package = affected.package_name.as_deref().unwrap_or("-");
            let status = affected.default_status.as_deref().unwrap_or("-");
            let collection = affected.collection_url.as_deref().unwrap_or("");
            let suffix = if collection.is_empty() {
                String::new()
            } else {
                format!(" {}", collection)
            };
            let mut affected_lines = vec![highlighted_line(
                &format!("{vendor}/{product} pkg:{package} status:{status}{suffix}"),
                detail_search,
            )];
            if let Some(description) = affected
                .description
                .as_deref()
                .map(normalize_spaces)
                .filter(|description| !description.is_empty())
            {
                affected_lines.push(highlighted_line(
                    &format!("  Description: {description}"),
                    detail_search,
                ));
            }
            affected_lines
        }));
    }
    lines
}

fn cvss_vector_explanation_lines(
    stored_version: &str,
    vector: &str,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    explain_cvss_vector(stored_version, vector)
        .into_iter()
        .map(|metric| {
            highlighted_line(
                &format!("- {}: {}", metric.name, metric.value),
                detail_search,
            )
        })
        .collect()
}

pub(super) fn osv_metadata_lines(
    osv: &OsvSummary,
    detail_search: &DetailSearch,
) -> Vec<Line<'static>> {
    let value = |label: &str, value: Option<&str>| {
        highlighted_line(&format!("{label}: {}", value.unwrap_or("-")), detail_search)
    };
    vec![
        highlighted_line(&format!("Identifier: {}", osv.osv_id), detail_search),
        value("Schema version", osv.schema_version.as_deref()),
        value("Published", osv.published_at.as_deref()),
        value("Updated", osv.modified_at.as_deref()),
        value("Withdrawn", osv.withdrawn_at.as_deref()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_core::database::{CveCvssDetail, CveCweDetail};

    #[test]
    fn shows_capec_ids_below_cwes() {
        let detail = CveDetail {
            cwes: vec![CveCweDetail {
                id: 79,
                description: Some("Cross-site Scripting".to_owned()),
            }],
            cvss: Vec::new(),
            affected: Vec::new(),
            ssvc: Vec::new(),
        };
        let lines = metadata_lines(Some(&detail), Some(&[63, 85]), &DetailSearch::new(""))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert_eq!(lines[0], "CWE-79 Cross-site Scripting");
        assert_eq!(lines[1], "CAPEC: CAPEC-63, CAPEC-85");
    }

    #[test]
    fn explains_cvss_vector_metrics_below_the_vector() {
        let detail = CveDetail {
            cwes: Vec::new(),
            cvss: vec![CveCvssDetail {
                version: "3.1".to_owned(),
                base_score: Some(9.9),
                base_severity: Some("CRITICAL".to_owned()),
                vector_string: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H".to_owned()),
                source: None,
            }],
            affected: Vec::new(),
            ssvc: Vec::new(),
        };
        let lines = metadata_lines(Some(&detail), Some(&[]), &DetailSearch::new(""))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        let cvss_line = lines
            .iter()
            .position(|line| line.contains("CVSS:3.1"))
            .expect("CVSS vector should be displayed");

        assert_eq!(lines[cvss_line + 1], "- Attack Vector: Network");
        assert_eq!(lines[cvss_line + 2], "- Attack Complexity: Low");
        assert_eq!(lines[cvss_line + 3], "- Privileges Required: Low");
        assert_eq!(lines[cvss_line + 4], "- User Interaction: None");
        assert_eq!(lines[cvss_line + 5], "- Scope: Changed");
        assert_eq!(lines[cvss_line + 6], "- Confidentiality Impact: High");
        assert_eq!(lines[cvss_line + 7], "- Integrity Impact: High");
        assert_eq!(lines[cvss_line + 8], "- Availability Impact: High");
    }

    #[test]
    fn preserves_unknown_cvss_metrics_and_values() {
        let lines = cvss_vector_explanation_lines("9.9", "CVSS:9.9/ZZ:Q", &DetailSearch::new(""));

        assert_eq!(lines[0].to_string(), "- ZZ: Q");
    }

    #[test]
    fn explains_cvss_v2_vectors_without_a_version_prefix() {
        let lines =
            cvss_vector_explanation_lines("2.0", "AV:A/AC:M/Au:S/C:P", &DetailSearch::new(""))
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>();

        assert_eq!(lines[0], "- Access Vector: Adjacent Network");
        assert_eq!(lines[1], "- Access Complexity: Medium");
        assert_eq!(lines[2], "- Authentication: Single");
        assert_eq!(lines[3], "- Confidentiality Impact: Partial");
    }
}
