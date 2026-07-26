use crate::{
    common::{DetailSearch, highlighted_line},
    utils::text::normalize_spaces,
};
use qanvuli_core::database::{CveDetail, OsvSummary};
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
        lines.extend(detail.cvss.iter().map(|cvss| {
            let score = cvss
                .base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| "-".to_owned());
            let severity = cvss.base_severity.as_deref().unwrap_or("-");
            let vector = cvss.vector_string.as_deref().unwrap_or("");
            highlighted_line(
                &format!("{} {} {} {}", cvss.version, score, severity, vector),
                detail_search,
            )
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
    use qanvuli_core::database::CveCweDetail;

    #[test]
    fn shows_capec_ids_below_cwes() {
        let detail = CveDetail {
            cwes: vec![CveCweDetail {
                id: 79,
                description: Some("Cross-site Scripting".to_owned()),
            }],
            cvss: Vec::new(),
            affected: Vec::new(),
        };
        let lines = metadata_lines(Some(&detail), Some(&[63, 85]), &DetailSearch::new(""))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert_eq!(lines[0], "CWE-79 Cross-site Scripting");
        assert_eq!(lines[1], "CAPEC: CAPEC-63, CAPEC-85");
    }
}
