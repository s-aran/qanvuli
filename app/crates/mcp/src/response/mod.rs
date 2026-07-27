use crate::common::error::mcp_error;
use qanvuli_core::database::{
    CveAffectedDetail, CveCvssDetail, CveCweDetail, CveReference, CveSummary, CveSummaryWithDetail,
    cve_state_label,
};
use qanvuli_core::model::RawCveStatusRecord;
use rmcp::model::{CallToolResult, ContentBlock};
use simd_json::{OwnedValue as Value, json};

pub(crate) const DESC_PREVIEW_CHARS: usize = 280;
pub(crate) const MAX_RESULT_BYTES: usize = 40_000;

pub(crate) fn tool_result(value: Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let value = if encoded_len(&value)? > MAX_RESULT_BYTES {
        shrink_over_budget(&value, MAX_RESULT_BYTES).ok_or_else(|| {
            mcp_error(format!(
                "tool result exceeds {MAX_RESULT_BYTES} byte response budget"
            ))
        })?
    } else {
        value
    };
    let text = simd_json::to_string(&value)
        .map_err(|err| mcp_error(format!("failed to encode tool result: {err}")))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn encoded_len(value: &Value) -> Result<usize, rmcp::ErrorData> {
    simd_json::to_string(value)
        .map(|text| text.len())
        .map_err(|err| mcp_error(format!("failed to encode tool result: {err}")))
}

/// Removes optional list detail, then pages a top-level results/findings array until it fits.
pub(crate) fn shrink_over_budget(value: &Value, budget: usize) -> Option<Value> {
    let mut compact = value.clone();
    let array_key = match &compact {
        Value::Object(object) if object.contains_key("results") => "results",
        Value::Object(object) if object.contains_key("findings") => "findings",
        _ => return None,
    };
    let total = {
        let Value::Object(object) = &mut compact else {
            return None;
        };
        let Value::Array(items) = object.get_mut(array_key)? else {
            return None;
        };
        for item in items.iter_mut() {
            if let Value::Object(item) = item {
                item.remove("description");
                item.remove("description_preview");
            }
        }
        items.len()
    };
    if encoded_len(&compact).ok()? <= budget {
        return Some(compact);
    }

    // Package batches are audit-oriented: preserve every package summary before
    // considering pagination. Full findings and enrichment are optional detail.
    if is_package_batch(&compact) {
        for field in ["findings", "cve_risk"] {
            remove_result_field(&mut compact, field)?;
            if encoded_len(&compact).ok()? <= budget {
                mark_detail_reduced(&mut compact)?;
                return Some(compact);
            }
        }
    }

    let package_batch = is_package_batch(&compact);
    loop {
        let returned = {
            let Value::Object(object) = &mut compact else {
                return None;
            };
            let Value::Array(items) = object.get_mut(array_key)? else {
                return None;
            };
            if package_batch {
                drop_last_non_vulnerable_package(items).or_else(|| items.pop());
            } else {
                items.pop();
            }
            items.len()
        };
        let Value::Object(object) = &mut compact else {
            return None;
        };
        object.insert("response_truncated".into(), json!(true));
        object.insert("returned".into(), json!(returned));
        object.insert("total".into(), json!(total));
        object.insert(
            "hint".into(),
            json!(if package_batch {
                "use verbosity=summary for large package batches"
            } else {
                "narrow query or page with offset"
            }),
        );
        if encoded_len(&compact).ok()? <= budget {
            return Some(compact);
        }
        if returned == 0 {
            break;
        }
    }
    (encoded_len(&compact).ok()? <= budget).then_some(compact)
}

fn is_package_batch(value: &Value) -> bool {
    matches!(value, Value::Object(object) if object.contains_key("coverage_notice"))
}

fn remove_result_field(value: &mut Value, field: &str) -> Option<()> {
    let Value::Object(object) = value else {
        return None;
    };
    let Value::Array(items) = object.get_mut("results")? else {
        return None;
    };
    for item in items.iter_mut() {
        if let Value::Object(item) = item {
            item.remove(field);
        }
    }
    Some(())
}

fn mark_detail_reduced(value: &mut Value) -> Option<()> {
    let Value::Object(object) = value else {
        return None;
    };
    object.insert("response_detail_reduced".into(), json!(true));
    object.insert(
        "hint".into(),
        json!("full findings or CVE enrichment omitted to preserve all package summaries"),
    );
    Some(())
}

fn drop_last_non_vulnerable_package(items: &mut Vec<Value>) -> Option<Value> {
    let index = items.iter().rposition(|item| {
        matches!(
            item,
            Value::Object(item)
                if matches!(item.get("summary"), Some(Value::Object(summary)) if summary.get("vulnerable") == Some(&json!(false)))
        )
    })?;
    Some(items.remove(index))
}

pub(crate) fn summaries_with_detail(cves: Vec<CveSummaryWithDetail>) -> Vec<Value> {
    cves.into_iter().map(summary_with_detail).collect()
}

pub(crate) fn summaries_with_detail_compact(cves: Vec<CveSummaryWithDetail>) -> Vec<Value> {
    cves.into_iter().map(summary_with_detail_compact).collect()
}

pub(crate) fn preview(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{preview}…")
    } else {
        preview
    }
}

pub(crate) fn summary(cve: CveSummary) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve_state_label(cve.state),
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "title": cve.title,
        "description": cve.description_en,
    })
}

pub(crate) fn summary_compact(cve: CveSummary) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve_state_label(cve.state),
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "title": cve.title,
        "description_preview": cve.description_en.as_deref().map(|value| preview(value, DESC_PREVIEW_CHARS)),
    })
}

pub(crate) fn summary_with_detail(cve: CveSummaryWithDetail) -> Value {
    let mut value = summary(cve.summary);
    if let Value::Object(ref mut object) = value {
        object.insert("cwe".into(), json!(cwe_values(cve.detail.cwes)));
        object.insert("cvss".into(), json!(cvss_values(cve.detail.cvss)));
        object.insert(
            "affected".into(),
            json!(affected_values(cve.detail.affected)),
        );
    }
    value
}

pub(crate) fn summary_with_detail_compact(cve: CveSummaryWithDetail) -> Value {
    let mut value = summary_compact(cve.summary);
    if let Value::Object(ref mut object) = value {
        object.insert("cwe".into(), json!(cwe_values(cve.detail.cwes)));
        object.insert("cvss".into(), json!(cvss_values(cve.detail.cvss)));
        object.insert(
            "affected".into(),
            json!(affected_values(cve.detail.affected)),
        );
    }
    value
}

fn cwe_values(cwes: Vec<CveCweDetail>) -> Vec<Value> {
    cwes.into_iter()
        .map(|cwe| {
            json!({
                "id": cwe.id,
                "cwe_id": format!("CWE-{}", cwe.id),
                "description": cwe.description,
            })
        })
        .collect()
}

fn cvss_values(cvss: Vec<CveCvssDetail>) -> Vec<Value> {
    cvss.into_iter()
        .map(|cvss| {
            json!({
                "version": cvss.version,
                "base_score": cvss.base_score,
                "base_severity": cvss.base_severity,
                "vector_string": cvss.vector_string,
                "source": cvss.source,
            })
        })
        .collect()
}

fn affected_values(affected: Vec<CveAffectedDetail>) -> Vec<Value> {
    affected
        .into_iter()
        .map(|affected| {
            json!({
                "vendor": affected.vendor,
                "product": affected.product,
                "package_name": affected.package_name,
                "collection_url": affected.collection_url,
                "default_status": affected.default_status,
                "versions": affected.versions.into_iter().map(|version| {
                    json!({
                        "version": version.version,
                        "status": version.status,
                        "version_type": version.version_type,
                        "less_than": version.less_than,
                        "less_than_or_equal": version.less_than_or_equal,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect()
}

pub(crate) fn full_cve(cve: RawCveStatusRecord) -> Value {
    cve.into_parts()
        .1
        .try_into()
        .unwrap_or_else(|_| Value::Static(simd_json::StaticNode::Null))
}

pub(crate) fn explain_match(
    query: Option<&str>,
    cve: Option<CveSummaryWithDetail>,
    references: Vec<CveReference>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let Some(cve) = cve else {
        return tool_result(json!(null));
    };
    let query = query.unwrap_or_default().trim().to_ascii_lowercase();
    let evidence = if query.is_empty() {
        Vec::new()
    } else {
        match_evidence(&query, &cve, &references)
    };
    tool_result(json!({
        "cve": summary_with_detail(cve),
        "query": if query.is_empty() { None } else { Some(query) },
        "matched_fields": evidence,
        "references": references,
    }))
}

fn match_evidence(
    query: &str,
    cve: &CveSummaryWithDetail,
    references: &[CveReference],
) -> Vec<Value> {
    let mut evidence = Vec::new();
    push_text_match(&mut evidence, "cve_id", &cve.summary.cve_id, query);
    push_text_match(&mut evidence, "title", &cve.summary.title, query);
    if let Some(description) = &cve.summary.description_en {
        push_text_match(&mut evidence, "description", description, query);
    }
    for cwe in &cve.detail.cwes {
        push_text_match(&mut evidence, "cwe_id", &format!("CWE-{}", cwe.id), query);
        if let Some(description) = &cwe.description {
            push_text_match(&mut evidence, "cwe_description", description, query);
        }
    }
    for cvss in &cve.detail.cvss {
        push_text_match(&mut evidence, "cvss_version", &cvss.version, query);
        if let Some(severity) = &cvss.base_severity {
            push_text_match(&mut evidence, "cvss_severity", severity, query);
        }
        if let Some(vector) = &cvss.vector_string {
            push_text_match(&mut evidence, "cvss_vector", vector, query);
        }
    }
    for affected in &cve.detail.affected {
        if let Some(vendor) = &affected.vendor {
            push_text_match(&mut evidence, "affected_vendor", vendor, query);
        }
        if let Some(product) = &affected.product {
            push_text_match(&mut evidence, "affected_product", product, query);
        }
        if let Some(package_name) = &affected.package_name {
            push_text_match(&mut evidence, "affected_package", package_name, query);
        }
        for version in &affected.versions {
            if let Some(value) = &version.version {
                push_text_match(&mut evidence, "affected_version", value, query);
            }
        }
    }
    for reference in references {
        if let Some(url) = &reference.url {
            push_text_match(&mut evidence, "reference_url", url, query);
        }
        if let Some(name) = &reference.name {
            push_text_match(&mut evidence, "reference_name", name, query);
        }
        for tag in &reference.tags {
            push_text_match(&mut evidence, "reference_tag", tag, query);
        }
    }
    evidence
}

fn push_text_match(evidence: &mut Vec<Value>, field: &str, value: &str, query: &str) {
    if value.to_ascii_lowercase().contains(query) {
        evidence.push(json!({
            "field": field,
            "value": value,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_is_character_based_and_marks_truncation() {
        assert_eq!(preview("あいうえお", 3), "あいう…");
        assert_eq!(preview("short", 280), "short");
    }

    #[test]
    fn shrink_over_budget_marks_and_truncates_results() {
        let results = (0..20)
            .map(|index| json!({"cve_id": format!("CVE-2026-{index}"), "title": "x".repeat(2_000), "description": "x".repeat(2_000)}))
            .collect::<Vec<_>>();
        let value = json!({"results": results});
        let shrunk = shrink_over_budget(&value, 800).expect("response can be truncated");
        let Value::Object(object) = shrunk else {
            panic!("object result")
        };
        assert_eq!(object.get("response_truncated"), Some(&json!(true)));
        assert!(object.get("returned").is_some());
        assert!(object.get("total").is_some());
    }

    #[test]
    fn package_batch_drops_optional_detail_before_package_results() {
        let results = (0..20)
            .map(|index| {
                json!({
                    "package": format!("package-{index}"),
                    "summary": {"vulnerable": false},
                    "findings": ["x".repeat(500)],
                    "cve_risk": ["x".repeat(500)],
                })
            })
            .collect::<Vec<_>>();
        let value = json!({"coverage_notice": "coverage", "results": results});
        let shrunk = shrink_over_budget(&value, 2_000).expect("summary batch fits");
        let Value::Object(object) = shrunk else {
            panic!("object result")
        };
        let Value::Array(results) = object.get("results").expect("results") else {
            panic!("results array")
        };
        assert_eq!(results.len(), 20);
        assert_eq!(object.get("response_detail_reduced"), Some(&json!(true)));
        assert!(
            results
                .iter()
                .all(|item| matches!(item, Value::Object(item) if !item.contains_key("findings")))
        );
    }

    #[test]
    fn package_batch_drops_non_vulnerable_results_before_vulnerable_ones() {
        let results = (0..25)
            .map(|index| {
                json!({
                    "package": format!("package-{index}"),
                    "summary": {
                        "vulnerable": index < 5,
                        "padding": "x".repeat(100),
                    },
                })
            })
            .collect::<Vec<_>>();
        let value = json!({"coverage_notice": "coverage", "results": results});
        let shrunk = shrink_over_budget(&value, 1_000).expect("batch can be truncated");
        let Value::Object(object) = shrunk else {
            panic!("object result")
        };
        let Value::Array(results) = object.get("results").expect("results") else {
            panic!("results array")
        };
        assert!(results.len() < 25);
        assert!(results.iter().any(|item| matches!(item, Value::Object(item) if item.get("package") == Some(&json!("package-0")))));
        assert!(results.iter().all(|item| matches!(item, Value::Object(item) if matches!(item.get("summary"), Some(Value::Object(summary)) if summary.get("vulnerable") == Some(&json!(true))))));
    }
}
