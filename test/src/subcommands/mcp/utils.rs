use qanvuli_db::{CveStateScope, CveSummary, cve_state_label};
use qanvuli_models::RawCveStatusRecord;
use simd_json::{OwnedValue as Value, json};

pub(crate) fn limit(value: Option<u64>) -> u64 {
    value.unwrap_or(10).clamp(1, 30)
}

pub(crate) fn offset(value: Option<u64>) -> u64 {
    value.unwrap_or(0)
}

pub(crate) fn state_scope(include_rejected: Option<bool>) -> CveStateScope {
    if include_rejected.unwrap_or(false) {
        CveStateScope::IncludeRejected
    } else {
        CveStateScope::PublishedOnly
    }
}

pub(crate) fn summaries(cves: Vec<CveSummary>) -> Vec<Value> {
    cves.into_iter().map(summary).collect()
}

pub(crate) fn summary(cve: CveSummary) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve_state_label(cve.state),
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "title": cve.title,
        "description_preview": cve.description_en.as_deref().map(preview),
    })
}

pub(crate) fn full_cve(cve: RawCveStatusRecord) -> Value {
    cve.into_parts()
        .1
        .try_into()
        .unwrap_or_else(|_| Value::Static(simd_json::StaticNode::Null))
}

pub(crate) fn preview(value: &str) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let max_chars = 500;

    if compact.chars().count() <= max_chars {
        compact
    } else {
        let mut truncated = compact.chars().take(max_chars).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}
