use crate::common::error::mcp_error;
use qanvuli_db::{
    CveAffectedDetail, CveCvssDetail, CveCweDetail, CveSummary, CveSummaryWithDetail,
    cve_state_label,
};
use qanvuli_models::RawCveStatusRecord;
use rmcp::model::{CallToolResult, Content};
use simd_json::{OwnedValue as Value, json};

pub(crate) fn tool_result(value: Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let text = simd_json::to_string_pretty(&value)
        .map_err(|err| mcp_error(format!("failed to encode tool result: {err}")))?;
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

pub(crate) fn summaries_with_detail(cves: Vec<CveSummaryWithDetail>) -> Vec<Value> {
    cves.into_iter().map(summary_with_detail).collect()
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
