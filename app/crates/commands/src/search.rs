use super::common::{DEFAULT_LIMIT, DateFilter, connect_sqlx_db, print_json};
use qanvuli_core::database::{SqlxCveSearch, SqlxCvssSearch};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
enum SearchSource {
    #[default]
    Cve,
    Osv,
}

/// CLI arguments for `qanvuli search`.
#[derive(Debug, Default, clap::Args)]
pub struct Args {
    /// Select one vulnerability source; filters and pagination apply only to that source.
    #[arg(long, value_enum, default_value_t = SearchSource::Cve)]
    source: SearchSource,
    #[arg(long = "cve", value_name = "ID")]
    cve_id: Option<String>,
    #[arg(long, value_name = "QUERY")]
    text: Option<String>,
    #[arg(long)]
    vendor: Option<String>,
    #[arg(long)]
    vendor_exact: Option<String>,
    #[arg(long)]
    product: Option<String>,
    #[arg(long)]
    product_exact: Option<String>,
    #[arg(long)]
    component: Option<String>,
    #[arg(long)]
    exact: bool,
    #[arg(long = "cwe", value_name = "CWE_ID")]
    cwe_ids: Vec<String>,
    #[arg(long = "capec", value_name = "CAPEC_ID")]
    capec_ids: Vec<String>,
    #[arg(long)]
    min_score: Option<f64>,
    #[arg(long)]
    max_score: Option<f64>,
    #[arg(long)]
    severity: Option<String>,
    #[arg(long = "cvss-version")]
    cvss_version: Option<String>,
    #[arg(long)]
    published_since: Option<String>,
    #[arg(long, alias = "since")]
    updated_since: Option<String>,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long)]
    offset: Option<u64>,
    #[arg(long)]
    include_rejected: bool,
    #[arg(long)]
    enriched: bool,
}

impl Args {
    fn vendor_like(&self) -> Option<&str> {
        let vendor = option_text(self.vendor.as_deref());
        if self.exact && vendor.is_some() {
            None
        } else {
            vendor
        }
    }

    fn product_like(&self) -> Option<&str> {
        let product = option_text(self.product.as_deref());
        if self.exact && product.is_some() {
            None
        } else {
            product
        }
    }

    fn component_like(&self) -> Option<&str> {
        let component = option_text(self.component.as_deref());
        if self.exact && component.is_some() {
            None
        } else {
            component
        }
    }

    fn vendor_exact(&self) -> Option<&str> {
        option_text(self.vendor_exact.as_deref()).or_else(|| {
            if self.exact {
                option_text(self.vendor.as_deref())
            } else {
                None
            }
        })
    }

    fn product_exact(&self) -> Option<&str> {
        option_text(self.product_exact.as_deref()).or_else(|| {
            if self.exact {
                option_text(self.product.as_deref())
                    .or_else(|| option_text(self.component.as_deref()))
            } else {
                None
            }
        })
    }

    fn date_filter(&self) -> Result<DateFilter, String> {
        DateFilter::new(
            self.published_since.as_deref(),
            self.updated_since.as_deref(),
        )
    }
}

/// Runs a CVE search and prints raw, summary, or enriched JSON results.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_sqlx_db(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
    let limit = i64::try_from(args.limit.unwrap_or(DEFAULT_LIMIT)).unwrap_or(i64::MAX);
    let offset = i64::try_from(args.offset.unwrap_or_default()).unwrap_or(i64::MAX);
    if args.source == SearchSource::Osv {
        let query = args
            .text
            .as_deref()
            .ok_or_else(|| "OSV search requires --text".to_owned())?;
        if args.cve_id.is_some()
            || args.vendor.is_some()
            || args.vendor_exact.is_some()
            || args.product.is_some()
            || args.product_exact.is_some()
            || args.component.is_some()
            || args.exact
            || !args.cwe_ids.is_empty()
            || !args.capec_ids.is_empty()
            || args.min_score.is_some()
            || args.max_score.is_some()
            || args.severity.is_some()
            || args.cvss_version.is_some()
            || args.published_since.is_some()
            || args.updated_since.is_some()
            || args.include_rejected
            || args.enriched
        {
            return Err(
                "CVE-specific filters and --enriched are not supported with --source osv"
                    .to_owned(),
            );
        }
        let advisories = db
            .search_osv_paginated(query, limit, offset)
            .await
            .map_err(|error| format!("failed to search OSV advisories: {error}"))?;
        print_json(&advisories)?;
        db.close()
            .await
            .map_err(|error| format!("failed to close database: {error}"))?;
        return Ok(());
    }
    let date_filter = args.date_filter()?;
    if let Some(cve_id) = args.cve_id.as_deref() {
        let summary = db
            .find_cve_summary(cve_id)
            .await
            .map_err(|error| format!("failed to fetch CVE: {error}"))?;
        let output = if args.enriched {
            serde_json::json!({"summary": summary, "detail": db.cve_detail(cve_id).await.map_err(|error| format!("failed to fetch CVE detail: {error}"))?})
        } else {
            serde_json::to_value(summary)
                .map_err(|error| format!("failed to encode CVE: {error}"))?
        };
        print_json(&output)?;
        db.close()
            .await
            .map_err(|error| format!("failed to close database: {error}"))?;
        return Ok(());
    }
    let filters = SqlxCveSearch {
        text: args.text.clone(),
        cwe_ids: args.cwe_ids.clone(),
        capec_ids: args.capec_ids.clone(),
        vendor_like: args.vendor_like().map(|value| format!("%{value}%")),
        product_like: args
            .product_like()
            .or(args.component_like())
            .map(|value| format!("%{value}%")),
        vendor_exact: args.vendor_exact().map(ToOwned::to_owned),
        product_exact: args.product_exact().map(ToOwned::to_owned),
        cvss: SqlxCvssSearch {
            min_score: args.min_score,
            max_score: args.max_score,
            severity: args.severity.clone(),
            version: args.cvss_version.clone(),
        },
        published_since: date_filter.published_since,
        published_until: None,
        updated_since: date_filter.updated_since,
        updated_until: None,
        sort_order: Default::default(),
    };
    let cves = db
        .search_cves_advanced(filters, args.include_rejected, limit, offset)
        .await
        .map_err(|error| format!("failed to search CVEs: {error}"))?;
    if args.enriched {
        let cve_ids = cves
            .iter()
            .map(|summary| summary.cve_id.clone())
            .collect::<Vec<_>>();
        let details = db
            .cve_details(&cve_ids)
            .await
            .map_err(|error| format!("failed to fetch CVE details: {error}"))?;
        let enriched = cves
            .into_iter()
            .zip(details)
            .map(|(summary, detail)| serde_json::json!({"summary": summary, "detail": detail}))
            .collect::<Vec<_>>();
        print_json(&enriched)?;
    } else {
        print_json(&cves)?;
    }
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))?;
    Ok(())
}

fn option_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_flag_routes_vendor_and_product_to_exact_filters() {
        let args = Args {
            vendor: Some("Example Vendor".to_owned()),
            product: Some("Django".to_owned()),
            exact: true,
            ..Args::default()
        };
        assert_eq!(args.vendor_like(), None);
        assert_eq!(args.product_like(), None);
        assert_eq!(args.vendor_exact(), Some("Example Vendor"));
        assert_eq!(args.product_exact(), Some("Django"));
    }

    #[test]
    fn exact_flag_routes_component_to_product_exact_filter() {
        let args = Args {
            component: Some("django".to_owned()),
            exact: true,
            ..Args::default()
        };
        assert_eq!(args.component_like(), None);
        assert_eq!(args.product_exact(), Some("django"));
    }

    #[test]
    fn explicit_exact_filters_take_precedence_over_exact_flag() {
        let args = Args {
            vendor: Some("broad".to_owned()),
            vendor_exact: Some("exact".to_owned()),
            exact: true,
            ..Args::default()
        };
        assert_eq!(args.vendor_like(), None);
        assert_eq!(args.vendor_exact(), Some("exact"));
    }
}
