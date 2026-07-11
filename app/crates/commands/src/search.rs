use super::common::{DEFAULT_LIMIT, DateFilter, close_db, connect_db, print_json};
use qanvuli_db::{CveStateScope, detect_identifier_type};

/// CLI arguments for `qanvuli search`.
#[derive(Debug, Default, clap::Args)]
pub struct Args {
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
    fn has_cvss_filter(&self) -> bool {
        self.min_score.is_some()
            || self.max_score.is_some()
            || self.severity.is_some()
            || self.cvss_version.is_some()
    }

    fn has_affected_filter(&self) -> bool {
        self.vendor
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || self
                .product
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            || self
                .vendor_exact
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            || self
                .product_exact
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            || self
                .component
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }

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
    let db = connect_db(db_url).await?;
    let date_filter = args.date_filter()?;

    if args.enriched
        && let Some(query) = args.text.as_deref()
        && detect_identifier_type(query) != "other"
    {
        let resolution = db
            .resolve_identifier(query)
            .await
            .map_err(|err| format!("failed to resolve {query}: {err}"))?;
        let mut results = Vec::with_capacity(resolution.related_cve_ids.len());
        for cve_id in &resolution.related_cve_ids {
            results.push(
                db.get_enriched_cve(cve_id)
                    .await
                    .map_err(|err| format!("failed to enrich {cve_id}: {err}"))?,
            );
        }
        print_json(&serde_json::json!({
            "resolution": resolution,
            "results": results,
        }))?;
        close_db(db).await?;
        return Ok(());
    }

    if let Some(cve_id) = args.cve_id.as_deref() {
        if args.enriched {
            let cve = db
                .get_enriched_cve(cve_id)
                .await
                .map_err(|err| format!("failed to fetch enriched {cve_id}: {err}"))?;
            print_json(&cve)?;
        } else {
            let cve = db
                .find_cve_model_by_id(cve_id)
                .await
                .map_err(|err| format!("failed to fetch {cve_id}: {err}"))?;
            let cve = cve.map(|cve| cve.into_parts().1);
            print_json(&cve)?;
        }
        close_db(db).await?;
        return Ok(());
    }

    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = args.offset.unwrap_or(0);
    let state_scope = CveStateScope::from_include_rejected(args.include_rejected);
    let vendor = args.vendor_like();
    let product = args.product_like();
    let component = args.component_like();
    let vendor_exact = args.vendor_exact();
    let product_exact = args.product_exact();
    let summaries = if let Some(query) = args.text.as_deref() {
        db.search_cve_summaries_free_text_with_state_scope(query, state_scope, limit, offset)
            .await
            .map_err(|err| format!("failed to search free text: {err}"))?
    } else if !args.cwe_ids.is_empty() {
        db.search_cve_summaries_by_cwe_with_state_scope(&args.cwe_ids, state_scope, limit, offset)
            .await
            .map_err(|err| format!("failed to search CWE: {err}"))?
    } else if args.has_cvss_filter() {
        if args.has_affected_filter() {
            db.search_cve_summaries_by_product_cvss_exact_with_state_scope(
                vendor,
                product.or(component),
                vendor_exact,
                product_exact,
                args.min_score,
                args.max_score,
                args.severity.as_deref(),
                args.cvss_version.as_deref(),
                state_scope,
                limit,
                offset,
            )
            .await
            .map_err(|err| format!("failed to search affected CVSS: {err}"))?
        } else {
            db.search_cve_summaries_by_cvss_with_state_scope(
                args.min_score,
                args.max_score,
                args.severity.as_deref(),
                args.cvss_version.as_deref(),
                state_scope,
                limit,
                offset,
            )
            .await
            .map_err(|err| format!("failed to search CVSS: {err}"))?
        }
    } else if args.has_affected_filter() {
        if let Some(component) = args
            .component_like()
            .filter(|value| !value.is_empty())
            .or(product_exact)
        {
            db.search_cve_summaries_by_affected_component_exact_with_state_scope(
                vendor,
                component,
                vendor_exact,
                product_exact,
                date_filter.published_since.as_deref(),
                date_filter.updated_since.as_deref(),
                state_scope,
                limit,
                offset,
            )
            .await
            .map_err(|err| format!("failed to search affected component: {err}"))?
        } else {
            db.search_cve_summaries_by_vendor_product_exact_date_with_state_scope(
                vendor,
                product,
                vendor_exact,
                product_exact,
                date_filter.published_since.as_deref(),
                date_filter.updated_since.as_deref(),
                state_scope,
                limit,
                offset,
            )
            .await
            .map_err(|err| format!("failed to search affected vendor/product: {err}"))?
        }
    } else {
        db.search_cve_summaries_by_date_with_state_scope(
            date_filter.published_since.as_deref(),
            date_filter.updated_since.as_deref(),
            state_scope,
            limit,
            offset,
        )
        .await
        .map_err(|err| format!("failed to search by date: {err}"))?
    };

    if let Some(query) = args.text.as_deref() {
        let osv_advisories = db
            .search_osv_summaries_free_text(query, limit, offset)
            .await
            .map_err(|err| format!("failed to search OSV advisories: {err}"))?;
        if args.enriched {
            let enriched = db
                .enrich_cve_summaries_full(summaries)
                .await
                .map_err(|err| format!("failed to enrich search results: {err}"))?;
            print_json(&serde_json::json!({
                "cves": enriched,
                "osv_advisories": osv_advisories,
            }))?;
        } else {
            print_json(&serde_json::json!({
                "cves": summaries,
                "osv_advisories": osv_advisories,
            }))?;
        }
        close_db(db).await?;
        return Ok(());
    }

    if args.enriched {
        let enriched = db
            .enrich_cve_summaries_full(summaries)
            .await
            .map_err(|err| format!("failed to enrich search results: {err}"))?;
        print_json(&enriched)?;
    } else {
        print_json(&summaries)?;
    }
    close_db(db).await?;
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
