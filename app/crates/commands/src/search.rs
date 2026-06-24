use super::common::{DEFAULT_LIMIT, DateFilter, connect_db, print_json};
use qanvuli_db::CveStateScope;

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
    #[arg(long = "cwe", value_name = "CWE_ID")]
    cwe_ids: Vec<String>,
    #[arg(long)]
    min_score: Option<f64>,
    #[arg(long)]
    max_score: Option<f64>,
    #[arg(long)]
    severity: Option<String>,
    #[arg(long)]
    version: Option<String>,
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
}

impl Args {
    fn has_cvss_filter(&self) -> bool {
        self.min_score.is_some()
            || self.max_score.is_some()
            || self.severity.is_some()
            || self.version.is_some()
    }

    fn component_name(&self) -> Option<&str> {
        self.component
            .as_deref()
            .or(self.product.as_deref())
            .filter(|value| !value.is_empty())
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

    fn date_filter(&self) -> Result<DateFilter, String> {
        DateFilter::new(
            self.published_since.as_deref(),
            self.updated_since.as_deref(),
        )
    }
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    let date_filter = args.date_filter()?;

    if let Some(cve_id) = args.cve_id.as_deref() {
        let cve = db
            .find_cve_model_by_id(cve_id)
            .await
            .map_err(|err| format!("failed to fetch {cve_id}: {err}"))?;
        let cve = cve.map(|cve| cve.into_parts().1);
        print_json(&cve)?;
        db.close()
            .await
            .map_err(|err| format!("failed to close database: {err}"))?;
        return Ok(());
    }

    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = args.offset.unwrap_or(0);
    let state_scope = if args.include_rejected {
        CveStateScope::IncludeRejected
    } else {
        CveStateScope::PublishedOnly
    };
    let summaries = if let Some(query) = args.text.as_deref() {
        db.search_cve_summaries_by_text_with_state_scope(query, state_scope, limit, offset)
            .await
            .map_err(|err| format!("failed to search text: {err}"))?
    } else if !args.cwe_ids.is_empty() {
        db.search_cve_summaries_by_cwe_with_state_scope(&args.cwe_ids, state_scope, limit, offset)
            .await
            .map_err(|err| format!("failed to search CWE: {err}"))?
    } else if args.has_cvss_filter() {
        if args.has_affected_filter() {
            db.search_cve_summaries_by_product_cvss_exact_with_state_scope(
                args.vendor.as_deref(),
                args.product.as_deref().or(args.component.as_deref()),
                args.vendor_exact.as_deref(),
                args.product_exact.as_deref(),
                args.min_score,
                args.max_score,
                args.severity.as_deref(),
                args.version.as_deref(),
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
                args.version.as_deref(),
                state_scope,
                limit,
                offset,
            )
            .await
            .map_err(|err| format!("failed to search CVSS: {err}"))?
        }
    } else if args.has_affected_filter() {
        if let Some(component) = args.component_name().or(args.product_exact.as_deref()) {
            db.search_cve_summaries_by_affected_component_exact_with_state_scope(
                args.vendor.as_deref(),
                component,
                args.vendor_exact.as_deref(),
                args.product_exact.as_deref(),
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
                args.vendor.as_deref(),
                args.product.as_deref(),
                args.vendor_exact.as_deref(),
                args.product_exact.as_deref(),
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

    print_json(&summaries)?;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
