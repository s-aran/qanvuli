# `qanvuli-core` API guide

[日本語](./API_J.md)

This document covers only the public Rust API exported by the `qanvuli-core`
crate. The command-line interface, TUI, and MCP server are applications built on
top of this API and are intentionally outside this guide.

`qanvuli-core` is a facade over qanvuli's database, feed collectors, and source
models. Its public API is split into four modules:

| Module | Responsibility |
| --- | --- |
| `qanvuli_core::database` | SQLite lifecycle, CVE/OSV queries, package evaluation, enrichment, imports, and safe database replacement. |
| `qanvuli_core::ingest` | Downloading CVE, CWE, CAPEC, OSV, KEV, and EPSS source data and reading CVE archives. |
| `qanvuli_core::model` | Source-level CVE, CWE, CAPEC, and OSV model types and catalog parsers. |
| `qanvuli_core::runtime` | One-time process setup required before using network clients. |

The crate is currently consumed from this workspace or a source checkout. It is
not yet a semver-stable crates.io API.

## Adding the crate

Use the `core` directory as a path dependency:

```toml
[dependencies]
qanvuli-core = { path = "../qanvuli/core" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The Rust package name contains a hyphen, while its import name uses an
underscore: `qanvuli_core`.

## Database API

### Connection lifecycle

`CveDatabase` is the preferred name for the database handle. It is a type alias
of the also-public `SqlxDatabase`.

```rust
use qanvuli_core::database::CveDatabase;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = CveDatabase::connect("sqlite://./db.sqlite?mode=rwc").await?;
    db.check_required_schema().await?;

    // Queries go here.

    db.close().await?;
    Ok(())
}
```

| Method | Use |
| --- | --- |
| `CveDatabase::connect(url)` | Open a SQLite-backed database handle. Connecting does not validate qanvuli's schema. |
| `initialize()` / `initialize_schema()` | Create or migrate the schema. `initialize_schema` is the compatibility name for `initialize`. |
| `check_required_schema()` | Verify that an existing database has the schema required by the current library. Call this before querying a user-selected database. |
| `schema_version()` | Return the schema version expected by this library build. This is an associated function and does not open a database. |
| `close()` | Close the writer connection. This consumes the handle. |

Most database methods return `Result<_, sqlx::Error>`. Although the concrete
error type comes from the underlying database crate, callers can use `?`
without importing `sqlx` when their enclosing error type accepts standard
errors, as in the example above.

### CVE result types

The high-level types contain public vulnerability identifiers and normalized
content; they do not expose SQLite row IDs.

| Type | Contents |
| --- | --- |
| `CveSummary` | CVE ID, state, publication/update timestamps, title, and optional English description. |
| `CveDetail` | `cwes`, `cvss`, `affected`, and `ssvc` collections. |
| `CveSummaryWithDetail` | A `CveSummary` paired with `CveDetail`. |
| `CveCweDetail` | Numeric CWE ID and optional description. |
| `CveCvssDetail` | CVSS version, base score, severity, vector, and source. |
| `CveAffectedDetail` | Vendor, product, package name, descriptive metadata, and affected versions. |
| `CveAffectedVersionDetail` | Version, status, version type, and upper bounds. |
| `CveReference` | Reference URL, name, and tags. |
| `CveRiskSummary` | Compact KEV, EPSS, and maximum-CVSS signals for triage. |
| `SsvcInfo` | One imported SSVC assessment, including its provider, role, version, assessment time, and decision points. |

`CveSummary.state` is numeric in memory. Use `cve_state_label(state)` to obtain
`"PUBLISHED"`, `"REJECTED"`, or `"UNKNOWN"`. Its `Serialize` implementation
also emits the readable label.

The `Sqlx*` types are lower-level database projections. They are public for
callers that need the exact stored representation:

- `SqlxCveSummary`, `SqlxCveDetail`, and `SqlxCveSummaryWithDetail`
- `SqlxCwe`, `SqlxCvss`, and `SqlxAffected`
- `SqlxCveReference`, `SqlxEpss`, `SqlxEpssRisk`, `SqlxKev`, and
  `SqlxKevEntry`
- `SqlxOsvSummary`, `SqlxDatabaseStatus`, `SqlxSourceSyncState`,
  `SqlxIdentifierResolution`, `SqlxIdentifierEdge`, and `SqlxPackageFinding`

Prefer the high-level types unless preserving the SQL projection is part of the
integration contract.

### Looking up CVEs

| Method | Result |
| --- | --- |
| `find_cve_summary(cve_id)` | One lightweight `SqlxCveSummary`, if present. |
| `find_cve_summary_with_detail(cve_id)` | One high-level `CveSummaryWithDetail`. |
| `find_cve_summary_with_detail_with_state_scope(cve_id, scope)` | The same lookup with explicit rejected-record visibility. |
| `cve_summaries_with_details_batch(ids, scope)` | Batch lookup preserving the requested ID order, with `None` for missing or hidden records. |
| `find_cve_raw_json_by_id(cve_id)` / `cve_raw_json(cve_id)` | Original stored CVE JSON. |
| `find_cve_model_by_id(cve_id)` | Parsed `RawCveStatusRecord` plus the original JSON value. |
| `find_cve_references(cve_id)` | Normalized references for one CVE. |

Use raw JSON only when provider-specific fields are required. The summary and
detail DTOs are smaller and keep callers independent of the complete CVE schema.

### Searching CVEs

The high-level search methods all accept an explicit row limit and offset.
Methods ending in `_with_state_scope` also accept `CveStateScope`:

```rust
use qanvuli_core::database::{CveDatabase, CveStateScope};

async fn search(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let rows = db
        .search_cve_summaries_free_text_with_state_scope(
            "openssl",
            CveStateScope::PublishedOnly,
            25,
            0,
        )
        .await?;

    for row in rows {
        println!("{} — {}", row.cve_id, row.title);
    }
    Ok(())
}
```

`CveStateScope::PublishedOnly` is the default and safest scope.
`CveStateScope::IncludeRejected` should be chosen deliberately.
`CveStateScope::from_include_rejected(bool)` is useful at an application
boundary.

| Method | Search contract |
| --- | --- |
| `search_cve_summaries_free_text_with_state_scope` | FTS over CVE ID, title, English description, affected text, and indexed reference text. Results use relevance order. |
| `search_cve_summaries_by_cwe_with_state_scope` | Any supplied CWE ID. IDs may be numeric or use the optional `CWE-` prefix. |
| `search_cve_summaries_by_vendor_product_with_state_scope` | Substring search over normalized affected vendor and product/package fields. |
| `search_cve_summaries_by_vendor_product_exact_with_state_scope` | Exact or substring affected-field search, with optional WordPress collection exclusion. |
| `search_cve_summaries_by_cvss_with_state_scope` | Inclusive score bounds plus optional severity and CVSS version. Matching CVSS constraints apply to the same metric row. |
| `search_cve_summaries_by_product_cvss_exact_with_state_scope` | Affected-field and CVSS filters combined with AND; ordered by highest matching score. |
| `search_cve_summaries_by_date_with_state_scope` | Inclusive publication/update lower bounds. |
| `search_cve_summaries_by_cve_id_prefix_with_state_scope` | CVE ID prefix search. |
| `search_cve_summaries_by_reference_text` | Reference URL, name, and tag search. |
| `search_cve_summaries_by_date_range` | Inclusive publication and update ranges. |
| `list_recent_updates` | CVEs updated on or after an optional timestamp. |

Most families also have a matching `count_*` method for pagination metadata.
Use the same scope and filters for the page and count calls.

Vendor and product searches are structural searches. A word present only in a
title or description does not satisfy an affected vendor/product filter. Use a
free-text method when prose is the intended source of a match.

In `search_cve_summaries_by_vendor_product_exact_with_state_scope`, an exact
value replaces the substring value for the same dimension. Supplying either
exact argument switches every supplied affected dimension in that call to
exact comparison. When filtering vendor and product together, use both
substring arguments or both exact arguments.

### Composed searches

`CveAdvancedSearch` provides one typed request instead of a long positional
argument list:

```rust
use qanvuli_core::database::{
    CveAdvancedQueryMode, CveAdvancedSearch, CveDatabase, CveStateScope,
    CveSummarySortOrder,
};

async fn products(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let request = CveAdvancedSearch {
        query: Some("openssl".to_owned()),
        query_mode: Some(CveAdvancedQueryMode::Product),
        published_from: Some("2025-01-01T00:00:00Z".to_owned()),
        state_scope: CveStateScope::PublishedOnly,
        sort_order: CveSummarySortOrder::UpdatedDesc,
        ..Default::default()
    };

    let rows = db.search_cve_summaries_advanced(&request, 25, 0).await?;
    Ok(())
}
```

`CveAdvancedQueryMode` controls only the `query` field:

| Mode | Meaning of `query` |
| --- | --- |
| `FreeText` | CVE full-text query. |
| `Product` | Substring match on normalized affected product. |
| `Vendor` | Substring match on normalized affected vendor. |
| `Cwe` | CWE ID. |
| `Cve` | CVE ID prefix. |

The remaining `CveAdvancedSearch` fields are independent AND filters:
publication bounds, CWE, product, vendor, KEV-only scope, SSVC decision
points, record state, and sort order. `product_exact` and `vendor_exact` are
mutually meaningful alternatives to their substring counterparts; avoid
supplying both forms for the same field.

`package_ecosystem` and `package_version` are request metadata used by
higher-level application orchestration. `search_cve_summaries_advanced` itself
does not evaluate an installed package version. Use `query_package_matches` or
`query_package_matches_batch` for version-aware matching.

For lower-level integrations, `SqlxCveSearch` and `SqlxCvssSearch` expose the
database query shape directly. `SqlxAffectedComponentSearch` is the bounded
filter used by the name-based CVE fallback in package searches. Values in
`vendor_like` and `product_like` are SQL LIKE patterns, so a substring caller
supplies a value such as `"%openssl%"`. Prefer `CveAdvancedSearch` when
exposing user input.

### SSVC assessments

SSVC assessments embedded in CVE ADP containers are extracted automatically
when CVE records are imported. They are available in `CveDetail.ssvc` and
`SqlxCveDetail.ssvc`; `ssvc_assessments(cve_id)` provides a direct lookup, and
`ssvc_assessment_count()` returns the total number of stored assessments.

The public decision-point enums and their values are:

| Type | Variants and string values |
| --- | --- |
| `SsvcExploitation` | `None` (`"none"`), `PublicPoc` (`"poc"`), `Active` (`"active"`) |
| `SsvcAutomatable` | `No` (`"no"`), `Yes` (`"yes"`) |
| `SsvcTechnicalImpact` | `Partial` (`"partial"`), `Total` (`"total"`) |

Each enum implements `Display`, `FromStr`, and `Serialize`. Use the
`ssvc_exploitation`, `ssvc_automatable`, and `ssvc_technical_impact` fields on
`CveAdvancedSearch` to filter CVEs. Supplied decision points are combined with
AND and must occur on the same stored assessment. `SsvcSearch` exposes the
same filter shape to callers using `SqlxCveSearch` directly.

### Sorting

`CveSummarySortOrder` is honored by advanced searches, explicit-ID sorted
lookups, and sorted OSV methods.

| Variant family | Behavior |
| --- | --- |
| `PublishedAsc` / `PublishedDesc` | Publication timestamp, then a deterministic identifier key. |
| `UpdatedAsc` / `UpdatedDesc` | Update timestamp, then a deterministic identifier key. |
| `CveIdAsc` / `CveIdDesc` | Natural CVE order: year and variable-width sequence are numeric, so `CVE-2099-9999` sorts before `CVE-2099-10000` ascending. OSV IDs use lexical order. |
| `RelationRankAsc` / `RelationRankDesc` | Relevance or caller-provided graph order when available; deterministic date/ID fallback otherwise. |
| `ScoreAsc` / `ScoreDesc` | Maximum stored CVSS base score for CVEs; missing scores stay last. OSV rows fall back to ID because an OSV summary has no CVSS column. |

Equal dates and scores have stable secondary keys, so offset pagination does not
randomly reshuffle tied rows. OSV records without a publication timestamp stay
last in both publication directions.

### OSV queries

`OsvSummary` is the high-level advisory DTO. It contains the OSV ID, schema
version, publication/modification/withdrawal timestamps, summary, details, and
a compact package summary. `OsvRawRecord` is the import input containing raw
JSON and an optional source path.

| Method | Purpose |
| --- | --- |
| `search_osv_summaries_free_text(query, limit, offset)` | Search advisory ID, text, aliases, ecosystems, package names, and purls. |
| `search_osv_summaries_free_text_sorted(...)` | The same search with `CveSummarySortOrder`. |
| `osv_summaries_by_ids_sorted(...)` | Load an explicit OSV ID set in a chosen order. |
| `search_osv_summaries_by_package(query, limit, offset)` | Match one normalized OSV package identity exactly. |
| `search_osv_summaries_scoped*` | Combine optional advisory-family and ecosystem scopes with text or exact/substring package matching. |
| `find_enriched_osv(osv_id)` / `find_osv_summary(osv_id)` | Look up one advisory summary. |
| `find_osv_raw_json_by_id(osv_id)` | Return original OSV JSON. |
| `osv_summaries_for_cve_ids(cve_ids)` | Follow OSV aliases from CVE IDs. |
| `cve_aliases_for_osv_ids(osv_ids, scope)` | Follow aliases in the other direction. |
| `osv_advisory_families()` | List imported advisory families. |

OSV has no normalized vendor field. Consumers should not reinterpret arbitrary
OSV prose as a vendor match.

### CWE and CAPEC catalogs

`CweEntry` is a compact weakness row with hierarchy counts and related CAPEC
IDs. `CapecEntry` is the corresponding attack-pattern summary.

| Method | Purpose |
| --- | --- |
| `find_cwe_entry(id)` | Load a compact CWE entry. |
| `search_cwe_entries(query, limit)` | Search CWE IDs and descriptions. |
| `search_cwe_entries_filtered(query, limit, statuses, capec_id)` | Add status and related-CAPEC filters. |
| `search_capec_entries(CapecSearchFilters)` | Search CAPEC text with optional status, abstraction type, and CWE filters. |
| `find_capec(id)` | Load a `CapecDetail`. |

`CapecSearchFilters` contains `query`, `statuses`, `types`, `cwe_id`, `limit`,
and `offset`. CAPEC output is split into reusable structures:

- `CapecEntry`, `CapecDetail`
- `CapecCategory`, `CapecCategoryDetail`
- `CapecView`, `CapecViewDetail`
- `CapecReference`, `CapecHistory`, `CapecNote`, and `CapecTaxonomyMapping`

### Identifier, enrichment, and risk queries

| Function or method | Purpose |
| --- | --- |
| `detect_identifier_type(value)` | Classify a CVE or OSV-family identifier without querying the database. |
| `resolve_identifier(id)` | Resolve CVE, GHSA, RUSTSEC, PYSEC, GO, and other stored aliases through the local graph. |
| `related_edges(id)` / `identifier_edges(id)` | Return graph edges and evidence. |
| `get_enriched_cve(cve_id)` | Join CVE detail with OSV aliases/packages, KEV, EPSS, SSVC, and source freshness. |
| `enriched_cve_summaries(cve_ids)` | Batch compact enrichment, including the latest SSVC decision points, for CVE lists. |
| `cve_risk_summaries(cve_ids)` | Batch KEV, EPSS, and maximum-CVSS triage rows. |
| `search_cve_risk_by_epss(...)` | Search by EPSS score/percentile with KEV context. |
| `kev_entries(...)` / `kev_entries_count()` | Read locally imported CISA KEV rows. |
| `database_status()` / `database_status_enriched()` | Read base or cross-source database status; the enriched status includes the SSVC assessment count. |
| `source_sync_states()` | Read per-source cursor and synchronization state. |

The exported response types used most often here are `EnrichedCveSummary`,
`CveRiskSummary`, `Evidence`, `PrioritySignals`, and `FindingEnrichment`.

### Package identity and version matching

For one installed package, call `query_package_matches`:

```rust
use qanvuli_core::database::CveDatabase;

async fn check_package(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let findings = db
        .query_package_matches("crates.io", "time", "0.1.0", None)
        .await?;

    for finding in findings {
        println!(
            "{}: {} ({})",
            finding.primary_id,
            finding.affected.status,
            finding.affected.confidence
        );
    }
    Ok(())
}
```

`query_package_matches_batch(&[PackageQuery])` is the bounded batch form.
`query_package_enriched_with_evidence` returns findings for one package with
KEV, EPSS, derived priority signals, and optional detailed evidence. CVE List
package joins ignore case and common `-`, `_`, `.`, and whitespace separators.
`has_osv_package_advisory` and its batch form check
whether the local OSV corpus covers a package identity without evaluating a
particular version.

`EnrichedFinding` keeps uncertainty explicit:

- `source` and `primary_id` identify the originating CVE List or OSV record.
- `package` echoes the `PackageQuery`.
- `affected: AffectedStatus` carries a status and confidence.
- `fixed_versions` and `FindingEnrichment` add remediation and KEV/EPSS data.
- `PrioritySignals` contains derived triage hints.
- `Evidence` explains why the package, advisory, and aliases were linked.

An unsupported or ambiguous comparison is not promoted to a confirmed
affected result.

The database module also exports pure identity helpers:

| Function | Purpose |
| --- | --- |
| `normalize_package_name(ecosystem, name)` | Apply ecosystem-specific package-name identity rules. |
| `ecosystem_identity_key(ecosystem)` | Build the canonical, case-aware ecosystem key. |
| `versions_equivalent(ecosystem, left, right)` | Compare two explicitly enumerated versions. |
| `is_concrete_package_version(ecosystem, version)` | Reject constraints and unsupported installed-version strings. |
| `parse_package_purl(purl)` | Parse a supported purl into `ParsedPackagePurl`. |
| `package_identity_purl(purl)` | Return a canonical versionless purl, preserving unsupported input unchanged. |
| `evaluate_sqlx_osv_version(ecosystem, installed, ranges)` | Evaluate `SqlxOsvRange` values and return `SqlxVersionMatch`. |

Specialized policies exist for crates.io/Cargo, GitHub Actions, Go, Maven, npm,
NuGet, PyPI, Pub, and RubyGems. Unknown ecosystems use a strict fallback rather
than guessing version semantics.

### Imports and maintenance

The database handle exposes imports at several levels:

| Area | Methods |
| --- | --- |
| CVE JSON | `import_cve_raw_json`, `import_cve_raw_jsons`, deferred-search variants, and `import_cve_raw_jsons_bulk_init` |
| OSV JSON | `import_osv_record`, `import_osv_records`, deferred/incremental/bulk variants |
| CWE/CAPEC | `upsert_cwe_catalog`, `replace_capec_catalog` |
| KEV/EPSS | `import_kev_json`, `import_kev_json_with_status`, `import_epss_csv`, `import_epss_csv_with_status` |

`OsvImportStats` reports `examined`, `inserted`, `updated`, and `unchanged`;
`changed()` returns inserted plus updated. `ImportSummary` is the compact
cross-source import summary.

Bulk APIs deliberately separate data loading from index maintenance:

- `prepare_cve_bulk_load` / `finish_cve_bulk_load`
- `prepare_osv_bulk_load` / `finish_osv_bulk_load`
- `rebuild_cve_search`, `rebuild_osv_search`, and `rebuild_search`
- `refresh_cve_search_for_ids`
- `rebuild_identifier_graph`

Do not leave a database between a `prepare_*` and `finish_*` call. Search
indexes may intentionally be incomplete during that interval.

Integrity checks have explicit cost levels:

| Method | Coverage |
| --- | --- |
| `check()` | Required schema plus bounded search sentinels. |
| `check_scan()` | SQLite quick check, foreign-key correspondence, and broader search scans. |
| `check_full_sqlite()` | SQLite integrity check. |
| `check_full_foreign_keys()` | Complete foreign-key verification. |
| `check_full_cve_search()` / `check_full_osv_search()` | Complete search-projection verification. |

## Safe database replacement

The replacement API installs a fully built, closed, and prevalidated SQLite
candidate beside the active database.

| Item | Purpose |
| --- | --- |
| `candidate_database_path(target)` | Create a unique candidate path in the target directory. |
| `DatabaseReplacement::new(target, candidate)` | Prepare a same-directory replacement transaction. |
| `install()` | Checkpoint and close the target, move it to a rollback backup, and install the candidate. |
| `rollback()` | Restore a pending backup before candidate installation has completed. It is state-specific; a successfully installed replacement proceeds to `commit()`. |
| `commit()` | Remove the backup after a successful install. |
| `backup_path()` | Inspect the generated backup path. |
| `recover_interrupted_replacement(target)` | Apply the bounded recovery policy and return `RecoveryAction` values. |
| `remove_sqlite_database_files(path)` | Remove one SQLite main file and its WAL/SHM/journal sidecars. |
| `remove_interrupted_replacement_candidates(target)` | Remove qanvuli-named candidate files. This requires caller confirmation because another process may own them. |

Failures are represented by `ReplacementError`. Ambiguous states are reported
for manual inspection instead of choosing a file destructively.

## Ingest API

Call `runtime::init_tls_provider()` once near process startup before using the
network-backed collectors. The function is idempotent.

```rust
use qanvuli_core::{
    ingest::CveRelease,
    runtime::init_tls_provider,
};

async fn newest_cve_archive() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tls_provider();

    let mut releases = CveRelease::new();
    releases.refresh().await?;
    if let Some(asset) = releases.latest_full_asset() {
        println!("{} ({} bytes)", asset.name, asset.size);
    }
    Ok(())
}
```

### Feed collectors

| Item | Purpose |
| --- | --- |
| `CveRelease` | Refresh CVEProject GitHub releases and select full, delta, end-of-day, or cursor-relative assets. |
| `GitHubReleaseFile` | Release-asset metadata plus async/blocking byte and file download methods. `safe_file_name()` validates an asset name before using it locally. |
| `CweCatalogFile` | Conditional CWE catalog download using ETag and Last-Modified state. |
| `CapecCatalogFile` | Conditional CAPEC catalog download to a caller-selected path. |
| `OsvGcsSource` | Public OSV bucket client for `all.zip`, source-family zips, `modified_id.csv`, and individual advisory JSON. |
| `OsvDownloadError` | Distinguishes local storage failures from network/response failures; `is_local_storage()` supports fallback decisions. |
| `OsvModifiedId` / `parse_modified_id_csv` | Parsed OSV incremental cursor rows. |
| `download_kev_json()` | Download the current CISA KEV JSON as a string. |
| `download_epss_current_csv()` | Download and decompress the current FIRST EPSS CSV as a string. |
| `OSV_ALL_ZIP` | The public OSV all-archive object name. |

### Archive readers

`JsonStorage` is the common interface for CVE JSON sources. It provides
`read_bytes`, `read_entry`, `read_string`, `paths`, and `entries`.

`ZipStorage::new(path)` opens a CVE archive and also handles the supported
nested-zip layout. `JsonEntry` identifies an archive entry. For large nested
archives, `ZipStorage` may use a temporary extraction directory; inspect it
with `extracted_dir()`, preserve it with `retain_extracted_dir()`, or clean it
explicitly with `cleanup_extracted_dir()`.

## Source model and CVSS API

The `model` module exports source-level models, catalog parsers, and CVSS
vector utilities:

| Item | Purpose |
| --- | --- |
| `RawCveStatusRecord` | A parsed published/rejected CVE value paired with its original JSON value. |
| `WeaknessCatalog` | Complete MITRE CWE catalog model. |
| `AttackPatternCatalog` | Complete MITRE CAPEC catalog model. |
| `read_cwe_catalog_zip(path)` | Read and parse the XML contained in a CWE zip. |
| `read_capec_catalog_xml(path)` | Read and parse a CAPEC XML file. |
| `OSV_DATABASE_SOURCE_PREFIXES` | Known OSV source-database prefixes. |
| `is_known_osv_database_prefix(prefix)` | Case-insensitive validation for an OSV source prefix. |
| `score_cvss_vector(vector)` | Validate a CVSS v2.0, v3.0, v3.1, or v4.0 vector and calculate its base score and severity. |
| `explain_cvss_vector(version, vector)` | Expand vector abbreviations into display-oriented metric names and values. |

```rust
use qanvuli_core::model::{explain_cvss_vector, score_cvss_vector};

fn inspect_vector() -> Result<(), String> {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L";
    let score = score_cvss_vector(vector)?;
    println!("CVSS {}: {} {}", score.version, score.score, score.severity);

    for metric in explain_cvss_vector(&score.version, vector) {
        println!("{}: {}", metric.name, metric.value);
    }
    Ok(())
}
```

`score_cvss_vector` returns `CvssScore` and rejects unsupported versions,
malformed vectors, missing required metrics, and duplicate metrics. A CVSS
v2.0 vector may omit the `CVSS:2.0/` header; later versions require a header.

`explain_cvss_vector` returns `Vec<CvssVectorMetric>` for presentation. A
version declared in the vector takes precedence over its `version` argument;
the argument is the fallback for headerless vectors. This function does not
validate or score the vector: unknown metric names and values are retained as
their raw text.

The source models are not compact database DTOs. Use them for ingestion and
catalog transformation; use `CveSummary`, `CweEntry`, and `CapecEntry` for
normal query responses.

## API design notes

- Prefer `CveDatabase`, high-level summary/detail DTOs, and typed option
  structures in new code. The `Sqlx*` surface exists for integrations that need
  the underlying projection.
- Treat `limit` and `offset` as part of every list-query contract. Choose a
  deterministic sort order before paging.
- An empty OSV package result describes only the locally imported OSV corpus;
  it is not proof that no CVE or vendor advisory exists.
- Database files are derived artifacts. Rebuild an incompatible schema rather
  than modifying qanvuli's tables directly.
