<div align="center">
    <img src="./design/logo.svg" width="12%" height="12%" alt="qanvuli logo">
</div>

# qanvuli

qanvuli builds and searches a local vulnerability database. It combines CVE List data with CWE, CAPEC, OSV, CISA KEV, and FIRST EPSS in SQLite.

The project provides a CLI, terminal UI, Rust API, and MCP server. Searches run locally after the source feeds have been imported.

API documentation: [English](./docs/API.md) · [日本語](./docs/API.ja.md)

## Features

- Build a database from the complete CVE archive and selected enrichment feeds.
- Apply CVE deltas and incremental OSV updates.
- Search CVE records by identifier, text, affected product, CWE, CAPEC, CVSS, and date, and search OSV advisories by text.
- Evaluate package versions against supported OSV and CVE List ranges.
- Browse CVE, OSV, CWE, and CAPEC data in a terminal UI.
- Scan GitHub dependency graph exports and SPDX or CycloneDX SBOM JSON with local vulnerability data.
- Expose search, enrichment, and maintenance operations through MCP.

## Requirements

- A Rust toolchain with edition 2024 support.
- Network access for feed downloads.
- Enough temporary and database storage for the CVE archive.

The default database is `db.sqlite` in the current directory:

```text
sqlite://./db.sqlite?mode=rwc
```

Set another location with `--db-url` or `QANVULI_DB_URL`.

## Install

```bash
cargo install --path . --locked
qanvuli --help
```

For development:

```bash
cargo run -- --help
```

## Initialize and update

Build a replacement database from current feeds:

```bash
qanvuli init
```

Use an existing CVE archive or reduce peak disk use:

```bash
qanvuli init --zip ./data/all-cves.zip
qanvuli init --delete-existing
qanvuli init --no-progress
```

`init` normally builds a candidate beside the active database, checks its required schema and bounded search sentinels, and closes it before installation. Before moving the active database to a rollback backup, qanvuli checkpoints its WAL and refuses replacement if the database cannot be closed safely. A failed build leaves the active database unchanged. Run initialization while other SQLite users are stopped.

An archive supplied with `init --zip` is a user-owned local file and is never removed automatically. `--keep` applies only to the CVE archive downloaded automatically when `--zip` is omitted.

`--delete-existing` (`-D`) deletes stale `*.qanvuli-new-*` replacement candidates and the active database before downloading and building the replacement. This minimizes peak disk usage, but can disrupt another running initialization and any later failure leaves no usable database. Use it only after confirming no other `qanvuli init` is running.

Apply unapplied remote CVE deltas and refresh enrichment feeds:

```bash
qanvuli update
qanvuli update --osv-refresh-all
qanvuli update --no-progress
```

Import a local CVE archive instead:

```bash
qanvuli update --zip ./data/delta.zip
```

Without `--zip`, `update` refreshes CWE, CAPEC, the stored OSV selection, KEV, and EPSS after applying CVE deltas. With `--zip`, it imports only the supplied CVE archive. OSV is also refreshed only when OSV family flags are supplied; CWE, CAPEC, KEV, and EPSS are not refreshed in this mode.

An archive supplied with `update --zip` is user-owned and is preserved on both success and failure. For remote updates, `--keep` retains automatically downloaded CVE delta archives; otherwise they may be removed after successful processing.

Remote `update` is resumable, but it is not one atomic transaction spanning every remote source. Each successfully applied CVE delta and its cursor are retained even if a later CWE, CAPEC, OSV, KEV, or EPSS refresh fails. Run `qanvuli update` again to resume from the stored state; a failed update does not necessarily mean that no data changed.

`--osv-refresh-all` ignores the OSV cursor and upserts complete selected snapshots. Missing snapshot entries are not treated as deletions; withdrawn advisories remain available with their withdrawal timestamp.

`init` imports GHSA and OSV (OSS-Fuzz) by default. Add source families with flags such as `--osv-rustsec` or `--osv-pysec`, or select all families with `--osv-all`. `update` reuses the selection stored by `init` and extends it with any supplied family flags. Run `qanvuli init --help` for the complete list.

Download a CVE archive without changing the database:

```bash
qanvuli download-cve --kind delta --output-dir ./data
qanvuli download-cve --kind all --output-dir ./data
```

## Search

```bash
qanvuli search --text openssl --limit 20
qanvuli search --source osv --text openssl
qanvuli search --cwe CWE-79
qanvuli search --capec CAPEC-63
qanvuli search --vendor microsoft --product windows
qanvuli search --min-score 9.0 --severity CRITICAL
qanvuli search --cve CVE-2024-12345
```

Search or inspect the catalogs:

```bash
qanvuli cwe cross-site --status Stable
qanvuli cwe --id CWE-79 --detail
qanvuli capec phishing --type Standard
qanvuli capec --id CAPEC-98 --detail
```

Query cross-source data:

```bash
qanvuli query resolve --id CVE-2024-12345
qanvuli query enriched-cve --id CVE-2024-12345
qanvuli query package --ecosystem crates.io --name time --version 0.1.0
```

`query package` evaluates supported OSV ranges using ecosystem-specific version rules. Unsupported or ambiguous evaluations are returned for review instead of being counted as confirmed findings.

Use `--pretty` for indented JSON.

## Database maintenance

```bash
qanvuli db status
qanvuli db check
qanvuli db check --scan
qanvuli db check --full
qanvuli db rebuild-search
```

`db check` validates the schema and bounded search sentinels. `--scan` adds SQLite, foreign-key, FTS, and projection checks. `--full` runs the most expensive integrity scans.

Rebuild cross-source identifier links from imported OSV relations:

```bash
qanvuli graph rebuild
```

Database files are derived artifacts. Unsupported schemas are not patched in place; rebuild them with `qanvuli init`.

## Terminal UI

```bash
qanvuli tui
qanvuli tui openssl
```

Common keys:

- `Enter`: search
- `Tab`: change pane
- `/`: find in details
- `F1`: help
- `F2`: change search mode
- `F3`: advanced search
- `F4`: display settings or catalog filters
- `F5`: database maintenance
- `F8`: raw CVE or OSV JSON
- `F9`: CWE catalog
- `F10`: CAPEC catalog
- `Esc`: close a popup or leave the current mode
- `Ctrl-C`: quit

## CVSS calculator

Explain the metrics in a CVSS v2.0, v3.0, v3.1, or v4.0 vector and calculate its score and severity without a database:

```bash
qanvuli cvss 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L'
```

## SBOM search

```bash
qanvuli sbom ./sbom.json
qanvuli sbom --file ./sbom.json --per-package-limit 5
qanvuli sbom ./sbom.json --sarif-output ./qanvuli.sarif
```

`sbom` accepts GitHub dependency graph exports and SPDX or CycloneDX JSON. CycloneDX support includes top-level `components`, the root `metadata.component`, and components nested below either location. PURL-backed packages are evaluated against OSV and CVE List data with dedicated version handling for crates.io/Cargo, Go, GitHub Actions, Maven, npm, NuGet, PyPI, Pub, and RubyGems. Missing, unsupported, or ambiguous version schemes are returned for review instead of being counted as confirmed vulnerabilities. Name-only CVE matches are optional candidates and never count as confirmed vulnerabilities.

JSON remains on standard output. `--sarif-output <PATH>` additionally writes the same scan as SARIF 2.1.0 for vulnerability reporting and code-scanning integrations. SARIF findings refer to the SBOM file as a whole; exact component line locations within the JSON document are not currently preserved, so the output is not intended for precise source navigation.

## MCP server

```bash
qanvuli mcp
```

The stdio server exposes local CVE, CWE, CAPEC, OSV, KEV, and EPSS queries plus database updates. Package queries omit detailed match evidence by default; request evidence only when match details are needed.

MCP searches use four independent SQLite read connections by default so concurrent tool calls do not queue behind one slow query. Set `QANVULI_MCP_READ_CONNECTIONS` to a value from 1 through 8 to tune this for the available memory and storage throughput. Database updates remain exclusive.

The `analyze_cvss_vector` tool validates a complete version-prefixed CVSS v2.0, v3.0, v3.1, or v4.0 vector and returns its base score, base severity, and expanded metrics without querying the database.

Batch package queries and recent-update lists return compact, decision-preserving summaries by default. They retain vulnerability/review state and risk signals; request `verbosity="full"` only for selected packages or CVEs that need findings, CWE, CVSS vectors, or affected-version details.

OSV coverage is not a guarantee that a package has no CVEs. Check CVE List and vendor advisories for critical or end-of-life packages.

## Workspace

- `app/`: CLI and user-facing crates
- `collector/`: feed clients
- `core/`: Rust API available from this repository workspace or a source checkout
- `db/`: schema, imports, and queries
- `models/`: source data models
- `utils/`: archive, GitHub, logging, and time utilities

The Rust API is not prepared or intended for crates.io publication. Use its path crates from this repository workspace or a source checkout.
