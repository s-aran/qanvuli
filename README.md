<div align="center">
    <img src="./design/logo.svg" width="12%" height="12%">
</div>

# qanvuli

qanvuli is a local CVE database maintenance and search tool.

It imports CVE JSON archives into a local SQLite database, applies delta updates, searches CVE records from the command line, opens an interactive TUI, and can run as an MCP server over stdio.

## Features

- Initialize a local CVE database from the all-CVE archive.
- Apply CVE delta updates.
- Search by CVE ID, text, vendor/product, component, CWE, CVSS, and date.
- Inspect results in an interactive terminal UI.
- Show raw CVE JSON from the TUI when needed.
- Search CVEs for packages in a GitHub SBOM JSON file.
- Expose CVE search and update tools through MCP.

## Requirements

- Rust toolchain with edition 2024 support.
- Network access for downloading CVE/CWE archives during initialization and updates.
- SQLite database path or connection URL.

By default, qanvuli uses:

```bash
sqlite://./db.sqlite?mode=rwc
```

You can override it with `--db-url` or `QANVULI_DB_URL`.

## Build

```bash
cargo build --release
```

The CLI binary is:

```bash
./target/release/qanvuli
```

## Install

From the repository root:

```bash
cargo install --path . --locked
qanvuli --help
```

For development, commands can be run directly through Cargo:

```bash
cargo run -- --help
```

## Quick Start

Initialize the database:

```bash
cargo run -- init
```

Apply later delta updates:

```bash
cargo run -- update
```

Open the TUI:

```bash
cargo run -- tui
```

Search from the CLI:

```bash
cargo run -- search --text openssl --limit 20
cargo run -- search --cwe CWE-79
cargo run -- search --vendor microsoft --product windows
cargo run -- search --min-score 9.0 --severity CRITICAL
```

Fetch one raw CVE JSON record:

```bash
cargo run -- search --cve CVE-2024-12345
```

## Database Commands

Create or rebuild the database schema and import CVE data:

```bash
cargo run -- init
cargo run -- init --schema-only
cargo run -- init --rebuild
cargo run -- init --zip ./path/to/cve.zip
```

Apply updates:

```bash
cargo run -- update
cargo run -- update --zip ./path/to/delta.zip
```

Download a CVE archive without modifying the database:

```bash
cargo run -- download-cve --kind delta --output-dir ./data
cargo run -- download-cve --kind all --output-dir ./data
```

## TUI

Start the terminal UI with an optional initial query:

```bash
cargo run -- tui openssl
```

Common keys:

- `Enter`: run search
- `Tab`: move focus
- `/`: search within the detail pane
- `F3`: open advanced search
- `F4`: open CWE status filter in CWE mode
- `F6`: display settings
- `F7`: maintenance
- `F8`: toggle raw CVE JSON
- `F9`: toggle CWE mode
- `Esc`: close popup or leave the current mode
- `Ctrl-C`: quit

## MCP Server

Run the MCP server over stdio:

```bash
cargo run -- mcp
```

The MCP server exposes tools for:

- CWE search
- vendor/product search
- text search
- CVSS search
- recent CVE search
- identifier resolution across CVE, OSV, GHSA, RUSTSEC, PYSEC, and GO aliases
- enriched CVE lookup with local OSV, CISA KEV, and FIRST EPSS data
- enriched OSV package/version lookup
- exact raw CVE JSON lookup
- database status

Use `--db-url` or `QANVULI_DB_URL` to point the MCP server at the same database used by the CLI/TUI.

## OSV, KEV, EPSS Enrichment

The CVE List V5 importer and updater remain the source of CVE records. OSV, CISA KEV, and FIRST EPSS are imported as additional local enrichment sources with raw source records, provider timestamps where available, fetched timestamps, content hashes, normalized lookup tables, source sync state, and identifier graph evidence.

Initialization:

```bash
cargo run -- init
cargo run -- init --osv-pysec --osv-ghsa
cargo run -- init --osv-rustsec --osv-go
cargo run -- init --osv-suse-su --osv-ubuntu
cargo run -- init --osv-all
cargo run -- update
cargo run -- update --osv-ghsa
cargo run -- graph rebuild
```

Cross-source queries:

```bash
cargo run -- query resolve --id GHSA-TEST-0001
cargo run -- query enriched-cve --id CVE-2099-0001
cargo run -- query package --ecosystem crates.io --name foo --version 1.2.3 --enriched
cargo run -- search --text GHSA-TEST-0001 --enriched
cargo run -- db status
```

MCP tools include `resolve_identifier`, `get_related_identifiers`, `get_enriched_cve`, `get_enriched_osv`, `query_package_enriched`, and enriched `get_database_status`.

`init` and `update` continue to use the existing CVE List V5 importer/updater, then rebuild the local identifier graph and report OSV/KEV/EPSS sync state. KEV and EPSS are refreshed as snapshots. During `init`, OSV records are imported from Google Cloud Storage by advisory ID prefix. `OSV-` (OSS-Fuzz) is included by default, `--osv-all` imports the complete OSV corpus, and any official OSV source DB prefix can be selected with repeatable `--osv-<prefix>` flags. For example, `--osv-ghsa` selects `GHSA-`, `--osv-pysec` selects `PYSEC-`, `--osv-rustsec` selects `RUSTSEC-`, and `--osv-suse-su` selects `SUSE-SU-`; these are generic prefix selections, not hard-coded source-specific modes. The selected OSV prefixes are stored locally so plain `update` applies `modified_id.csv` changes only for the configured subset, upserting changed OSV IDs. `update --osv-<prefix>` and `update --osv-all` expand the stored OSV selection and seed the expanded set before continuing with KEV/EPSS snapshots. OSV imports upsert by OSV ID and skip unchanged records by content hash.

Current limits: OSV imports are streamed from disk into DB batches to reduce peak memory use, but `--osv-all` can still be slow. Package/version matching currently supports OSV SEMVER ranges for `crates.io`; unsupported ecosystems are not reported as `not_affected`. EPSS history, NVD/CVSS/CWE/CPE enrichment beyond existing CVE data, CSAF, VEX, automated remediation, and arbitrary MCP URL fetching are not implemented.

## SBOM Search

Search CVEs for packages in a GitHub SBOM JSON file:

```bash
cargo run -- sbom ./sbom.json
cargo run -- sbom --file ./sbom.json --per-package-limit 5
```

## Workspace Layout

- `app/`: CLI entrypoint and user-facing application crates.
- `app/crates/commands/`: non-interactive command implementations.
- `app/crates/tui/`: terminal UI.
- `app/crates/mcp/`: MCP server.
- `collector/`: release and archive collection.
- `db/`: database access and query logic.
- `models/`: CVE/CWE data models and parsing.
- `utils/`: shared utilities.

## Development

Format the workspace:

```bash
cargo fmt
```

Check the main app:

```bash
cargo check
```

Run focused crate checks:

```bash
cargo check -p qanvuli-app-tui
cargo check -p qanvuli-app-mcp
```

Run tests:

```bash
cargo test
```
