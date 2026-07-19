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

By default, qanvuli stores and opens `db.sqlite` in the current working directory:

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
cargo run -- search --source osv --text openssl --limit 20 --offset 0
cargo run -- search --cwe CWE-79
cargo run -- search --vendor microsoft --product windows
cargo run -- search --min-score 9.0 --severity CRITICAL
```

Fetch one raw CVE JSON record:

```bash
cargo run -- search --cve CVE-2024-12345
```

## Database Commands

Build and install a complete replacement database:

```bash
cargo run -- init
cargo run -- init --zip ./path/to/cve.zip
```

Apply updates:

```bash
cargo run -- update
cargo run -- update --osv-full-snapshot
cargo run -- update --zip ./path/to/delta.zip
```

Verify database storage and rebuild derived search indexes:

```bash
cargo run -- db check
cargo run -- db check --scan
cargo run -- db check --full
cargo run -- db rebuild-search
```

### Database rebuild policy

The SQLite file is derived from source feeds and is intentionally rebuildable. A full `init`
builds and validates a candidate database in the same directory, closes its connections, and only
then installs it over the active file. A failed download, parse, import, index build, or integrity
check leaves the previous file untouched.

The database layer has a dedicated SQLx write connection for schema creation, bulk writes,
foreign-key PRAGMAs, FTS rebuilds, and integrity checks. SQLite foreign keys are enabled on each
such physical connection. `db check` is a low-latency schema and fixed-sentinel check; it does not
run `quick_check`, `integrity_check`, full counts, or OFFSET sampling. `db check --scan` adds
`quick_check(1)` and broader correspondence scans. `db check --full` additionally
runs the potentially long SQLite integrity, foreign-key, and native FTS scans, reporting each stage
and elapsed time on stderr while keeping JSON on stdout. `db rebuild-search` rebuilds and directly
verifies the derived CVE and OSV search structures without running the full SQLite scan.

Existing incompatible schemas are never stamped as current or patched in place; run `init` to
build and install a complete validated replacement.

Normalized CVE affected-product rows retain provider version conditions (`version`, `status`,
`versionType`, `lessThan`, and `lessThanOrEqual`) under integer foreign keys, while the original
CVE JSON remains available for provider-specific fields.

See [database architecture](docs/database-architecture.md) for schema ownership, replacement,
identifier graph, FTS, and source-cursor details.

OSV aliases, upstream identifiers, and related identifiers are stored as distinct relationship
types. OSV synchronization advances its cursor only after every selected record, derived index,
and integrity check succeeds; a failed run keeps the prior cursor so the records are retried.
OSV exports retain withdrawn records, including their `withdrawn` timestamp. The incremental feed
lists new or modified records; `update --osv-full-snapshot` explicitly ignores the cursor and
downloads complete selected snapshots. It does not delete local IDs absent from those snapshots.

`init` builds a new SQLx-backed database from CVE, CWE, OSV, KEV, and EPSS sources. `update --zip`
imports a local CVE archive through the same schema without network access; a normal `update`
refreshes the latest CVE snapshot and enrichment sources before its final integrity check.

Download a CVE archive without modifying the database:

```bash
cargo run -- download-cve --kind delta --output-dir ./data
cargo run -- download-cve --kind all --output-dir ./data
```

## TUI

The TUI and MCP server use the SQLx database API. They expose public CVE/OSV identifiers rather
than internal SQLite keys, and neither surface silently creates or alters a database.

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
- vendor/product search with substring or exact-match arguments
- text search
- CVSS search
- recent CVE search
- exact raw CVE JSON lookup
- database update

Package enrichment queries normalize PyPI package names according to PEP 503, so `pillow_heif`,
`Pillow_Heif`, and `pillow.heif` match `pillow-heif`. The batch package query returns compact
per-package summaries by default; pass `include_evidence: true` only when detailed OSV/alias
match evidence is needed.

OSV package ranges do not necessarily model vulnerabilities left unpatched on end-of-life
branches, and some CVEs may be absent from OSV. For important packages on EOL branches, also
cross-check the CVE List or the vendor's security advisories.

Use `--db-url` or `QANVULI_DB_URL` to point the MCP server at the same database used by the CLI/TUI.

## SBOM Search

Search CVEs for packages in a GitHub SBOM JSON file:

```bash
cargo run -- sbom ./sbom.json
cargo run -- sbom --file ./sbom.json --per-package-limit 5
```

SBOM results distinguish confirmed findings from name-only candidates. A package is marked
`vulnerable` only when range/version evaluation confirms it is affected; candidates remain
explicitly reviewable and do not make the package definitely vulnerable.

PURL lookup recognizes Cargo, RubyGems, GitHub Actions, Go, Maven, npm, NuGet, PyPI, and Pub.
Range comparison currently supports only Cargo/crates.io SemVer. Exact versions listed directly
by OSV are supported for every recognized ecosystem. Other ranges are reported under
`unresolved_versions` as `unsupported_version_scheme`; they are never treated as not affected.
`--published-since` and `--updated-since` use CVE timestamps for linked CVE findings and OSV
provider timestamps for OSV findings. `--per-package-limit` limits each final source class
independently. `--include-rejected` applies to linked CVEs because OSV has no CVE rejection state.
Package findings include explicit `*_status` fields for aliases, fixed versions, KEV, EPSS,
priority, and evidence. A placeholder value is reported as `not_queried`, not as source absence.
Package processing is deterministic and sequential because all SQLite work uses one physical
mutex-protected connection; there is intentionally no public `--jobs` tuning option.

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
cargo fmt --all -- --check
```

Check the main app:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run focused crate checks:

```bash
cargo check -p qanvuli-app-tui
cargo check -p qanvuli-app-mcp
```

Run tests:

```bash
cargo test --workspace --all-features
```
