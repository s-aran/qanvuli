<div align="center">
    <img src="./design/logo.svg" width="12%" height="12%" alt="qanvuli logo">
</div>

# qanvuli

qanvuli builds and searches a local vulnerability database. It combines CVE List data with CWE, CAPEC, OSV, CISA KEV, and FIRST EPSS in SQLite.

The project provides a CLI, terminal UI, Rust API, and MCP server. Searches run locally after the source feeds have been imported.

## Features

- Build a database from the complete CVE archive and enrichment feeds.
- Apply CVE deltas and incremental OSV updates.
- Search CVE and OSV records by identifier, text, affected product, CWE, CAPEC, CVSS, and date.
- Evaluate package versions against supported OSV ranges.
- Browse CVE, CWE, and CAPEC data in a terminal UI.
- Scan GitHub SBOM JSON with local vulnerability data.
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
qanvuli init --remove-existing-first
qanvuli init --no-progress
```

`init` normally builds and validates a candidate beside the active database, then installs it with rollback protection. A failed build leaves the active database unchanged. Run initialization while other qanvuli processes are stopped.

`--remove-existing-first` deletes the active database before the build. It uses less disk space but leaves no usable database if initialization fails.

Apply current deltas and refresh enrichment feeds:

```bash
qanvuli update
qanvuli update --zip ./data/delta.zip
qanvuli update --osv-refresh-all
qanvuli update --no-progress
```

`--osv-refresh-all` ignores the OSV cursor and upserts complete selected snapshots. Missing snapshot entries are not treated as deletions; withdrawn advisories remain available with their withdrawal timestamp.

Select additional OSV source families with flags such as `--osv-ghsa`, `--osv-rustsec`, or `--osv-pysec`. Run `qanvuli init --help` for the complete list.

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
qanvuli query package --ecosystem crates.io --name example --version 1.2.3
```

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
- `F3`: advanced search
- `F4`: display settings or catalog filters
- `F5`: database maintenance
- `F8`: raw CVE JSON
- `F9`: CWE catalog
- `F10`: CAPEC catalog
- `Esc`: close a popup or leave the current mode
- `Ctrl-C`: quit

## SBOM search

```bash
qanvuli sbom ./sbom.json
qanvuli sbom --file ./sbom.json --per-package-limit 5
```

OSV range evaluation confirms affected package versions where the ecosystem is supported. Name-only CVE matches are optional candidates and never count as confirmed vulnerabilities.

## MCP server

```bash
qanvuli mcp
```

The stdio server exposes local CVE, CWE, CAPEC, OSV, KEV, and EPSS queries plus database updates. Package queries return compact results by default; request evidence only when match details are needed.

OSV coverage is not a guarantee that a package has no CVEs. Check CVE List and vendor advisories for critical or end-of-life packages.

## Workspace

- `app/`: CLI and user-facing crates
- `collector/`: feed clients
- `core/`: public Rust API
- `db/`: schema, imports, and queries
- `models/`: source data models
- `utils/`: archive, GitHub, logging, and time utilities
