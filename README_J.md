<div align="center">
    <img src="./design/logo.svg" width="12%" height="12%">
</div>

# qanvuli (寒鰤)

qanvuli はローカルに構築した CVE データベースを検索するライブラリーおよびツールソフトウェアです。

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
cargo build --manifest-path app/Cargo.toml --release
```

The CLI binary is:

```bash
./target/release/qanvuli-app
```

For development, commands can be run directly through Cargo:

```bash
cargo run --manifest-path app/Cargo.toml -- --help
```

## Quick Start

Initialize the database:

```bash
cargo run --manifest-path app/Cargo.toml -- init
```

Apply later delta updates:

```bash
cargo run --manifest-path app/Cargo.toml -- update
```

Open the TUI:

```bash
cargo run --manifest-path app/Cargo.toml -- tui
```

Search from the CLI:

```bash
cargo run --manifest-path app/Cargo.toml -- search --text openssl --limit 20
cargo run --manifest-path app/Cargo.toml -- search --cwe CWE-79
cargo run --manifest-path app/Cargo.toml -- search --vendor microsoft --product windows
cargo run --manifest-path app/Cargo.toml -- search --min-score 9.0 --severity CRITICAL
```

Fetch one raw CVE JSON record:

```bash
cargo run --manifest-path app/Cargo.toml -- search --cve CVE-2024-12345
```

## Database Commands

Create or rebuild the database schema and import CVE data:

```bash
cargo run --manifest-path app/Cargo.toml -- init
cargo run --manifest-path app/Cargo.toml -- init --schema-only
cargo run --manifest-path app/Cargo.toml -- init --rebuild
cargo run --manifest-path app/Cargo.toml -- init --zip ./path/to/cve.zip
```

Apply updates:

```bash
cargo run --manifest-path app/Cargo.toml -- update
cargo run --manifest-path app/Cargo.toml -- update --zip ./path/to/delta.zip
```

Download a CVE archive without modifying the database:

```bash
cargo run --manifest-path app/Cargo.toml -- download-cve --kind delta --output-dir ./data
cargo run --manifest-path app/Cargo.toml -- download-cve --kind all --output-dir ./data
```

## TUI

Start the terminal UI with an optional initial query:

```bash
cargo run --manifest-path app/Cargo.toml -- tui openssl
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
cargo run --manifest-path app/Cargo.toml -- mcp
```

The MCP server exposes tools for:

- CWE search
- vendor/product search
- text search
- CVSS search
- recent CVE search
- exact raw CVE JSON lookup
- database update

Use `--db-url` or `QANVULI_DB_URL` to point the MCP server at the same database used by the CLI/TUI.

## SBOM Search

Search CVEs for packages in a GitHub SBOM JSON file:

```bash
cargo run --manifest-path app/Cargo.toml -- sbom ./sbom.json
cargo run --manifest-path app/Cargo.toml -- sbom --file ./sbom.json --per-package-limit 5
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
cargo fmt --manifest-path app/Cargo.toml
```

Check the main app:

```bash
cargo check --manifest-path app/Cargo.toml
```

Run focused crate checks:

```bash
cargo check --manifest-path app/Cargo.toml -p qanvuli-app-tui
cargo check --manifest-path app/Cargo.toml -p qanvuli-app-mcp
```

Run tests:

```bash
cargo test --manifest-path app/Cargo.toml
```
