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
cargo build --release
```

The CLI binary is:

```bash
./target/release/qanvuli
```

## Install

リポジトリのルートで実行します。

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
- exact raw CVE JSON lookup
- database update

Use `--db-url` or `QANVULI_DB_URL` to point the MCP server at the same database used by the CLI/TUI.

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
