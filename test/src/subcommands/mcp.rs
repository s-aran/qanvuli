use qanvuli_db::entity::cve;
use qanvuli_db::{CveDatabase, CveSummary};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
struct CweArgs {
    cwe_ids: Vec<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ProductArgs {
    vendor: Option<String>,
    product: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TextArgs {
    query: String,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GetCveArgs {
    cve_id: String,
}

#[derive(Debug, Deserialize)]
struct CvssArgs {
    min_score: Option<f64>,
    max_score: Option<f64>,
    severity: Option<String>,
    version: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ProductCvssArgs {
    vendor: Option<String>,
    product: Option<String>,
    min_score: Option<f64>,
    severity: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DateArgs {
    published_since: Option<String>,
    updated_since: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
}

pub fn run(db_url: String) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;
    let mut db = None;

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    loop {
        let Some(message) =
            read_message(&mut input).map_err(|err| format!("failed to read MCP message: {err}"))?
        else {
            break;
        };

        let request = match serde_json::from_slice::<JsonRpcRequest>(&message) {
            Ok(request) => request,
            Err(err) => {
                let response = error_response(Value::Null, -32700, format!("parse error: {err}"));
                write_message(&mut output, &response)
                    .map_err(|err| format!("failed to write MCP response: {err}"))?;
                continue;
            }
        };

        if request.id.is_none() {
            continue;
        }

        let id = request.id.clone().unwrap_or(Value::Null);
        let response = runtime.block_on(handle_request(&mut db, &db_url, request));
        let response = match response {
            Ok(result) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
            }),
            Err(err) => error_response(id, -32603, err),
        };

        write_message(&mut output, &response)
            .map_err(|err| format!("failed to write MCP response: {err}"))?;
    }

    Ok(())
}

async fn handle_request(
    db: &mut Option<CveDatabase>,
    db_url: &str,
    request: JsonRpcRequest,
) -> Result<Value, String> {
    match request.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "qanvuli-cve-search",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        "tools/list" => Ok(json!({
            "tools": tools()
        })),
        "tools/call" => {
            if db.is_none() {
                *db = Some(
                    CveDatabase::connect(db_url)
                        .await
                        .map_err(|err| format!("failed to connect database `{db_url}`: {err}"))?,
                );
            }
            call_tool(db.as_ref().expect("database is connected"), request.params).await
        }
        "ping" => Ok(json!({})),
        method => Err(format!("unsupported method: {method}")),
    }
}

async fn call_tool(db: &CveDatabase, params: Value) -> Result<Value, String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "tools/call missing name".to_owned())?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let value = match name {
        "search_by_cwe" => {
            let args: CweArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_cwe(&args.cwe_ids, limit(args.limit), offset(args.offset))
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "search_by_product" => {
            let args: ProductArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_vendor_product(
                    args.vendor.as_deref(),
                    args.product.as_deref(),
                    limit(args.limit),
                    offset(args.offset),
                )
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "search_text" => {
            let args: TextArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_text(&args.query, limit(args.limit), offset(args.offset))
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "search_by_cvss" => {
            let args: CvssArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_cvss(
                    args.min_score,
                    args.max_score,
                    args.severity.as_deref(),
                    args.version.as_deref(),
                    limit(args.limit),
                    offset(args.offset),
                )
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "search_product_by_cvss" => {
            let args: ProductCvssArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_product_cvss(
                    args.vendor.as_deref(),
                    args.product.as_deref(),
                    args.min_score,
                    args.severity.as_deref(),
                    limit(args.limit),
                    offset(args.offset),
                )
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "search_recent" => {
            let args: DateArgs = parse_args(args)?;
            let cves = db
                .search_cve_summaries_by_date(
                    args.published_since.as_deref(),
                    args.updated_since.as_deref(),
                    limit(args.limit),
                    offset(args.offset),
                )
                .await
                .map_err(|err| err.to_string())?;
            json!(summaries(cves))
        }
        "get_cve" => {
            let args: GetCveArgs = parse_args(args)?;
            let cve = db
                .find_cve_by_id(&args.cve_id)
                .await
                .map_err(|err| err.to_string())?;
            json!(cve.map(full_cve))
        }
        _ => return Err(format!("unknown tool: {name}")),
    };

    let text = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": false
    }))
}

fn parse_args<T>(value: Value) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|err| format!("invalid arguments: {err}"))
}

fn limit(value: Option<u64>) -> u64 {
    value.unwrap_or(10).clamp(1, 25)
}

fn offset(value: Option<u64>) -> u64 {
    value.unwrap_or(0)
}

fn summaries(cves: Vec<CveSummary>) -> Vec<Value> {
    cves.into_iter().map(summary).collect()
}

fn summary(cve: CveSummary) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve.state,
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "title": cve.title,
        "description_preview": cve.description_en.as_deref().map(preview),
    })
}

fn full_cve(cve: cve::Model) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve.state,
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "serial": cve.serial,
        "title": cve.title,
        "description_en": cve.description_en,
        "raw_json": cve.raw_json,
    })
}

fn preview(value: &str) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let max_chars = 500;

    if compact.chars().count() <= max_chars {
        compact
    } else {
        let mut truncated = compact.chars().take(max_chars).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "search_by_cwe",
            "description": "Search CVEs by vulnerability type using CWE IDs such as CWE-79 or CWE-89.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwe_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "CWE IDs to match."
                    },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                },
                "required": ["cwe_ids"]
            }
        },
        {
            "name": "search_by_product",
            "description": "Search CVEs by affected vendor and/or product name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vendor": { "type": "string", "description": "Affected vendor name or fragment." },
                    "product": { "type": "string", "description": "Affected product name or fragment." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }
        },
        {
            "name": "search_text",
            "description": "Search CVEs by CVE ID, title, or English description text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Text to search for." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                },
                "required": ["query"]
            }
        },
        {
            "name": "search_by_cvss",
            "description": "Search CVEs by CVSS score, severity, and/or CVSS version.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "min_score": { "type": "number", "minimum": 0, "maximum": 10, "description": "Minimum CVSS base score." },
                    "max_score": { "type": "number", "minimum": 0, "maximum": 10, "description": "Maximum CVSS base score." },
                    "severity": { "type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "description": "CVSS base severity." },
                    "version": { "type": "string", "description": "CVSS version, for example 3.1 or 4.0." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }
        },
        {
            "name": "search_product_by_cvss",
            "description": "Search high-risk CVEs for a specific affected vendor/product.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vendor": { "type": "string", "description": "Affected vendor name or fragment." },
                    "product": { "type": "string", "description": "Affected product name or fragment." },
                    "min_score": { "type": "number", "minimum": 0, "maximum": 10, "description": "Minimum CVSS base score." },
                    "severity": { "type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "description": "CVSS base severity." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }
        },
        {
            "name": "search_recent",
            "description": "Search recently published and/or recently updated CVEs using ISO-8601 timestamps.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "published_since": { "type": "string", "description": "Only CVEs published at or after this timestamp, for example 2026-06-01T00:00:00Z." },
                    "updated_since": { "type": "string", "description": "Only CVEs updated at or after this timestamp, for example 2026-06-01T00:00:00Z." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25, "default": 10 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }
        },
        {
            "name": "get_cve",
            "description": "Fetch one CVE record by CVE ID, including raw JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cve_id": { "type": "string", "description": "CVE ID such as CVE-2024-1000." }
                },
                "required": ["cve_id"]
            }
        }
    ])
}

fn read_message<R>(input: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: BufRead,
{
    let mut line = String::new();
    let read = input.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }

    let trimmed = line.trim_end_matches(['\r', '\n']);
    if let Some(value) = trimmed.strip_prefix("Content-Length:") {
        let content_length = value.trim().parse::<usize>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad content length: {err}"),
            )
        })?;

        loop {
            line.clear();
            let read = input.read_line(&mut line)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected eof while reading headers",
                ));
            }
            if line.trim_end_matches(['\r', '\n']).is_empty() {
                break;
            }
        }

        let mut body = vec![0; content_length];
        input.read_exact(&mut body)?;
        Ok(Some(body))
    } else {
        Ok(Some(trimmed.as_bytes().to_vec()))
    }
}

fn write_message<W>(output: &mut W, value: &Value) -> io::Result<()>
where
    W: Write,
{
    let body = serde_json::to_vec(value)?;
    output.write_all(&body)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn error_response(id: Value, code: i64, message: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}
