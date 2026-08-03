#![cfg(feature = "mcp")]

use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);

struct McpOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct TemporaryDatabase {
    path: PathBuf,
    url: String,
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("sqlite-shm"));
        let _ = std::fs::remove_file(self.path.with_extension("sqlite-wal"));
    }
}

async fn initialized_database() -> TemporaryDatabase {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "qanvuli-mcp-stdio-{}-{nonce}.sqlite",
        std::process::id()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let database = qanvuli_core::database::SqlxDatabase::connect(&url)
        .await
        .expect("temporary MCP database should open");
    database
        .initialize()
        .await
        .expect("temporary MCP database should initialize");
    database
        .import_osv_record(qanvuli_core::database::OsvRawRecord {
            source_path: None,
            raw_json: json!({
                "schema_version": "1.8.0",
                "id": "PYSEC-2099-mcp-stdio",
                "modified": "2099-01-01T00:00:00Z",
                "affected": [{
                    "package": {
                        "ecosystem": "PyPI",
                        "name": "friendly-bard",
                        "purl": "pkg:pypi/friendly-bard"
                    },
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            { "introduced": "1.0" },
                            { "fixed": "2.0.post1" }
                        ]
                    }]
                }]
            })
            .to_string(),
        })
        .await
        .expect("MCP OSV fixture should import");
    database
        .import_cve_raw_json(
            r#"{"cveMetadata":{"cveId":"CVE-2099-0102","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"compact MCP recent fixture","descriptions":[{"lang":"en","value":"description for MCP compact response testing"}],"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"affected":[{"vendor":"example","product":"widget","versions":[{"version":"1.0.0","status":"affected"}]}]}}}"#.to_owned(),
        )
        .await
        .expect("MCP CVE fixture should import");
    database
        .close()
        .await
        .expect("temporary MCP database should close");
    TemporaryDatabase { path, url }
}

fn run_mcp_stdio(db_url: &str, messages: &[Value]) -> McpOutput {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qanvuli"))
        .args(["--db-url", db_url, "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("MCP server process should start");

    let stdout = child.stdout.take().expect("stdout should be piped");
    let (stdout_sender, stdout_receiver) = mpsc::channel();
    let stdout_reader = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut output = String::new();
        loop {
            let mut line = String::new();
            let bytes = stdout
                .read_line(&mut line)
                .expect("MCP stdout should be readable");
            if bytes == 0 {
                break;
            }
            output.push_str(&line);
            let _ = stdout_sender.send(line);
        }
        output
    });
    let mut stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_reader = thread::spawn(move || {
        let mut output = String::new();
        stderr
            .read_to_string(&mut output)
            .expect("MCP stderr should be readable");
        output
    });

    let mut stdin = child.stdin.take().expect("stdin should be piped");
    for message in messages {
        serde_json::to_writer(&mut stdin, message).expect("request should serialize");
        writeln!(stdin).expect("request should be written");
    }
    stdin.flush().expect("requests should be flushed");

    // Keep stdin open until every request has received a response. Closing it
    // immediately can legitimately cancel in-flight MCP work when the
    // transport observes EOF, which would make this process test racy.
    let mut pending_ids = messages
        .iter()
        .filter_map(|message| message.get("id").and_then(Value::as_i64))
        .collect::<BTreeSet<_>>();
    let response_started = Instant::now();
    while !pending_ids.is_empty() {
        let remaining = PROCESS_TIMEOUT.saturating_sub(response_started.elapsed());
        let line = match stdout_receiver.recv_timeout(remaining) {
            Ok(line) => line,
            Err(error) => {
                drop(stdin);
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "MCP responses {pending_ids:?} were not received before EOF/timeout: {error}"
                );
            }
        };
        if let Ok(response) = serde_json::from_str::<Value>(&line)
            && let Some(id) = response.get("id").and_then(Value::as_i64)
        {
            pending_ids.remove(&id);
        }
    }
    drop(stdin);

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("MCP process should be waitable") {
            break status;
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            child
                .kill()
                .expect("timed-out MCP process should be killed");
            let _ = child.wait();
            panic!("MCP process did not exit after stdin reached EOF");
        }
        thread::sleep(Duration::from_millis(20));
    };

    McpOutput {
        status,
        stdout: stdout_reader.join().expect("stdout reader should finish"),
        stderr: stderr_reader.join().expect("stderr reader should finish"),
    }
}

fn response_with_id(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response.get("id") == Some(&Value::from(id)))
        .unwrap_or_else(|| panic!("response id {id} not found in {responses:#?}"))
}

fn assert_lists_enriched_package_tool(response: &Value) {
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list result is malformed: {response:#?}"));
    assert!(
        tools.iter().any(|tool| {
            tool.get("name").and_then(Value::as_str) == Some("query_package_enriched")
        }),
        "query_package_enriched was not listed: {tools:#?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn mcp_stdio_lists_tools_recovers_from_request_error_and_exits_on_eof() {
    let database = initialized_database().await;
    let output = run_mcp_stdio(
        &database.url,
        &[
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "qanvuli-integration-test",
                        "version": "0.1.0"
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "qanvuli/not-a-real-method",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "query_package_enriched",
                    "arguments": {
                        "ecosystem": "PyPI",
                        "package": "Friendly_Bard",
                        "version": "2.0",
                        "purl": "pkg:pypi/friendly-bard@2.0",
                        "include_evidence": true
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "query_packages_enriched",
                    "arguments": {
                        "packages": [{
                            "ecosystem": "PyPI",
                            "package": "Friendly_Bard",
                            "version": "2.0",
                            "purl": "pkg:pypi/friendly-bard@2.0"
                        }],
                        "include_fixed": true
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "list_recent_updates",
                    "arguments": {"limit": 1}
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "list_recent_updates",
                    "arguments": {"limit": 1, "verbosity": "full"}
                }
            }),
        ],
    );

    assert!(
        output.status.success(),
        "MCP process failed with {}\nstderr:\n{}\nstdout:\n{}",
        output.status,
        output.stderr,
        output.stdout
    );

    let responses = output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("invalid JSON-RPC response `{line}`: {error}"))
        })
        .collect::<Vec<_>>();

    assert!(!responses.is_empty(), "MCP server returned no responses");
    assert!(
        responses
            .iter()
            .all(|response| response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")),
        "non-JSON-RPC response returned: {responses:#?}"
    );

    let initialize = response_with_id(&responses, 1);
    assert_eq!(
        initialize
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str),
        Some("2025-11-25")
    );

    assert_lists_enriched_package_tool(response_with_id(&responses, 2));

    let invalid_request = response_with_id(&responses, 3);
    assert!(
        invalid_request.get("error").is_some(),
        "unknown method should return a JSON-RPC error: {invalid_request:#?}"
    );

    assert_lists_enriched_package_tool(response_with_id(&responses, 4));

    let tool_call = response_with_id(&responses, 5);
    assert!(
        tool_call.get("error").is_none(),
        "package tool call failed: {tool_call:#?}"
    );
    let result_text = tool_call
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("package tool result is malformed: {tool_call:#?}"));
    let result: Value = serde_json::from_str(result_text)
        .unwrap_or_else(|error| panic!("package tool returned invalid JSON: {error}"));
    assert_eq!(result.get("vulnerable"), Some(&Value::Bool(true)));
    assert_eq!(result.get("confirmed_count"), Some(&Value::from(1)));
    assert_eq!(result.get("review_count"), Some(&Value::from(0)));
    assert_eq!(
        result
            .pointer("/findings/0/primary_id")
            .and_then(Value::as_str),
        Some("PYSEC-2099-mcp-stdio")
    );
    assert_eq!(
        result
            .pointer("/findings/0/affected/status")
            .and_then(Value::as_str),
        Some("affected")
    );
    assert_eq!(
        result
            .pointer("/findings/0/evidence_status")
            .and_then(Value::as_str),
        Some("available")
    );

    let batch_text = response_with_id(&responses, 6)
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("batch result text");
    let batch: Value = serde_json::from_str(batch_text).expect("batch result JSON");
    assert_eq!(batch["verbosity"], "summary");
    assert_eq!(batch["results"][0]["summary"]["vulnerable"], true);
    assert!(batch["results"][0].get("findings").is_none());

    let recent_summary_text = response_with_id(&responses, 7)
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("recent summary text");
    let recent_summary: Value =
        serde_json::from_str(recent_summary_text).expect("recent summary JSON");
    assert_eq!(recent_summary["verbosity"], "summary");
    assert_eq!(recent_summary["results"][0]["cve_id"], "CVE-2099-0102");
    assert_eq!(recent_summary["results"][0]["max_cvss_score"], 9.8);
    assert!(recent_summary["results"][0].get("affected").is_none());

    let recent_full_text = response_with_id(&responses, 8)
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("recent full text");
    let recent_full: Value = serde_json::from_str(recent_full_text).expect("recent full JSON");
    assert!(recent_full["results"][0]["affected"].is_array());
    assert!(recent_summary_text.len() < recent_full_text.len());
}
