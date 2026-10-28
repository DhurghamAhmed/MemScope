#![allow(clippy::result_large_err)]

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::{Fixture, allowlist_for, fixture_exe};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, ErrorCode as RpcCode};

fn call_params(name: &str, arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::default();
    params.name = name.to_owned().into();
    params.arguments = arguments.as_object().cloned();
    params
}
use rmcp::RoleClient;
use rmcp::service::{RunningService, ServiceError};
use rmcp::transport::TokioChildProcess;
use serde_json::{Value, json};

fn server_exe() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_memscope"));
    if !path.exists() {
        path = common::repo_root().join("target/debug/memscope.exe");
    }
    assert!(path.exists(), "{} is missing", path.display());
    path
}

struct Client {
    service: RunningService<RoleClient, ()>,
}

impl Client {
    async fn start(allowlist: &std::path::Path, allow_write: bool) -> Self {
        let mut command = tokio::process::Command::new(server_exe());
        command
            .arg("serve")
            .env("MEMSCOPE_ALLOWLIST", allowlist)
            .env("MEMSCOPE_LOG", "warn");
        if allow_write {
            command.env("MEMSCOPE_ALLOW_WRITE", "1");
        } else {
            command.env_remove("MEMSCOPE_ALLOW_WRITE");
        }
        let transport =
            TokioChildProcess::new(command).expect("spawn the memscope server as a child");
        let service = ().serve(transport).await.expect("the MCP initialize handshake must succeed");
        Self { service }
    }

    async fn call(&self, name: &str, arguments: Value) -> CallToolResult {
        self.service
            .call_tool(call_params(name, arguments))
            .await
            .unwrap_or_else(|e| panic!("tool {name} failed at the protocol level: {e}"))
    }

    async fn expect_ok(&self, name: &str, arguments: Value) -> Value {
        let result = self.call(name, arguments).await;
        assert_ne!(
            result.is_error,
            Some(true),
            "tool {name} reported an operation failure: {:?}",
            result.structured_content
        );
        result
            .structured_content
            .unwrap_or_else(|| panic!("tool {name} returned no structured content"))
    }

    async fn expect_failure(&self, name: &str, arguments: Value) -> Value {
        let result = self.call(name, arguments).await;
        assert_eq!(
            result.is_error,
            Some(true),
            "tool {name} should have reported an operation failure"
        );
        result
            .structured_content
            .unwrap_or_else(|| panic!("tool {name} returned no structured error"))
    }

    async fn shutdown(self) {
        let _ = self.service.cancel().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_actual_mcp_client_discovers_exactly_the_twenty_seven_named_tools() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let client = Client::start(&allowlist, false).await;

    let info = client
        .service
        .peer_info()
        .expect("the server must report its info after initialize");
    let server_info = info
        .server_info
        .as_ref()
        .expect("the server must identify itself");
    assert_eq!(server_info.name, "memscope");
    assert_eq!(info.protocol_version.to_string(), "2025-11-25");
    assert!(info.capabilities.tools.is_some());
    let instructions = info
        .instructions
        .as_ref()
        .expect("the server must send instructions");
    assert!(instructions.contains("CONSISTENCY_UNAVAILABLE"));
    assert!(instructions.contains("never executes code"));

    let listed = client
        .service
        .list_all_tools()
        .await
        .expect("tools/list must succeed");
    let discovered: BTreeSet<String> = listed.iter().map(|t| t.name.to_string()).collect();
    let expected: BTreeSet<String> = memscope::mcp::TOOL_NAMES
        .iter()
        .map(|n| (*n).to_owned())
        .collect();
    assert_eq!(
        discovered, expected,
        "the discovered tool set must be exactly the 27 named tools"
    );
    for tool in &listed {
        assert!(
            tool.description.is_some(),
            "{} has no description",
            tool.name
        );
    }

    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_tool_is_a_protocol_error_while_a_named_failure_is_a_tool_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let client = Client::start(&allowlist, false).await;

    let protocol = client
        .service
        .call_tool(call_params("definitely_not_a_tool", json!({})))
        .await
        .expect_err("an unknown tool must be a JSON-RPC protocol error");
    match protocol {
        ServiceError::McpError(data) => assert!(
            data.code == RpcCode::METHOD_NOT_FOUND || data.code == RpcCode::INVALID_PARAMS,
            "an unroutable call must come back as a JSON-RPC error; rmcp 3.8 reports an unknown              tool as {:?}",
            data.code
        ),
        other => panic!("expected an McpError, got {other:?}"),
    }

    let operation = client.expect_failure("list_modules", json!({})).await;
    assert_eq!(
        operation["code"], "NOT_ATTACHED",
        "a named operation failure must arrive as a tool result, not a protocol error"
    );
    assert_eq!(operation["operation"], "list_modules");
    assert!(operation["next_step"].is_string());

    let malformed = client
        .service
        .call_tool(call_params("read_memory", json!({ "address": 12345 })))
        .await;
    assert!(
        malformed.is_err() || malformed.as_ref().unwrap().is_error == Some(true),
        "a schema violation must be refused, not accepted"
    );

    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_complete_analysis_workflow_runs_over_real_stdio() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let mut fixture = Fixture::start("x64");
    let client = Client::start(&allowlist, true).await;

    let status = client.expect_ok("server_status", json!({})).await;
    assert_eq!(status["tool_count"], 27);
    assert_eq!(status["attached"], false);
    assert_eq!(status["writes_enabled_in_environment"], true);
    assert_eq!(status["policy_entries"], 0);
    assert_eq!(status["target_selection"], "unrestricted");

    let processes = client.expect_ok("list_processes", json!({})).await;
    let listed = processes.as_array().expect("an array of processes");
    let entry = listed
        .iter()
        .find(|p| p["pid"] == fixture.pid())
        .expect("the fixture must be enumerated");
    assert_eq!(entry["allowlisted"], true);
    assert_eq!(entry["owned_by_current_user"], true);

    let attached = client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;
    assert_eq!(attached["session"]["pid"], fixture.pid());
    assert_eq!(attached["session"]["architecture"], "x64");
    assert_eq!(attached["session"]["pointer_width_bytes"], 8);
    assert!(
        attached["authorisation"]["hash_pin_meaning"]
            .as_str()
            .expect("hash pin meaning")
            .contains("not Authenticode")
    );
    let session_id = attached["session"]["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();

    let modules = client.expect_ok("list_modules", json!({})).await;
    let anchor = modules
        .as_array()
        .expect("modules")
        .iter()
        .find(|m| m["name"] == "memscope_anchor.dll")
        .expect("the anchor module must be loaded");
    let anchor_name = anchor["name"].as_str().expect("name").to_owned();

    let block_base = fixture.area("block");
    let counter = fixture.counter_address();
    let regions = client
        .expect_ok(
            "list_regions",
            json!({
                "filter": {
                    "min_address": format!("0x{:x}", block_base & !0xFFFF),
                    "max_address": format!("0x{:x}", block_base + 0x2_0000)
                }
            }),
        )
        .await;
    assert!(
        regions
            .as_array()
            .expect("regions")
            .iter()
            .any(|r| r["eligible"] == true),
        "the block region must be eligible"
    );

    let read = client
        .expect_ok(
            "read_memory",
            json!({ "address": format!("0x{counter:x}"), "value_type": "int32" }),
        )
        .await;
    assert_eq!(read["decoded"]["value"], "100");
    assert_eq!(read["raw"], "64000000");
    assert_eq!(read["session_id"], session_id);
    assert_eq!(read["complete"], true);
    assert_eq!(read["consistency"], "live");

    let bytes = client
        .expect_ok(
            "read_bytes",
            json!({ "address": format!("0x{block_base:x}"), "length": 12 }),
        )
        .await;
    assert_eq!(bytes["raw"], "a5a5a5a5640000005a5a5a5a");

    let batch = client
        .expect_ok(
            "read_batch",
            json!({ "items": [
                { "address": format!("0x{counter:x}"), "value_type": "int32" },
                { "address": format!("0x{:x}", fixture.area("noaccess")), "value_type": "int32" }
            ]}),
        )
        .await;
    assert_eq!(batch["summary"]["succeeded"], 1);
    assert_eq!(batch["summary"]["failed"], 1);
    assert_eq!(batch["summary"]["atomic_snapshot"], false);

    let structure = client
        .expect_ok(
            "read_struct",
            json!({
                "address": format!("0x{block_base:x}"),
                "fields": [
                    { "name": "sentinel_before", "value_type": "uint32", "offset": 0 },
                    { "name": "counter", "value_type": "int32", "offset": 4 },
                    { "name": "sentinel_after", "value_type": "uint32", "offset": 8 }
                ]
            }),
        )
        .await;
    assert!(
        structure["layout_source"]
            .as_str()
            .expect("layout source")
            .contains("caller-declared")
    );

    let filter = json!({
        "min_address": format!("0x{:x}", block_base & !0xFFFF),
        "max_address": format!("0x{:x}", block_base + 0x2_0000)
    });
    let first = client
        .expect_ok(
            "first_scan",
            json!({
                "value_type": "int32",
                "operator": "exact",
                "needle": { "kind": "int", "value": "100" },
                "filter": filter,
                "budget": { "display_limit": 50, "max_results": 10000,
                            "max_snapshot_bytes": 33554432,
                            "max_bytes_scanned": 134217728, "timeout_ms": 20000 }
            }),
        )
        .await;
    assert_eq!(first["stop_reason"], "completed");
    assert_eq!(first["truncated"], false);
    assert_eq!(first["values_are_from_capture"], true);
    assert!(
        first["displayed"]
            .as_array()
            .expect("displayed")
            .iter()
            .any(|c| c["address_raw"] == format!("{counter}")),
        "the counter must be among the matches"
    );

    assert_eq!(fixture.send("set 4242"), "value=4242");

    let narrowed = client
        .expect_ok(
            "next_scan",
            json!({
                "operator": "changed",
                "baseline_source": "previous_scan",
                "budget": { "display_limit": 50, "max_results": 10000,
                            "max_snapshot_bytes": 33554432,
                            "max_bytes_scanned": 134217728, "timeout_ms": 20000 }
            }),
        )
        .await;
    assert_eq!(narrowed["generation"], "2");
    assert_eq!(
        narrowed["compared_against_scan_id"], first["scan_id"],
        "the narrowing must name the scan it compared against"
    );
    assert!(
        narrowed["displayed"]
            .as_array()
            .expect("displayed")
            .iter()
            .any(|c| c["address_raw"] == format!("{counter}")),
        "the counter changed and must survive narrowing"
    );

    let listed_results = client
        .expect_ok("list_results", json!({ "offset": 0, "limit": 10 }))
        .await;
    assert_eq!(listed_results["display_pagination_only"], true);
    assert_eq!(listed_results["values_are_from_capture"], true);

    let grouped = client
        .expect_ok(
            "group_scan",
            json!({
                "fields": [
                    { "name": "before", "value_type": "uint32", "offset": -4,
                      "operator": "exact", "needle": { "kind": "uint", "value": "2779096485" } },
                    { "name": "counter", "value_type": "int32", "offset": 0,
                      "operator": "exact", "needle": { "kind": "int", "value": "4242" } },
                    { "name": "after", "value_type": "uint32", "offset": 4,
                      "operator": "exact", "needle": { "kind": "uint", "value": "1515870810" } }
                ],
                "filter": filter,
                "alignment": 4,
                "budget": { "display_limit": 50, "max_results": 1000,
                            "max_snapshot_bytes": 33554432,
                            "max_bytes_scanned": 134217728, "timeout_ms": 20000 }
            }),
        )
        .await;
    assert_eq!(grouped["field_count"], 3);
    assert!(
        grouped["matches"]
            .as_array()
            .expect("matches")
            .iter()
            .any(|m| m["base_address_raw"] == format!("{counter}")),
        "the counter must be the base of a group match"
    );

    let dissected = client
        .expect_ok(
            "dissect_region",
            json!({ "address": format!("0x{block_base:x}"), "length": 128 }),
        )
        .await;
    assert_eq!(dissected["analysis_is_heuristic"], true);

    let watched = client
        .expect_ok(
            "watch_value",
            json!({
                "address": format!("0x{counter:x}"),
                "value_type": "int32",
                "interval_ms": 10,
                "duration_ms": 120,
                "max_samples": 8
            }),
        )
        .await;
    assert!(watched["taken_samples"].as_u64().expect("samples") > 0);
    assert_eq!(watched["consistency"], "live");
    assert!(
        watched["observation_limits"]
            .as_array()
            .expect("limits")
            .iter()
            .any(|l| l
                .as_str()
                .unwrap_or_default()
                .contains("not instrumentation"))
    );

    let paused_refusal = client
        .expect_failure(
            "watch_value",
            json!({
                "address": format!("0x{counter:x}"),
                "value_type": "int32",
                "interval_ms": 10,
                "duration_ms": 50,
                "consistency": "paused"
            }),
        )
        .await;
    assert_eq!(paused_refusal["code"], "CONSISTENCY_UNAVAILABLE");

    let root_rva = fixture.meta["pointer_chain"]["root_rva"]
        .as_str()
        .expect("root rva")
        .to_owned();
    let resolved = client
        .expect_ok(
            "resolve_address",
            json!({ "address": format!("{anchor_name}+{root_rva}") }),
        )
        .await;
    assert_eq!(resolved["form"], "module_relative");

    let offsets = fixture.meta["pointer_chain"]["deref_offsets"].clone();
    let path = client
        .expect_ok(
            "resolve_pointer_path",
            json!({
                "base": format!("{anchor_name}+{root_rva}"),
                "deref_offsets": offsets,
                "final_offset": 0
            }),
        )
        .await;
    assert_eq!(path["resolved"], true);
    assert_eq!(path["pointer_width"], 8);
    let leaf = path["value_address_raw"].as_str().expect("leaf").to_owned();
    let leaf_raw: u64 = leaf.parse().expect("leaf is a decimal string");

    let leaf_value = client
        .expect_ok(
            "read_memory",
            json!({ "address": format!("0x{leaf_raw:x}"), "value_type": "int32" }),
        )
        .await;
    assert_eq!(leaf_value["decoded"]["value"], "1337");

    let node1 = fixture.meta["pointer_chain"]["node1"]
        .as_str()
        .expect("node1")
        .to_owned();
    let references = client
        .expect_ok(
            "find_references",
            json!({
                "target": node1,
                "filter": filter,
                "alignment": 1,
                "max_results": 64,
                "timeout_ms": 10000
            }),
        )
        .await;
    assert!(
        references["limitations"]
            .as_array()
            .expect("limitations")
            .iter()
            .any(|l| l
                .as_str()
                .unwrap_or_default()
                .contains("No instruction is decoded"))
    );

    let anchor_base = fixture.meta["pointer_chain"]["anchor_base"]
        .as_str()
        .expect("anchor base")
        .to_owned();
    let anchor_base_raw =
        u64::from_str_radix(anchor_base.trim_start_matches("0x"), 16).expect("hex");
    let pointer_scan = client
        .expect_ok(
            "pointer_scan",
            json!({
                "target": node1,
                "max_depth": 1,
                "max_offset": 0,
                "offset_alignment": 8,
                "max_results": 32,
                "max_index_bytes": 33554432,
                "timeout_ms": 20000,
                "require_module_base": true,
                "filter": {
                    "min_address": anchor_base,
                    "max_address": format!("0x{:x}", anchor_base_raw + 0x20_0000),
                    "include_images": true
                }
            }),
        )
        .await;
    assert!(
        pointer_scan["paths"]
            .as_array()
            .expect("paths")
            .iter()
            .any(|p| p["base_is_module_relative"] == true && p["verified"] == true),
        "a verified module-relative path must be found"
    );

    let rescan = client
        .expect_ok(
            "rescan_pointer_paths",
            json!({
                "value_bytes": 4,
                "paths": [{
                    "id": "leaf",
                    "session_id": session_id,
                    "base": format!("{anchor_name}+{root_rva}"),
                    "deref_offsets": offsets,
                    "final_offset": 0,
                    "expected_value_raw": "39050000"
                }]
            }),
        )
        .await;
    assert_eq!(
        rescan.as_array().expect("results")[0]["verdict"],
        "survived"
    );

    let written = client
        .expect_ok(
            "write_memory",
            json!({
                "address": format!("0x{counter:x}"),
                "payload": { "kind": "typed", "value_type": "int32",
                             "value": { "kind": "int", "value": "31337" } },
                "confirm": true
            }),
        )
        .await;
    assert_eq!(written["verified"], true);
    assert_eq!(written["mutation_status"], "written");
    assert_eq!(written["readback_raw"], "697a0000");
    let undo_id = written["undo_id"].as_str().expect("undo id").to_owned();
    assert_eq!(
        fixture.send("get"),
        "value=31337",
        "the fixture must confirm the write through its own control channel"
    );

    let unconfirmed = client
        .expect_failure(
            "write_memory",
            json!({
                "address": format!("0x{counter:x}"),
                "payload": { "kind": "bytes", "hex": "00000000" }
            }),
        )
        .await;
    assert_eq!(unconfirmed["code"], "CONFIRMATION_REQUIRED");

    let undone = client
        .expect_ok("undo_write", json!({ "undo_id": undo_id, "confirm": true }))
        .await;
    assert_eq!(undone["verified"], true);
    assert_eq!(
        fixture.send("get"),
        "value=4242",
        "undo must restore what the write replaced"
    );

    let frozen = client
        .expect_ok(
            "freeze_value",
            json!({
                "address": format!("0x{counter:x}"),
                "payload": { "kind": "typed", "value_type": "int32",
                             "value": { "kind": "int", "value": "555" } },
                "interval_ms": 10,
                "lifetime_ms": 5000,
                "confirm": true
            }),
        )
        .await;
    let freeze_id = frozen["freeze_id"].as_str().expect("freeze id").to_owned();
    assert_eq!(frozen["initial_write_verified"], true);
    assert_eq!(fixture.send("get"), "value=555");

    assert_eq!(fixture.send("set 1"), "value=1");
    let mut recovered = false;
    for _ in 0..100 {
        if fixture.send("get") == "value=555" {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(recovered, "the freeze worker must restore the value");

    let listed_frozen = client.expect_ok("list_frozen", json!({})).await;
    let view = listed_frozen
        .as_array()
        .expect("frozen list")
        .iter()
        .find(|v| v["freeze_id"] == freeze_id.as_str())
        .expect("the freeze must be listed");
    assert_eq!(view["stats"]["running"], true);
    assert!(view["stats"]["corrections"].as_str().expect("corrections") != "0");

    let unfrozen = client
        .expect_ok(
            "unfreeze_value",
            json!({ "freeze_id": freeze_id, "restore_original": true, "confirm": true }),
        )
        .await;
    assert_eq!(unfrozen["stopped"], true);
    assert_eq!(unfrozen["joined"], true);
    assert_eq!(unfrozen["restore"], "restored");
    assert_eq!(unfrozen["restore_verified"], true);

    let reset = client.expect_ok("reset_scan", json!({})).await;
    assert!(reset["cleared_candidates"].as_u64().expect("cleared") > 0);

    let detached = client
        .expect_ok("detach_process", json!({ "restore_frozen_values": false }))
        .await;
    assert_eq!(detached["detached"], true);
    assert_eq!(detached["cleared_scan"], false);

    let after = client.expect_ok("server_status", json!({})).await;
    assert_eq!(after["attached"], false);
    assert_eq!(after["active_freezes"], 0);

    let not_attached = client
        .expect_failure(
            "read_memory",
            json!({
                "address": format!("0x{counter:x}"), "value_type": "int32"
            }),
        )
        .await;
    assert_eq!(not_attached["code"], "NOT_ATTACHED");

    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_are_refused_over_mcp_when_the_server_was_started_without_the_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let mut fixture = Fixture::start("x64");
    let client = Client::start(&allowlist, false).await;

    let status = client.expect_ok("server_status", json!({})).await;
    assert_eq!(status["writes_enabled_in_environment"], false);

    client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;

    for (tool, arguments) in [
        (
            "write_memory",
            json!({
                "address": format!("0x{:x}", fixture.counter_address()),
                "payload": { "kind": "bytes", "hex": "00000000" },
                "confirm": true
            }),
        ),
        (
            "undo_write",
            json!({ "undo_id": "undo-1", "confirm": true }),
        ),
        (
            "freeze_value",
            json!({
                "address": format!("0x{:x}", fixture.counter_address()),
                "payload": { "kind": "bytes", "hex": "00000000" },
                "interval_ms": 20,
                "lifetime_ms": 1000,
                "confirm": true
            }),
        ),
    ] {
        let refusal = client.expect_failure(tool, arguments).await;
        assert_eq!(
            refusal["code"], "WRITE_DISABLED",
            "{tool} must be refused without the environment gate"
        );
    }

    assert_eq!(
        fixture.send("get"),
        "value=100",
        "nothing may have changed the fixture"
    );
    assert!(fixture.send("externals").starts_with("external_changes=0"));

    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_are_served_correctly_and_session_changes_are_serialised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let fixture = Fixture::start("x64");
    let client = std::sync::Arc::new(Client::start(&allowlist, false).await);

    client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;

    let counter = fixture.counter_address();
    let mut handles = Vec::new();
    for _ in 0..16 {
        let client = std::sync::Arc::clone(&client);
        handles.push(tokio::spawn(async move {
            let value = client
                .expect_ok(
                    "read_memory",
                    json!({ "address": format!("0x{counter:x}"), "value_type": "int32" }),
                )
                .await;
            value["decoded"]["value"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        }));
    }
    for handle in handles {
        assert_eq!(
            handle.await.expect("the read task must not panic"),
            "100",
            "every concurrent read must return the same correct value"
        );
    }

    let second_attach = client
        .expect_failure("attach_process", json!({ "pid": fixture.pid() }))
        .await;
    assert_eq!(
        second_attach["code"], "INVALID_ARGUMENT",
        "a session change while attached must be refused, not interleaved"
    );

    let client = std::sync::Arc::try_unwrap(client).ok().expect("sole owner");
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_long_running_tool_keeps_the_rest_of_the_server_answering() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let fixture = Fixture::start("x64");
    let client = std::sync::Arc::new(Client::start(&allowlist, false).await);

    client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;
    let counter = fixture.counter_address();

    let idle = client.expect_ok("server_status", json!({})).await;
    assert!(idle["operation_in_flight"].is_null());
    assert!(
        idle["concurrency_note"]
            .as_str()
            .expect("a concurrency note")
            .contains("OPERATION_IN_FLIGHT")
    );

    let watch_ms = 4_000u64;
    let watcher = {
        let client = std::sync::Arc::clone(&client);
        tokio::spawn(async move {
            client
                .expect_ok(
                    "watch_value",
                    json!({
                        "address": format!("0x{counter:x}"),
                        "value_type": "int32",
                        "interval_ms": 50,
                        "duration_ms": watch_ms,
                        "max_samples": 1000
                    }),
                )
                .await
        })
    };

    let mut in_flight = None;
    for _ in 0..40 {
        let started = std::time::Instant::now();
        let status = client.expect_ok("server_status", json!({})).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(1_000),
            "server_status waited {elapsed:?} while watch_value was running"
        );
        if status["operation_in_flight"]["operation"] == "watch_value" {
            in_flight = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let status = in_flight.expect("server_status must observe watch_value in flight");
    assert_eq!(status["operation_in_flight"]["owns_scan_state"], false);
    assert!(status["operation_in_flight"]["running_ms"].is_number());

    let started = std::time::Instant::now();
    let read = client
        .expect_ok(
            "read_memory",
            json!({ "address": format!("0x{counter:x}"), "value_type": "int32" }),
        )
        .await;
    assert_eq!(read["decoded"]["value"], "100");
    assert!(
        started.elapsed() < Duration::from_millis(1_000),
        "a read must not wait for a watch to finish"
    );

    let second = client
        .expect_failure(
            "watch_value",
            json!({
                "address": format!("0x{counter:x}"),
                "value_type": "int32",
                "interval_ms": 50,
                "duration_ms": 100
            }),
        )
        .await;
    assert_eq!(second["code"], "OPERATION_IN_FLIGHT");
    assert!(
        second["message"]
            .as_str()
            .unwrap_or_default()
            .contains("watch_value")
    );

    let detach = client
        .expect_failure("detach_process", json!({ "restore_frozen_values": false }))
        .await;
    assert_eq!(
        detach["code"], "OPERATION_IN_FLIGHT",
        "the session must not be released under a running tool"
    );

    let watched = watcher.await.expect("the watch task must not panic");
    assert!(watched["taken_samples"].as_u64().expect("samples") > 0);

    let after = client.expect_ok("server_status", json!({})).await;
    assert!(
        after["operation_in_flight"].is_null(),
        "the lease must be released when the tool returns"
    );
    client
        .expect_ok("detach_process", json!({ "restore_frozen_values": false }))
        .await;

    let client = std::sync::Arc::try_unwrap(client).ok().expect("sole owner");
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_attach_over_mcp_without_a_valid_allowlist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = dir.path().join("allowlist.json");
    for contents in [
        None,
        Some("invalid JSON"),
        Some(r#"{"schema":1,"entries":[]}"#),
        Some(r#"{"schema":1,"entries":[{"path":"missing","sha256":"wrong"}]}"#),
    ] {
        if let Some(contents) = contents {
            std::fs::write(&allowlist, contents).expect("write legacy config");
        }
        let fixture = Fixture::start("x64");
        let client = Client::start(&allowlist, false).await;
        let status = client.expect_ok("server_status", json!({})).await;
        assert_eq!(status["target_selection"], "unrestricted");
        assert_eq!(status["denied_roots"], json!([]));
        let attached = client
            .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
            .await;
        assert_eq!(attached["session"]["pid"], fixture.pid());
        let value = client
            .expect_ok(
                "read_memory",
                json!({
                    "address": format!("0x{:x}", fixture.counter_address()), "value_type": "int32"
                }),
            )
            .await;
        assert_eq!(value["decoded"]["value"], "100");
        client.expect_ok("detach_process", json!({})).await;
        let attached = client
            .expect_ok("attach_process", json!({ "pid": std::process::id() }))
            .await;
        assert_eq!(attached["session"]["pid"], std::process::id());
        client.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_wow64_fixture_is_analysable_over_mcp_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x86");
    let fixture = Fixture::start("x86");
    let client = Client::start(&allowlist, false).await;

    let attached = client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;
    assert_eq!(attached["session"]["architecture"], "x86_wow64");
    assert_eq!(attached["session"]["pointer_width_bytes"], 4);

    let slot = fixture.area("block") + fixture.layout("pointer_root");
    let pointer = client
        .expect_ok(
            "read_memory",
            json!({ "address": format!("0x{slot:x}"), "value_type": "pointer" }),
        )
        .await;
    assert_eq!(pointer["actual_bytes"], 4);
    let reported = pointer["decoded"]["raw_value"]
        .as_str()
        .expect("the pointer value as a decimal string")
        .parse::<u64>()
        .expect("decimal");
    let expected = u64::from_str_radix(
        fixture.meta["pointer_chain"]["node1"]
            .as_str()
            .expect("node1")
            .trim_start_matches("0x"),
        16,
    )
    .expect("hex");
    assert_eq!(
        reported, expected,
        "the canonical form is zero-padded to the target width, so compare numerically"
    );
    assert_eq!(
        pointer["decoded"]["value"]
            .as_str()
            .expect("canonical pointer")
            .len(),
        10,
        "a WOW64 pointer is canonicalised as 0x plus eight hex digits"
    );

    let too_high = client
        .expect_failure(
            "read_memory",
            json!({ "address": "0x7ff600001234", "value_type": "int32" }),
        )
        .await;
    assert_eq!(too_high["code"], "UNSUPPORTED_POINTER_WIDTH");

    client.shutdown().await;
}

#[test]
fn the_fixtures_and_server_binary_exist() {
    assert!(fixture_exe("x64").exists());
    assert!(fixture_exe("x86").exists());
    assert!(server_exe().exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdout_stays_protocol_clean_even_at_debug_logging() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let fixture = Fixture::start("x64");

    let mut command = tokio::process::Command::new(server_exe());
    command
        .arg("serve")
        .env("MEMSCOPE_ALLOWLIST", &allowlist)
        .env("MEMSCOPE_LOG", "debug")
        .env("MEMSCOPE_ALLOW_WRITE", "1");
    let transport = TokioChildProcess::new(command).expect("spawn");
    let service = ()
        .serve(transport)
        .await
        .expect("the handshake must survive debug-level diagnostics");

    let status = service
        .call_tool(call_params("server_status", json!({})))
        .await
        .expect("a tool call must still parse");
    assert_ne!(status.is_error, Some(true));

    let attached = service
        .call_tool(call_params(
            "attach_process",
            json!({ "pid": fixture.pid() }),
        ))
        .await
        .expect("attach must parse");
    assert_ne!(
        attached.is_error,
        Some(true),
        "attach logs at info and warn; the response must still be clean JSON-RPC"
    );

    for _ in 0..20 {
        let read = service
            .call_tool(call_params(
                "read_memory",
                json!({
                    "address": format!("0x{:x}", fixture.counter_address()),
                    "value_type": "int32"
                }),
            ))
            .await
            .expect("every response must remain parseable");
        assert_ne!(read.is_error, Some(true));
    }

    let _ = service.cancel().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_scan_stops_and_reports_cancellation_rather_than_a_false_total() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let fixture = Fixture::start("x64");
    let client = Client::start(&allowlist, false).await;

    client
        .expect_ok("attach_process", json!({ "pid": fixture.pid() }))
        .await;

    let cancelled = client
        .expect_ok(
            "first_scan",
            json!({
                "value_type": "int32",
                "operator": "exact",
                "needle": { "kind": "int", "value": "100" },
                "budget": { "display_limit": 10, "max_results": 1000000,
                            "max_snapshot_bytes": 33554432,
                            "max_bytes_scanned": 65536, "timeout_ms": 20000 }
            }),
        )
        .await;
    assert_eq!(
        cancelled["stop_reason"], "max_bytes_scanned",
        "a budget stop must be named, not hidden"
    );
    assert_eq!(cancelled["truncated"], true);
    assert_eq!(cancelled["total_matches_known"], false);
    assert!(
        cancelled.get("total_matches").is_none(),
        "a truncated scan must withhold the total entirely"
    );

    let timed_out = client
        .expect_ok(
            "first_scan",
            json!({
                "value_type": "int32",
                "operator": "unknown",
                "budget": { "display_limit": 10, "max_results": 1000000,
                            "max_snapshot_bytes": 1073741824,
                            "max_bytes_scanned": 4294967296u64, "timeout_ms": 1 }
            }),
        )
        .await;
    assert!(
        timed_out["stop_reason"] == "timeout"
            || timed_out["stop_reason"] == "max_snapshot_bytes"
            || timed_out["stop_reason"] == "completed",
        "got {}",
        timed_out["stop_reason"]
    );
    if timed_out["stop_reason"] != "completed" {
        assert_eq!(timed_out["truncated"], true);
        assert_eq!(timed_out["total_matches_known"], false);
    }

    let scan_state_gone = client
        .expect_ok("list_results", json!({ "offset": 0, "limit": 5 }))
        .await;
    assert!(
        scan_state_gone["retained"].as_u64().is_some(),
        "scan state must survive a truncated scan so it can still be narrowed"
    );

    client.shutdown().await;
}
