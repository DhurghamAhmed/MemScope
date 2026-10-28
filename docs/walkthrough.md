# A complete walkthrough

Discovering a counter in the test fixture, proving it, and changing it. Every
step below is executed by
[`tests/phase9_mcp.rs`](../tests/phase9_mcp.rs) against a real client over stdio.

**1. Discover.** `server_status` reports the tool count, limits, target selection and
whether writes are possible. `list_processes` shows each PID with its owner,
architecture, and any Windows access limitation.

**2. Attach.** `attach_process {"pid": 1234}` requests the required Windows
access and binds a session to the handle, PID, creation time and executable
identity. Owner and executable hash information is optional metadata.

```json
{ "session": { "session_id": "s1-1234-6225f0a1b2", "architecture": "x64",
               "pointer_width_bytes": 8, "capabilities": { "read": true, "write": false } } }
```

**3. Map.** `list_modules` and `list_regions`. Every excluded region says why:
`not_committed`, `no_access`, `guard_page`, `not_readable`, `outside_address_range`, …

**4. Inspect.** `read_memory {"address": "0x...", "value_type": "int32"}` returns
the decoded value *and* the raw bytes, requested and actual sizes, a `complete`
flag, an observation timestamp, elapsed time and the consistency mode.

**5. Search.** `first_scan` with an explicit operator, region filter and budget:

```json
{ "value_type": "int32", "operator": "exact",
  "needle": { "kind": "int", "value": "100" },
  "filter": { "min_address": "0x1000000", "max_address": "0x2000000" },
  "budget": { "display_limit": 100, "max_results": 1000000,
              "max_snapshot_bytes": 536870912,
              "max_bytes_scanned": 4294967296, "timeout_ms": 30000 } }
```

**6. Narrow.** Change the value in the target by its own means, then
`next_scan {"operator": "changed"}`. The response names the scan it compared
against, so `previous_scan` and `initial_baseline` are never confused.

**7. Validate.** `list_results` with `reread_current: true` returns the captured
match *and*, separately, the value now — never one in place of the other.
`group_scan` confirms neighbouring fields; `dissect_region` suggests nearby
structure, labelled heuristic.

**8. Stabilise.** `resolve_address` and `resolve_pointer_path` express the
location as a module offset or a pointer path; `pointer_scan` finds candidate
paths and re-resolves each before reporting it.

**9. Validate across a restart.** Restart the target, re-attach, then
`rescan_pointer_paths`, which separates `survived`, `broken`,
`resolved_elsewhere` and `resolved_unverified`.

**10. Modify.** With both gates open:

```json
{ "address": "0x...", "confirm": true,
  "payload": { "kind": "typed", "value_type": "int32",
               "value": { "kind": "int", "value": "31337" } } }
```

The response carries the original bytes, `bytes_written`, the read-back bytes and
`verified`. Confirm the change through the target itself, not the server's
read-back.

**11. Observe and restore.** `freeze_value` holds a value with a bounded worker;
`list_frozen` shows measured tick latency and correction counts;
`unfreeze_value` stops and joins the worker *before* any optional restore.

**12. Close.** `detach_process` stops every worker, clears scan and undo state,
and reports what it cleared.
