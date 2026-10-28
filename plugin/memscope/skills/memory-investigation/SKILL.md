---
name: memory-investigation
description: Use the MemScope MCP server to find, validate, watch or change values in a live Windows process, including pointer paths and restart validation when needed.
---

# Investigating a live process

This plugin registers the `memscope` MCP server from the binary named by the
`MEMSCOPE_BIN` environment variable. It starts read-only. Its tools appear as `mcp__memscope__*`.

## The workflow

Choose the steps needed for the user's task and continue through verification.
The sequence below is a complete investigation example, not a requirement to
perform every step before a simple read or write. Validate across a restart when
the task requires a location that survives restarts. Select routine scan and
read parameters independently within the server's resource limits.

1. **Discover.** `server_status` — tool count, limits, target selection, whether
   writes are possible. `list_processes` — PID, owner, architecture, and any
   Windows access limitation.
2. **Attach.** `attach_process {"pid": N}` binds a session to the handle, PID,
   creation time and executable identity. Any PID may be selected; Windows
   decides whether the token can obtain the handle.
3. **Map.** `list_modules`, `list_regions`. Every excluded region states why —
   `not_committed`, `no_access`, `guard_page`, `not_readable`,
   `outside_address_range`.
4. **Inspect.** `read_memory` returns the decoded value *and* the raw bytes,
   requested and actual sizes, a `complete` flag, an observation timestamp,
   elapsed time and the consistency mode. `read_batch`, `read_bytes`,
   `read_struct` for the wider shapes.
5. **Search.** `first_scan` with an explicit operator, region filter and budget.
   Always set the budget — an unbudgeted scan on a large process is how a
   session stalls.
6. **Narrow.** Change the value through the target's own interface, then
   `next_scan {"operator": "changed"}`. The response names the scan it compared
   against, so `previous_scan` and `initial_baseline` are never confused.
7. **Validate.** `list_results {"reread_current": true}` returns the captured
   match *and*, separately, the value now. `group_scan` confirms neighbouring
   fields. `dissect_region` suggests nearby structure, labelled heuristic.
8. **Stabilise.** `resolve_address` and `resolve_pointer_path` express the
   location as a module offset or a pointer path. `pointer_scan` finds candidate
   paths and re-resolves each before reporting it.
9. **Survive a restart.** Restart the target, re-attach, `rescan_pointer_paths`
   — it separates `survived`, `broken`, `resolved_elsewhere` and
   `resolved_unverified`.
10. **Modify.** Both gates must be open (below). The response carries the
    original bytes, `bytes_written`, the read-back bytes and `verified`. Confirm
    the change through the target itself, not through the server's read-back.
11. **Observe and restore.** `freeze_value` holds a value with a bounded worker;
    `list_frozen` shows measured tick latency and correction counts;
    `unfreeze_value` stops and joins the worker before any optional restore;
    `undo_write` reverts within the bounded undo history.
12. **Close.** `detach_process` stops every worker, clears scan and undo state,
    and reports what it cleared. Always close a session you opened.

## The two write gates

Both are required, and neither implies the other:

- `MEMSCOPE_ALLOW_WRITE=1` in the server's environment, read at startup only.
  Exactly `1` — `true`, `yes` and `on` are rejected on purpose. Changing it
  means editing the plugin's `.mcp.json` and restarting the session.
- `confirm: true` on each mutating call.

An explicit request to change, freeze or restore a value in an identified target
authorizes the corresponding calls. Discover and validate the address when that
is part of the task, then use `confirm: true` without asking for the same
authorization again. Record the address, original value, intended value and
verification result. Authorization already given in the conversation persists
within its scope; a new session alone does not require another question.

Ask only if the target, intended effect or authorization is materially unclear,
or the next action would expand the agreed scope. Read or analysis requests
alone do not authorize writes. Any PID may be selected subject to Windows access;
do not add application, owner or installation-path exclusions.

## Reporting rules

These are the server's honesty rules; a report that softens them is wrong even
when the numbers are right.

- Unread bytes are never zero-filled. A partial read reports the prefix it got,
  with the Win32 error and the exact byte count.
- A typed scalar needs all its bytes, or it is `PARTIAL_READ`.
- A truncated scan withholds its total and names the stop reason. Display
  pagination is not truncation.
- Matches come from the captured bytes; a later reread is reported separately,
  with its own timestamp, never in place of the match.
- One candidate is not proof. Evidence is `candidate`, `behaviour_correlated` or
  `restart_validated` — use the server's label, and say what test produced it.
- Dissection is heuristic. No compiler layout, debug information or symbol table
  is consulted.
- `watch_value` is bounded polling, not instrumentation. It cannot see every
  intermediate write and reports failed and dropped samples — quote those.
- `consistency = paused` is refused with `CONSISTENCY_UNAVAILABLE`. No target
  thread is ever suspended.

Distinguish what was observed from what was inferred, in that vocabulary.
