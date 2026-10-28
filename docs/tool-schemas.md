# MemScope tool schemas

Generated from the live tool router by `cargo run --bin schemas`, so this file cannot
drift from the registered tools. 27 tools.

A tool failure arrives as a tool **result** with `is_error` set and structured
content carrying `code`, `message`, `operation`, session and address context, the
Win32 code when one exists, and a next step. Only an unroutable request is a
JSON-RPC protocol error. See the error codes in README.md.

## `server_status`

Report server capabilities, limits, policy state, and the attached session.

Takes no parameters.

## `list_processes`

Enumerate processes with owner, architecture, and Windows access limitations.

Takes no parameters.

## `attach_process`

Attach to any PID Windows permits, binding a session to its handle, creation time and executable identity.

| Field | Type | Required | Notes |
|---|---|---|---|
| `pid` | `integer` | required | |

## `detach_process`

Stop all workers, clear scan and undo state, and release the session. Optionally restore frozen values first.

| Field | Type | Required | Notes |
|---|---|---|---|
| `confirm` | `boolean` | optional | |
| `restore_frozen_values` | `boolean` | optional | |

## `list_regions`

Enumerate memory regions with mapping metadata, module attribution, and every applicable exclusion reason.

| Field | Type | Required | Notes |
|---|---|---|---|
| `filter` | `RegionFilter` | optional | |

## `first_scan`

Start a scan with an explicit operator, region filter, alignment and resource budget.

| Field | Type | Required | Notes |
|---|---|---|---|
| `operator` | `Operator` | required | |
| `value_type` | `ValueType` | required | |
| `alignment` | `integer` | optional | |
| `budget` | `ScanBudget` | optional | |
| `filter` | `RegionFilter` | optional | |
| `float_compare` | `FloatCompare (nullable)` | optional | |
| `needle` | `Needle (nullable)` | optional | |
| `needle_high` | `Needle (nullable)` | optional | |
| `pattern` | `string` | optional | |

## `next_scan`

Narrow the current scan against the previous scan or the initial baseline.

| Field | Type | Required | Notes |
|---|---|---|---|
| `operator` | `Operator` | required | |
| `baseline_source` | `BaselineSource` | optional | |
| `budget` | `ScanBudget` | optional | |
| `float_compare` | `FloatCompare (nullable)` | optional | |
| `integer_overflow` | `IntegerOverflow (nullable)` | optional | |
| `needle` | `Needle (nullable)` | optional | |

## `list_results`

Page through retained scan candidates. Pagination never discards undisplayed candidates.

| Field | Type | Required | Notes |
|---|---|---|---|
| `limit` | `integer` | optional | |
| `offset` | `integer` | optional | |
| `reread_current` | `boolean` | optional | |

## `reset_scan`

Discard the current scan state and report what was cleared.

Takes no parameters.

## `group_scan`

Find bases where several typed fields at fixed offsets all match, keeping field-level evidence.

| Field | Type | Required | Notes |
|---|---|---|---|
| `fields` | `array<GroupFieldSpec>` | required | |
| `alignment` | `integer` | optional | |
| `budget` | `ScanBudget` | optional | |
| `filter` | `RegionFilter` | optional | |
| `float_compare` | `FloatCompare (nullable)` | optional | |

## `read_memory`

Read one typed value with full provenance: raw bytes, requested and actual sizes, and timing.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `value_type` | `ValueType` | required | |
| `max_bytes` | `integer` | optional | |
| `max_chars` | `integer` | optional | |

## `read_batch`

Read several addresses with independent per-item outcomes. A batch is never an atomic snapshot.

| Field | Type | Required | Notes |
|---|---|---|---|
| `items` | `array<BatchItemRequest>` | required | |

## `read_bytes`

Read a bounded raw byte range, reporting the readable prefix honestly if the mapping ends.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `length` | `integer` | required | |

## `read_struct`

Read declared fields at caller-given offsets. No compiler packing is ever inferred.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `fields` | `array<StructFieldSpec>` | required | |
| `total_size` | `integer` | optional | |

## `list_modules`

List loaded modules with base, size and path, for module-relative addressing.

Takes no parameters.

## `resolve_address`

Resolve an absolute address, a module base, or module+offset, reporting the form and stability caveat.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |

## `pointer_scan`

Search for bounded pointer paths to an address, with cycle detection and reported index coverage.

| Field | Type | Required | Notes |
|---|---|---|---|
| `target` | `string` | required | |
| `filter` | `RegionFilter` | optional | |
| `max_depth` | `integer` | optional | |
| `max_index_bytes` | `integer` | optional | |
| `max_offset` | `integer` | optional | |
| `max_results` | `integer` | optional | |
| `offset_alignment` | `integer` | optional | |
| `require_module_base` | `boolean` | optional | |
| `timeout_ms` | `integer` | optional | |

## `resolve_pointer_path`

Walk a pointer path hop by hop using one documented dereference order, reporting every hop.

| Field | Type | Required | Notes |
|---|---|---|---|
| `base` | `string` | required | |
| `deref_offsets` | `array<integer>` | required | |
| `final_offset` | `integer` | optional | |

## `rescan_pointer_paths`

Re-resolve stored paths, separating survived, broken, resolved elsewhere, and resolved unverified.

| Field | Type | Required | Notes |
|---|---|---|---|
| `paths` | `array<StoredPointerPath>` | required | |
| `value_bytes` | `integer` | required | |

## `find_references`

Search readable memory for pointer-sized values equal to an address. A data search only; no instruction is decoded.

| Field | Type | Required | Notes |
|---|---|---|---|
| `target` | `string` | required | |
| `alignment` | `integer` | optional | |
| `filter` | `RegionFilter` | optional | |
| `max_bytes_scanned` | `integer` | optional | |
| `max_results` | `integer` | optional | |
| `timeout_ms` | `integer` | optional | |

## `watch_value`

Poll one address on a bounded schedule, reporting per-sample timestamps and the limits of polling.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `duration_ms` | `integer` | required | |
| `interval_ms` | `integer` | required | |
| `value_type` | `ValueType` | required | |
| `consistency` | `ConsistencyMode (nullable)` | optional | |
| `max_bytes` | `integer` | optional | |
| `max_samples` | `integer` | optional | |

## `dissect_region`

Suggest possible types, strings and pointers in a byte range. Every inference is labelled a heuristic.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `length` | `integer` | required | |
| `consistency` | `ConsistencyMode (nullable)` | optional | |
| `stride` | `integer` | optional | |

## `write_memory`

Write a pre-encoded payload after capturing the original bytes, then verify byte for byte. Requires MEMSCOPE_ALLOW_WRITE=1 and confirm=true.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `payload` | `WritePayload` | required | |
| `attempt_recovery_on_failure` | `boolean` | optional | |
| `confirm` | `boolean` | optional | |
| `expect_original_raw` | `string` | optional | |

## `undo_write`

Restore the original bytes of a retained write, refusing a conflict unless explicitly overridden. Requires both write gates.

| Field | Type | Required | Notes |
|---|---|---|---|
| `undo_id` | `string` | required | |
| `confirm` | `boolean` | optional | |
| `override_conflict` | `boolean` | optional | |

## `freeze_value`

Hold a value in place with a bounded worker using session-bound process handles. Requires both write gates.

| Field | Type | Required | Notes |
|---|---|---|---|
| `address` | `string` | required | |
| `interval_ms` | `integer` | required | |
| `lifetime_ms` | `integer` | required | |
| `payload` | `WritePayload` | required | |
| `confirm` | `boolean` | optional | |

## `unfreeze_value`

Stop and join a freeze worker, then optionally restore the pre-freeze bytes with both write gates.

| Field | Type | Required | Notes |
|---|---|---|---|
| `freeze_id` | `string` | required | |
| `confirm` | `boolean` | optional | |
| `restore_original` | `boolean` | optional | |

## `list_frozen`

List active and recently stopped freezes with worker state, measured timing, and retained stop reasons.

Takes no parameters.

## Shared value shapes

**`value_type`**: `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`,
`uint64`, `float` (IEEE-754 binary32), `double` (binary64), `string` (UTF-8),
`string16` (UTF-16LE), `bytes`, `pointer` (the target's width).

**`needle`** is tagged by `kind`:

```json
{ "kind": "int",   "value": "-42" }
{ "kind": "uint",  "value": "18446744073709551615" }
{ "kind": "float", "value": 0.1 }
{ "kind": "bytes", "hex": "cdcccc3d" }
```

`int` and `uint` take **decimal strings** so no 64-bit value is lost to a JSON
double. A JSON integer is accepted only when it is exactly representable.

**`payload`** for writes and freezes is tagged by `kind`:

```json
{ "kind": "typed", "value_type": "int32", "value": { "kind": "int", "value": "100" } }
{ "kind": "bytes", "hex": "cd cc cc 3d" }
{ "kind": "text",  "value_type": "string", "text": "hi", "include_terminator": false }
```

A wildcard pattern is never a valid write payload.
