# MemScope architecture and safety notes

This file is where the rationale lives: unsafe invariants, non-obvious
correctness constraints, and the decisions a reader would otherwise have to
reverse-engineer. Keep it current when the code changes.

## 1. Module split

the original specification requires policy, Win32 process access, memory decoding,
scanning, pointer analysis, mutation lifecycle, and MCP transport to be
separately testable.

| Module | Responsibility | Phase | State |
|---|---|---|---|
| `src/error.rs` | The 21 named operation-failure codes, plus `OPERATION_IN_FLIGHT`, and their context | - | Done |
| `src/wire.rs` | Wire representation: addresses, 64-bit integers, floats, hex | - | Done |
| `src/diag.rs` | Stderr-only diagnostics with a level threshold | - | Done |
| `src/win.rs` | RAII handle ownership, wide strings, OS error reporting | - | Done |
| `src/policy.rs` | Target metadata, canonical paths, optional SHA-256, legacy API compatibility | 2 | Done |
| `src/target.rs` | Process discovery, least-privilege handles, session identity | 2 | Done |
| `src/mem.rs` | Typed and raw reads, decoding, completeness, float semantics | 3 | Done |
| `src/scan.rs` | Regions, first/next scans, baselines, kernels, `group_scan` | 4, 5 | Done |
| `src/kernel.rs` | Scalar and AVX2 comparison kernels, optimised pattern search | 10 | Done |
| `src/investigate.rs` | `watch_value`, `dissect_region`, evidence levels, consistency | 5 | Done |
| `src/ptr.rs` | Modules, module-relative addressing, pointer paths and scans | 4, 6 | Done |
| `src/mutate.rs` | Writes, undo history, failure journal, freeze workers | 7, 8 | Done |
| `src/mcp.rs` | The 27 tools, schemas, stdio transport, error split, cancellation | 9 | Done |
| `src/bin/bench.rs` | Benchmark harness over the fixture's 128 MiB workload | 10 | Done |
| `src/bin/schemas.rs` | Generates `docs/tool-schemas.md` from the live router | 10 | Done |

`memscope serve` is a working MCP server: all 27 tools are reachable by a real
client over stdio. The earlier deliberate exit-1 stub is gone.

## 2. Process access

Target selection has no application-level restrictions. The server requests
specific Win32 query, read and write rights, and Windows grants or denies them.
Process ownership, installation location and legacy allowlist files do not
participate in selection. The implemented tools inspect and modify data through
the documented memory APIs.

## 3. Unsafe invariants

The Win32 FFI and SIMD implementation uses `unsafe` in `src/win.rs`,
`src/policy.rs`, `src/target.rs`, `src/mem.rs`, `src/scan.rs`, `src/ptr.rs`,
`src/mutate.rs`, and `src/kernel.rs`. The invariants each block relies on:

### `win::OwnedHandle`

* `from_raw` is `unsafe` because it claims ownership. The caller must pass a
  handle that is open, owned by this process, and closed by nothing else.
  Pseudo-handles — notably `GetCurrentProcess()`, which returns `-1` — must
  never be wrapped, because closing one is meaningless and the value is not an
  owned reference.
* `Drop` closes at most once: `Drop::drop` runs once per value, and the type is
  neither `Copy` nor `Clone`.
* A failed `CloseHandle` leaks a handle. It cannot be returned from `Drop`, and
  it must not be swallowed, because leaked handles are exactly what P2-08
  checks, so it is logged at `warn`.
* `Send`/`Sync` are implemented manually. Sound because a `HANDLE` is a kernel
  object reference, not a thread-affine pointer; the type exposes only `&self`
  access to the raw value, and the Win32 calls made with it are thread-safe.

### `win::error_message`

`FormatMessageW` receives a live `[u16; 512]` and is told exactly that length, so
it cannot write past the buffer. `FORMAT_MESSAGE_IGNORE_INSERTS` means no insert
arguments are read, so `Arguments` may be null;
`FORMAT_MESSAGE_FROM_SYSTEM` means `lpsource` is unused.

### `policy::canonicalise`

* The wide-string buffer passed to `CreateFileW` is NUL-terminated and outlives
  the call.
* `FILE_READ_ATTRIBUTES` with `FILE_SHARE_READ | WRITE | DELETE` cannot block a
  running image — opening a target's own executable must not interfere with it.
* `FILE_FLAG_BACKUP_SEMANTICS` is required so a *directory* can be opened, which
  is how denylist roots are canonicalised by the same code path as files.
* `GetFinalPathNameByHandleW` returns a length that **excludes** the terminating
  NUL when the buffer was large enough and **includes** it when it was not. The
  loop grows and retries on `len >= buffer.len()`, which is why the comparison is
  `>=` and not `>`.

## 4. Least-privilege access rights

Section 5.2 forbids `PROCESS_ALL_ACCESS` as a convenience default and requires
memory-access rights to be requested only after identity checks succeed. The
sequence is therefore two-stage:

| Stage | Rights requested | Purpose |
|---|---|---|
| Identify | `PROCESS_QUERY_LIMITED_INFORMATION` | Owner SID, executable path, creation time, WOW64 status |
| Attach (read) | `PROCESS_QUERY_LIMITED_INFORMATION \| PROCESS_VM_READ \| SYNCHRONIZE` | Reads, region enumeration, liveness waits |
| Mutate | `PROCESS_VM_WRITE \| PROCESS_VM_OPERATION` | Acquired separately, only for an authorised write |

`SYNCHRONIZE` is requested because `WaitForSingleObject` needs it; without it a
liveness check fails rather than reporting the process state.

Process access depends on the rights Windows grants the current token. A denial
is reported as `PERMISSION_DENIED` with the OS code preserved. The crate never
infers PPL status, protection level, or any other cause from `ERROR_ACCESS_DENIED`
alone.

## 5. Target selection and metadata

`Policy::default()` selects unrestricted targets. `Policy::load`, `reload`,
and `revalidate` remain source-compatible with existing callers, but legacy
allowlist contents are ignored. There are no denied roots or owner/self filters.

`Policy::authorise` now collects metadata: it tries filesystem canonicalisation
and falls back to the queried executable path; SHA-256 is best effort and is an
empty string if unavailable. A hash is not a pin or an access condition. Owner
SID lookup is also optional. Enumeration and periodic checkpoints do not hash
executables or read legacy configuration files.

`Session::ensure_identity` still checks liveness and the creation time of the
retained handle. Neither changing a file on disk nor editing an old allowlist
changes the identity of the running process. Windows errors retain their codes.

See [target-selection.md](target-selection.md) for the current behavior and tests.

## 6. Wire representation

Three JSON limitations drive `src/wire.rs`:

* A 64-bit integer does not survive a client's `double`, so `int64`/`uint64`
  cross the wire as decimal strings. On input a JSON *number* is accepted only
  when it is exactly representable; `18446744073709551616` is refused rather
  than rounded, because a client that sent it has already lost the value.
* `NaN` and the infinities are not JSON numbers. A non-finite float is reported
  as a tagged `FloatValue` whose `value` field is absent, so the output is always
  valid JSON.
* An address is width-dependent, so it is formatted for the **target's** pointer
  width, zero-padded, which also makes textual sorting match numeric order.

`FloatValue::repr` is Rust's shortest round-tripping decimal, so parsing it back
yields the identical float. For binary32 `0.1` that is `"0.1"` with wire bytes
`cd cc cc 3d` — the representation the original specification names. A different decimal rendering
after decoding is not a failed write.

## 7. Lint allowances

Two crate-level `allow`s, both deliberate:

* `clippy::result_large_err` — `OperationError` carries the code, message,
  operation, session and address context, Win32 code, and next step that section
  10 requires, which costs about 168 bytes. These errors are built at most once
  per tool call and never per candidate inside a scan or read loop, so the `Err`
  size has no measurable cost, while boxing it would add a conversion at every
  refusal site. Revisit if an error ever has to be returned per candidate.
* `clippy::missing_safety_doc` — the lint wants a `# Safety` doc comment on
  `unsafe fn`. Those invariants are recorded in §3 of this file instead.

## 8. Fixture design

See `fixtures/README.md` for the full layout, control-channel protocol, and build
dependencies. Two constraints worth repeating here because they govern how
server results are judged:

* Values are read through `Marshal.Read*` on a `GCHandle`-pinned buffer, so the
  fixture reports what is really in memory rather than a JIT-cached copy. That is
  what makes "the fixture itself confirmed the write" independent evidence.
* The external-change watcher is **polling, not instrumentation**. It cannot
  claim to have seen every intermediate write, only that the value is no longer
  what the fixture last put there.

Two real defects were found by the fixture's own acceptance checks and are worth
recording:

1. The initial counter write did not seed the watcher's baseline, so the first
   poll reported a change nothing had made. That would have made every Phase 7
   "the fixture observed the server's write" claim worthless.
2. The watcher read the counter *outside* the lock and compared it *inside*, so a
   self-mutation tick landing between the two looked like an external change.
   Both the read and the comparison now happen under the lock, and the
   self-mutation thread re-checks the pause flag under the lock before writing.

## 9. Comparison kernels and the parallelism decision

`src/kernel.rs` holds a scalar and an AVX2 kernel for 4- and 8-byte exact
matching, plus `memchr`-backed searches for exact byte strings and wildcard
patterns.

**Safety.** The two AVX2 functions are `#[target_feature(enable = "avx2")]
unsafe fn`, reached only through `find_exact_4`/`find_exact_8`, which dispatch on
`std::arch::is_x86_feature_detected!("avx2")` at run time and fall back to the
scalar path otherwise. Inside those functions the only raw-pointer operation is
`_mm256_loadu_si256` on `haystack.as_ptr().add(offset)`, where `offset` is bounded
by `aligned_end = (haystack.len() / step) * step`, so a full vector always lies
inside the slice. The remaining `step - 1` tail bytes are handled by the scalar
path, which is why the SIMD function ends by calling it on the remainder.

**Equivalence is tested, not assumed.** Four tests assert the kernels produce
identical results, including on buffers that are deliberately not a whole number
of vectors (0 to 11 trailing values), so the fast path cannot be faster by
finding less.

**Where it is used.** `first_scan` builds a `FastPath` before the sweep and takes
it only when the comparison is genuinely bitwise: integer or pointer `exact`
always, float `exact` **only** when the caller asked for `FloatCompare::Exact`.
The default float comparison is tolerance-based, and a bitwise match would
silently change its semantics, so that case stays on the generic path. Ordering
and delta operators cannot be bitwise and stay on the generic path too.

**Why the sweep is not parallel.** the original specification asks for bounded chunk
parallelism to be benchmarked. It was: rayon over AVX2 across 8 threads measured
**×1.01** (`docs/benchmarks.md` §2), because at ~51 GB/s a single core already
saturates memory bandwidth for this access pattern. Wiring the kernel in moved the
bottleneck to `ReadProcessMemory` at ~6.3 GB/s, so parallel *capture* — not
parallel comparison — is the next optimisation. It is not implemented, and no
claim is made about it.

## 10. MCP layer structure

**Two locks, and a lease.** `MemScope` holds `Arc<Mutex<Policy>>` separately
from `Arc<Mutex<ServerState>>`, and they are never acquired in the opposite
order. Neither is held while a long-running tool works. Each of the six takes an
`OperationLease` first: under a short state lock it runs the identity checkpoint,
duplicates the target handle, checks the scan state out of the server when it
needs one, and records itself as the active operation. The lock is released for
the whole scan, so `server_status`, the reads, the writes and the freeze tools
are answered while it runs, and the per-chunk authorisation closure still takes
only the policy lock.

The lease is what makes releasing the lock safe. It owns the duplicated handle,
so the work reads through a handle nothing else can close — a freeze worker's
reasoning, applied to a request. Its `Drop` puts the scan state back and clears
the active operation on the error and panic paths as well as the success path,
and reinstalls nothing if the session has gone meanwhile. While a lease is held,
a second long-running tool and `detach_process` are refused with
`OPERATION_IN_FLIGHT` rather than queued behind it; `list_results` and
`reset_scan` are refused only when the running tool is the one holding the scan
state, so a checked-out scan state is never reported as a missing one. The
refusal names the running tool and how long it has been running, and
`server_status` reports the same under `operation_in_flight`.

**What stays serialised.** The short tools still take the state mutex for the
length of their own work, so two reads are served one after the other rather
than in parallel. Writes and freezes are deliberately *not* blocked by a running
scan: a freeze worker could already write during one, and a scan reports `live`
consistency precisely because the target is never held still.

**Cancellation.** The six long-running tools run their work on
`tokio::task::spawn_blocking` and wire the request's `CancellationToken` to the
scan engine's `Cancel` flag through a watcher task, so a client cancellation stops
a sweep mid-flight rather than after it. The short tools stay synchronous.

**Error channel.** A named operation failure is `Ok(CallToolResult::error(...))`
carrying the serialised `OperationError` as both text and structured content, so
the caller actually reads it. `Err(McpError)` is reserved for unroutable
requests. Observed and worth recording: rmcp 3.8 reports an unknown tool as
`-32602` INVALID_PARAMS rather than `-32601` METHOD_NOT_FOUND.

**Protocol revision.** 2025-11-25 is negotiated because it is
`LATEST_WITH_INITIALIZE` in this SDK; revision 2026-07-28 removes the
`initialize` handshake that current clients rely on.

**Freeze worker handles.** Each worker duplicates the session's read and write
handles with `win::duplicate_for_worker` and owns the copies, so a worker can
never outlive a borrowed handle. That is what makes `stop_all` on detach a safety
convenience rather than a safety requirement. `OperationLease` duplicates the
read handle through the same function for the same reason.
