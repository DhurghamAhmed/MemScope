# Semantics

What an address means, what a write guarantees, what a failure looks like, and
which protocol revisions the server speaks.

- [Addressing and pointer paths](#addressing-and-pointer-paths)
- [Write, undo and freeze](#write-undo-and-freeze)
- [Error codes](#error-codes)
- [Protocol revisions](#protocol-revisions)

## Addressing and pointer paths

Three address forms are accepted:

| Form | Example | Stability |
|---|---|---|
| Absolute | `0x7ff6000012a0` | This run of this process only |
| Module base | `game.dll` | Candidate for stability |
| Module + offset | `game.dll+0x1234` | Candidate for stability |

**One documented dereference order**, reported in every pointer-path response:

> Start at the base address. For each entry in `deref_offsets`, in order, add the
> offset to the current address and dereference the result as one target-width
> pointer, which becomes the new current address. After the last dereference, add
> `final_offset` **without** dereferencing; that sum is the value address.

Worked example against the test fixture, whose chain is
`anchor root → node1 → node2 → leaf`:

```json
{ "base": "memscope_anchor.dll+0xac000",
  "deref_offsets": [0, 16, 8],
  "final_offset": 0 }
```

Resolves as:

```
memscope_anchor.dll+0xac000   = 0x7ffbda5cc000   base
  +0  deref                   -> 0x039e3d60      node1
  +16 deref                   -> 0x039e3dc0      node2
  +8  deref                   -> 0x039e3e80      leaf
  +0  (no deref)              => 0x039e3e80      value address, holds int32 1337
```

A pointer is read at the **target's** width: four bytes for a WOW64 target, eight
for x64. A readable path proves neither identity nor stability.

## Write, undo and freeze

**Two independent gates.** `MEMSCOPE_ALLOW_WRITE=1` in the server environment
*and* `confirm: true` on the call. Restoration counts as a mutation, so
`undo_write` and a restoring `unfreeze_value` need both too.

**Before writing:** the payload is fully encoded and its exact length computed; a
value that does not fit its declared type is refused rather than truncated; a
wildcard pattern is refused outright; the range is checked for committed,
writable, whole-range coverage (page protection is never changed to force a
write); and the original bytes are captured completely, or the write is not
attempted.

**After writing:** the response reports requested bytes, original bytes,
`bytes_written`, read-back bytes and `verified`. `verified: true` means
byte-for-byte equality at the stated time — nothing more. For binary32 `0.1`,
`cd cc cc 3d` is correct, and a different decimal rendering after decoding is not
a failed write.

**On failure:** a short write or a failed read-back is **never** reported as
success and **never** produces an undo entry. It goes to a separate
failed-operation journal with its recovery evidence, including whether
restoration was attempted and whether it verified. The response states that
memory may already have changed.

**Strings** take `include_terminator`, default `false`. Trailing bytes are never
cleared implicitly.

**Undo** is bounded (entries and bytes, with evictions counted) and bound to the
session, PID and creation time, so an entry is never applied to a different or
restarted process. Before restoring, the current bytes are compared with what was
written; a mismatch is `UNDO_CONFLICT` and the entry is retained unless the
caller explicitly overrides.

**Freeze is a worker, not an undo entry.** Its repeated writes never enter undo
history. Interval and lifetime are bounded, pre-freeze bytes are captured once,
tick latency is measured, and the worker uses session-bound process handles. The
frozen range refuses overlapping writes and undos with `ADDRESS_FROZEN`. Stopping
a freeze restores bytes only when requested with both write gates enabled.

## Error codes

A tool failure arrives as a **tool result** with structured content carrying
`code`, `message`, `operation`, session and address context, the Win32 code when
one exists, and an actionable next step. Only an unroutable request is a JSON-RPC
protocol error.

`INVALID_ARGUMENT`, `NOT_ATTACHED`, `TARGET_NOT_ALLOWED`, `PERMISSION_DENIED`,
`PROCESS_GONE`, `PROCESS_REPLACED`, `INVALID_ADDRESS`, `PARTIAL_READ`,
`DECODE_ERROR`, `WRITE_DISABLED`, `CONFIRMATION_REQUIRED`, `PARTIAL_WRITE`,
`VERIFY_FAILED`, `ADDRESS_FROZEN`, `UNDO_CONFLICT`, `UNSUPPORTED_ARCHITECTURE`,
`UNSUPPORTED_POINTER_WIDTH`, `CONSISTENCY_UNAVAILABLE`, `SCAN_STATE_INVALID`,
`BUDGET_EXCEEDED`, `CANCELLED`.

One code is defined beyond those twenty-one: `OPERATION_IN_FLIGHT`, returned when
a long-running tool holds the session and the call would have had to wait for it.
It is the one retryable refusal here — the message names the running tool and how
long it has been running, and the next step is to wait or to cancel that request.

The underlying OS code is preserved when the exact cause is unknown, and a hint
always addresses the identified failure — "run elevated" is never offered as a
generic fix.

## Protocol revisions

The server negotiates **2025-11-25** and also accepts 2025-06-18, 2025-03-26 and
2024-11-05. Revision 2026-07-28 is deliberately not offered, because it removes
the `initialize` handshake that current clients rely on.
