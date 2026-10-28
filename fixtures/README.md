# MemScope test fixtures

The deterministic test targets required by the original specification. One C#
source builds both architectures; one small native module supplies the only
thing a managed process cannot: a stable module-relative pointer root.

| File | Role |
|---|---|
| `MemScopeFixture.cs` | The fixture. Pinned buffers, named-pipe control channel, independent observation. |
| `anchor/anchor.c`, `anchor/anchor.def` | Companion native module holding the module-relative pointer root. |
| `build.ps1` | Builds `bin/x64` and `bin/x86`. |
| `verify.ps1` | Acceptance checks for P1-04, P1-05, P1-06. |

## Build

```powershell
& fixtures/build.ps1           # both architectures
& fixtures/build.ps1 -Clean    # delete bin/ first
```

Outputs, each architecture in its own directory because the companion module
must keep the file name `memscope_anchor.dll` in both builds:

```
fixtures/bin/x64/memscope-fixture.exe   fixtures/bin/x64/memscope_anchor.dll
fixtures/bin/x86/memscope-fixture.exe   fixtures/bin/x86/memscope_anchor.dll
```

### Build dependencies

| Dependency | Used for |
|---|---|
| `%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (C# compiler 4.8.9221.0) | Both fixture executables, via `/platform:x64` and `/platform:x86` |
| MSVC `cl.exe`/`link.exe` 19.51.36248 (toolset 14.51.36231), reached through `vcvarsall.bat` | `memscope_anchor.dll` for both architectures |
| `vswhere.exe` in `%ProgramFiles(x86)%\Microsoft Visual Studio\Installer` | Locating `vcvarsall.bat` |

Two host-specific details `build.ps1` handles, both discovered by failure here:

* `vswhere -latest` returns SQL Server Management Studio on this host, which
  ships no VC build tools. The script enumerates every install and takes the
  first that actually has `vcvarsall.bat`.
* `vcvarsall.bat` delegates to `vsdevcmd`, which invokes `vswhere.exe` as a bare
  command name. It is not on this host's `PATH`, so the script prepends the
  Installer directory for the duration of one `cmd` process.

Compiler flags that matter:

* `csc /optimize-` — nothing the fixture reports can be dismissed as an
  optimisation artefact.
* `cl /MT` — static CRT, so neither DLL needs a separately installed
  redistributable.
* `cl /W4 /WX` — the x86 build caught a real pointer-truncation bug in
  `anchor.c` this way (`0xA1A1A1A1` cast through `unsigned long long`); the
  root is now cast through `uintptr_t`.
* `/DEF:anchor.def` — a `__cdecl` function exported with
  `__declspec(dllexport)` is decorated differently on x86 than on x64. The `.def`
  gives both builds the same undecorated export names, so one `DllImport`
  declaration works for both.

## Why the values live where they do

Every observable value sits in a byte buffer pinned with a `GCHandle`, and is
read back through `Marshal.Read*` rather than from a managed field:

1. A pinned buffer cannot be relocated by the GC, so the address printed at
   startup stays valid for the whole run.
2. Reading through `Marshal.Read*` means the fixture reports what is really in
   memory, not a copy the JIT parked in a register. That is what makes "the
   fixture itself confirmed the server's write" an independent observation
   rather than a restatement of the server's own read-back.

## Startup metadata

The fixture prints one JSON line, then the bare sentinel `ready`, then waits for
a control-channel connection. The pipe exists before the JSON is printed, so a
test that has read `ready` can connect immediately.

Tests must take offsets, addresses and dataset facts from this metadata rather
than hardcoding them. Keys: `pid`, `arch`, `pointer_size`, `wow64`, `exe`,
`pipe_name`, `pipe_path`, `areas`, `layout`, `pointer_chain`, `datasets`,
`strings`.

## Memory layout

### Scalar block (`areas.block`, 256 bytes, pinned)

Offsets are also emitted in `layout`.

| Offset | Type | Value |
|---|---|---|
| `0x00` | uint32 | sentinel `0xA5A5A5A5` |
| `0x04` | int32 | **the mutable counter**, initially 100 |
| `0x08` | uint32 | sentinel `0x5A5A5A5A` |
| `0x0C`–`0x0F` | int8/uint8 | `-128`, `127`, `0`, `255` |
| `0x10`–`0x17` | int16/uint16 | min and max of each |
| `0x18`–`0x27` | int32/uint32 | min and max of each |
| `0x28`–`0x3F` | int64/uint64 | `i64::MIN`, `i64::MAX`, `u64::MAX` |
| `0x40` | binary32 | `0.1` → bytes `cd cc cc 3d` |
| `0x44`, `0x48`, `0x4C` | binary32 | NaN, `+inf`, `-0.0` |
| `0x50`, `0x58`, `0x60` | binary64 | `0.1`, `-inf`, NaN |
| `0x68` | pointer | → `node1`; occupies 4 or 8 bytes by build |
| `0x68 + pointer_size` | uint64 | `0xDEADBEEFCAFEBABE` |
| `0x80`–`0xFF` | bytes | scratch, `0xCC` filled, for write/undo tests |

The counter is flanked by sentinels so a write that runs long is visible, and
the guard word sits immediately after the pointer at *this build's* width — so a
WOW64 pointer read as 8 bytes yields a visibly wrong value instead of
accidentally correct zeroes (specification P6-04).

The scratch region is `0xCC`, not zero: a stray NUL would hand a string read a
terminator it was supposed to have to find for itself.

### Strings (`areas.strings`, 256 bytes, pinned)

Filler is `0xFF`, never `0x00`, so a missing-terminator case cannot be rescued by
neighbouring zeroes.

| Offset | Case |
|---|---|
| `0x00` | UTF-8 `memscope-utf8`, NUL-terminated |
| `0x20` | UTF-8 `no-terminator`, **no** terminator |
| `0x40` | UTF-8 `48 69 FF FE 00` — "Hi", two invalid bytes, terminator |
| `0x50` | UTF-16LE `memscope-utf16`, two-byte terminator |
| `0x80` | UTF-16LE `no-term`, **no** terminator |
| `0xA0` | UTF-16LE `00 D8 41 00 00 00` — lone high surrogate U+D800, `A`, terminator |

The terminated UTF-16 cases already exercise code-unit boundaries: every ASCII
character carries a `0x00` high byte, so a reader that scans for a single zero
byte stops after one character.

### Pointer chain

The root is **not** a managed address. It is `g_anchor_root`, one pointer in the
writable data section of `memscope_anchor.dll`, so it has a real RVA:

```
memscope_anchor.dll + root_rva     ->  node1
node1 + 0x10                       ->  node2
node2 + 0x08                       ->  leaf
leaf  + 0x00                       ->  int32 1337
```

`pointer_chain` reports `anchor_base`, `root_address`, `root_rva`,
`deref_offsets` `[0, 16, 8]`, `final_offset` `0`, every node address, and
`leaf_value`.

**Proof of the root's identity** (the specification requires this, not an assertion):

* `verify.ps1` checks `anchor_base + root_rva == root_address`. The fixture
  obtains `anchor_base` from `GetModuleHandleW` and `root_address` from the
  module's own `anchor_root_address()`, so the two sides come from independent
  sources.
* On this host `root_rva` is `0xac000` — a data-section offset, not a heap
  address. The check also asserts it is non-zero and below 2 MiB.
* The fixture refuses to start if `Marshal.ReadIntPtr(root_address) != node1`,
  so a run that reaches `ready` has already proved the root points where the
  metadata claims.
* `anchor_base` differs between runs (ASLR) while `root_rva` does not. That is
  exactly the property Phase 6 restart validation needs.

### Deterministic scan datasets

| Area | Content |
|---|---|
| `duplicates` | 1024 copies of int32 `0x11223344` — duplicate-match handling |
| `boundary` | 128 KiB; int32 `0x7EEDBEEF` straddling the 64 KiB mark at `+65534`, so a chunked sweep must stitch chunks to find it (P4-08) |
| `noaccess` | 4 KiB `PAGE_NOACCESS` — must be reported excluded, never read as zeroes |
| `guard` | 4 KiB `PAGE_READWRITE \| PAGE_GUARD` — must be reported excluded |
| `protect` | 4 KiB whose protection changes at runtime via `protect` |
| `bench` | `--bench` only: 128 MiB (134 217 728 bytes) |

The benchmark workload is a documented LCG (`state = state * 1103515245 + 12345`,
seed `0x1234ABCD`) with `0x4D454D53` planted every 1 000 000 int32 slots. The
match count is **measured during the fill**, not assumed, because the LCG could
produce the planted value itself. Observed on this host: `bench_matches = 34`,
i.e. the 34 planted slots and no coincidences.

## Control channel

A per-run named pipe, `\\.\pipe\memscope-fixture-<32 hex>`. A named pipe rather
than stdin because the server is a separate process that did not launch the
fixture; a fresh GUID per run so concurrent fixtures never collide.

Lines are UTF-8, newline-terminated, bounded at 4096 bytes — an over-long line
drops the connection rather than guessing.

| Command | Reply | Notes |
|---|---|---|
| `ping` | `pong` | |
| `get` | `value=<int32>` | Read through memory every time |
| `set <n>` / `add <n>` / `sub <n>` | `value=<int32>` | int32 range enforced; wrapping is explicit |
| `read <hexaddr> <len>` | `bytes=<hex> area=<name>` | Only inside a known readable area; `len` ≤ 256 |
| `peek <area>` | `bytes=<hex> area=<name> base=0x…` | First ≤256 bytes |
| `tick <ms>` | `tick=<ms>` | Self-mutation every `ms`; `0` stops; else 10–10000 |
| `churn <ms>` | `churn=<ms>` | Increments the counter in a **tight loop** for `ms` (0–5000). Exists so the Phase 7 write-verification failure path can be exercised: a 10 ms tick leaves too small a window between a write and its read-back. |
| `pause` / `resume` | `paused=1` / `resumed=1` | The cooperative pause protocol the specification prefers |
| `protect <noaccess\|rw>` | `protect=<state> previous=0x<old>` | |
| `externals` | `external_changes=<n> last=<value>` | **Independent** observation of writes the fixture did not make |
| `chain` | `root=… node1=… node2=… leaf=… value=…` | Every hop re-read from memory now |
| `layout` | the startup JSON | |
| `exit` | `bye` | Graceful; frees pins and returns 0 |

Unknown or malformed input is refused by name: `err=unknown_command`,
`err=not_an_integer`, `err=length_out_of_range`, `err=interval_out_of_range`,
`err=address_outside_readable_fixture_area`,
`err=area_is_deliberately_inaccessible`.

`read` is restricted to known readable areas on purpose. The fixture must not
become a general-purpose memory reader, and must not crash on a bad address from
a test.

### Independent observation

A background thread polls the counter every 25 ms and compares it with the value
the fixture itself last wrote. A mismatch increments `external_changes`, records
the new value, and prints `external_change=<old>-><new>` on stdout. This is how
a server write is confirmed in Phase 7 without trusting the server's read-back.

It is **polling, not instrumentation**: it cannot claim to have seen every
intermediate write, only that the value is no longer what the fixture put there.

`verify.ps1` asserts `external_changes=0` at the end of a run in which only the
fixture wrote. That check caught a real defect: the initial counter write did not
seed the watcher's baseline, so the first poll reported a change nothing had
made — which would have made the Phase 7 evidence worthless.

## Verify

```powershell
& fixtures/verify.ps1                  # x64 and x86
& fixtures/verify.ps1 -Arch x64 -Bench # include the 128 MiB workload
```

Exit code 0 only if every check passes. Observed 2026-10-27: **85/85 pass**
across both architectures; **45/45** for x64 with `-Bench`.

These checks exercise the fixture, not MemScope. They are what makes later
server results trustworthy; they prove nothing about the server itself.
