# MemScope

A local MCP server that inspects the memory of **Windows processes**, explains
the evidence behind every result, and — only when two
separate gates are open — performs verified memory changes.

Written for operators who need to understand Windows processes: 27 named tools
over stdio, unrestricted target selection, and output that distinguishes what was
observed from what was inferred.

One command, no runtime to install first:


## Contents

- [Install](#install)
- [Capabilities](#capabilities)
- [Agents](#agents)
- [Requirements](#requirements)
- [Target selection](#target-selection)
- [Environment variables](#environment-variables)
- [Tool reference](#tool-reference)
- [Honesty rules](#honesty-rules)
- [Limitations](#limitations)
- [Documentation](#documentation)
- [Intended use](#intended-use)

## Install

```powershell
irm https://raw.githubusercontent.com/DhurghamAhmed/MemScope/main/install.ps1 | iex
```

It downloads the latest `memscope.exe`, refuses to install it unless the
SHA-256 matches the published `SHA256SUMS.txt`, puts it in
`%LOCALAPPDATA%\Programs\memscope`, and sets `MEMSCOPE_BIN`. Add `-Skills` to
install the investigation skill into `.claude/skills` as well:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/DhurghamAhmed/MemScope/main/install.ps1))) -Skills
```

To do it by hand instead, download `memscope.exe` from the
[releases](https://github.com/DhurghamAhmed/MemScope/releases), check it against
`SHA256SUMS.txt`, and register it with your MCP client:

```json
{
  "mcpServers": {
    "memscope": {
      "command": "C:\\tools\\memscope\\memscope.exe",
      "args": ["serve"]
    }
  }
}
```

Windows x64, nothing else to install. The file is unsigned, and it calls
`OpenProcess`, `ReadProcessMemory` and `WriteProcessMemory`, so SmartScreen and
some endpoint products will question it. Verify the hash rather than the
warning — and, if you have the GitHub CLI, the build provenance GitHub attests
for each release:

```powershell
gh attestation verify memscope.exe --repo DhurghamAhmed/MemScope
```

As a Claude Code plugin, which registers the server and the investigation skill
together — set `MEMSCOPE_BIN` to the executable's full path first:

```
/plugin marketplace add DhurghamAhmed/MemScope
/plugin install memscope
```

Or from source, which needs Rust 1.99.1 and the MSVC linker:

```powershell
cargo install --git https://github.com/DhurghamAhmed/MemScope.git memscope
```

Step by step, with how to confirm it runs and what to do when it does not:
**[docs/getting-started.md](docs/getting-started.md)**.

## Capabilities

Enumerate processes and regions, read typed and raw memory with provenance, scan
and narrow by value or pattern, group typed fields, watch and dissect, express
locations as module offsets or pointer paths, validate across restarts, and write,
undo or freeze values when both write gates are enabled.

Any PID may be selected, including processes installed under Windows or Program
Files, processes owned by another user, and MemScope itself. Windows determines
whether the current token can obtain the required query, read or write handles.

[docs/walkthrough.md](docs/walkthrough.md) runs the whole sequence against the
test fixture — discover, attach, scan, narrow, prove, stabilise, write, restore.

## Agents

Agents follow [AGENTS.md](AGENTS.md) and the investigation skill to complete
authorized tasks without repeated approval questions. An explicit request to
change a value authorizes the corresponding `confirm: true` calls; the agent
still validates the address, captures original bytes and verifies the result.
The two runtime write gates and Windows access checks remain in effect.

## Requirements

| To | You need |
|---|---|
| Run the released `.exe` | Windows x64. **Nothing else** — no Python, .NET, numerical runtime, or Rust runtime. It links the MSVC CRT statically and imports only Windows system DLLs. |
| Build from source | Rust 1.99.1 (`rust-toolchain.toml` pins it) and the MSVC linker |
| Build and run the test fixtures | `csc.exe` from .NET Framework 4.x and MSVC `cl.exe` — see [fixtures/README.md](fixtures/README.md) |

Supported Windows versions: built and verified on Windows 11 Pro 10.0.26200
(x64). The APIs used (`OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`,
`WriteProcessMemory`, `QueryFullProcessImageNameW`, `EnumProcessModulesEx`,
`GetProcessTimes`, `IsWow64Process`) are available from Windows 7 / Server 2008 R2
onward, but **only Windows 11 26200 was tested**; nothing else is claimed.

Building, the quality gates and the fixture build are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Target selection

No allowlist, executable hash pin, owner SID match, or installation-path denylist
is required. Select a live PID with `attach_process`. A Windows access refusal
is returned with its OS error code.

`MEMSCOPE_ALLOWLIST` is ignored, including when it points to an old, missing or
malformed file. Executable paths and optional SHA-256 values are metadata rather
than selection conditions. Sessions remain bound to retained handles, PID and
creation time.

`server_status.target_selection` is `unrestricted`, `denied_roots` is empty,
and `policy_entries` is zero. The legacy `allowlisted` process field is always
`true`; it does not promise that Windows will grant memory access. See
[docs/target-selection.md](docs/target-selection.md).

## Environment variables

| Variable | Effect |
|---|---|
| `MEMSCOPE_ALLOWLIST` | Legacy setting, ignored. Target selection is unrestricted. |
| `MEMSCOPE_ALLOW_WRITE` | Must be exactly `1` to permit any mutation. `true`, `yes` and `on` are deliberately **not** accepted. Read at startup only. |
| `MEMSCOPE_LOG` | `error`, `warn`, `info` (default) or `debug`. Always written to stderr; stdout carries protocol messages only. |

## Tool reference

| Group | Tools |
|---|---|
| Session | `server_status`, `list_processes`, `attach_process`, `detach_process` |
| Regions and scans | `list_regions`, `first_scan`, `next_scan`, `list_results`, `reset_scan` |
| Composite search | `group_scan` |
| Reading | `read_memory`, `read_batch`, `read_bytes`, `read_struct` |
| Addressing | `list_modules`, `resolve_address`, `pointer_scan`, `resolve_pointer_path`, `rescan_pointer_paths`, `find_references` |
| Investigation | `watch_value`, `dissect_region` |
| Mutation | `write_memory`, `undo_write`, `freeze_value`, `unfreeze_value`, `list_frozen` |

Full input and output schemas are discoverable over MCP (`tools/list`) and
documented in [docs/tool-schemas.md](docs/tool-schemas.md). What an address
means, what a write guarantees, every error code and the accepted protocol
revisions are in [docs/semantics.md](docs/semantics.md).

## Honesty rules

These are enforced by tests, not just intentions:

- **Unread bytes are never zero-filled.** A partial read reports the prefix it
  actually got, with the Win32 error and the exact byte count.
- **A typed scalar requires all its bytes**, or it is `PARTIAL_READ`.
- **A truncated scan withholds its total entirely** and names the stop reason.
  Display pagination is not truncation, and paging never discards candidates.
- **Matches come from the captured bytes.** A later reread is reported separately,
  with its own timestamp, never in place of the match.
- **One candidate is not proof.** Evidence is labelled `candidate`,
  `behaviour_correlated` or `restart_validated`, and each level states the test
  behind it.
- **Dissection output is heuristic** and says so; no compiler layout, debug
  information or symbol table is consulted.
- **`watch_value` is bounded polling**, not instrumentation. It cannot see every
  intermediate write and reports failed and dropped samples.
- **A natively paused observation is refused** with `CONSISTENCY_UNAVAILABLE`.
- **64-bit integers cross the wire as decimal strings**, and non-finite floats are
  tagged rather than emitted as invalid JSON.

## Limitations

Known and deliberate:

1. **No native paused mode.** No target thread is ever suspended, so a coherent
   multi-address snapshot is not available. Use the target's own pause mechanism
   if it has one; results stay labelled `live`.
2. **`find_references` is a data search only.** No instruction is decoded, so a
   code reference that builds the address in registers or encodes it as a relative
   displacement is not found.
3. **One long-running tool at a time.** A scan releases the server state lock
   while it works, so status, reads, writes and the freeze tools are answered
   during it. A second long-running tool, and `detach_process`, are refused with
   `OPERATION_IN_FLIGHT` rather than queued.
4. **One session per server.** Attach a second target by detaching first.
5. **Pointer index memory.** A distinct pointer value costs between 46 and 83
   bytes in the index, 77.2 bytes measured at a million distinct values.
   `max_index_bytes` refuses an allocation that would pass the cap rather than
   making it, so a dense region ends as `index_complete: false`. Indexing a fully
   pointer-dense 128 MiB region to completion would need about 1.2 GiB.
6. **Capture is the performance limit** for the fast-path case; parallel capture is
   identified but not implemented.
7. **A genuine short write could not be forced** through the pre-write region
   check, so `PARTIAL_WRITE` reporting is proven by unit test rather than against
   live memory.
8. **Only Windows 11 26200 x64 was tested**, and only on a CPU with AVX2. The
   scalar fallback is correctness-tested but was never exercised on a machine
   lacking AVX2.
9. **The specification's historical performance figures do not reproduce** on this
   machine against the same reference code; see
   [docs/benchmarks.md](docs/benchmarks.md) §6.1.
10. **The build is not byte-reproducible.** Two clean locked release builds give
    the same size and pass the suite, but 24 bytes differ — the PE timestamp,
    three debug-directory timestamps and a PDB GUID. All code and data bytes are
    identical. A recorded SHA-256 identifies one linked artifact, not a value you
    can reproduce from source.

## Documentation

| Document | Contents |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | Install, register, confirm it runs, use the skill, troubleshoot |
| [docs/walkthrough.md](docs/walkthrough.md) | The twelve-step investigation, end to end |
| [docs/semantics.md](docs/semantics.md) | Addressing, write/undo/freeze guarantees, error codes, protocol |
| [docs/tool-schemas.md](docs/tool-schemas.md) | Input and output schema for each of the 27 tools |
| [docs/architecture.md](docs/architecture.md) | Module split, unsafe invariants, design decisions |
| [docs/target-selection.md](docs/target-selection.md) | Unrestricted targets, compatibility, verification |
| [docs/benchmarks.md](docs/benchmarks.md) | Every measured figure, with method and raw logs |
| [fixtures/README.md](fixtures/README.md) | Fixture layout, control channel, build dependencies |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, the quality gates, changing the tool surface |

## Intended use

MemScope is a debugging and analysis tool. It uses documented Win32 APIs and
obtains nothing Windows does not already grant the calling token. It contains
no privilege escalation, no kernel driver, no code injection, and no attempt to
evade a protection mechanism. A refused handle is reported as a refused handle.

You are responsible for having authorization for every process you inspect or
change. Reading or modifying the memory of a process you do not own or
administer may breach computer misuse law, employment policy, or the terms of
service of the software concerned. Online games in particular treat memory
modification as a terms violation whether or not it is unlawful.

## Licence

MIT. Copyright (c) 2026 Dhurgham Ahmed. The software is provided without
warranty of any kind, and the copyright holder is not liable for how it is
used — see [LICENSE](LICENSE).
