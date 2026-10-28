# Getting started

Install MemScope, confirm it runs, and use it through the investigation skill.

## What you get

| Piece | What it is |
|---|---|
| `memscope.exe` | The MCP server. 27 tools over stdio. Windows x64, no runtime. |
| The `memory-investigation` skill | Instructions your agent loads when a task involves process memory, so it drives the 27 tools in the right order and reports in the right vocabulary. |

The server works without the skill. The skill is what stops an agent from
guessing at the workflow.

## 1. Get the binary

```powershell
irm https://raw.githubusercontent.com/DhurghamAhmed/MemScope/main/install.ps1 | iex
```

The script downloads the latest `memscope.exe` and its `SHA256SUMS.txt`,
compares the two, and **refuses to install on a mismatch**. On success it puts
the binary in `%LOCALAPPDATA%\Programs\memscope`, adds that directory to your
user `Path`, and sets `MEMSCOPE_BIN`.

Options are passed by creating a script block instead of piping to `iex`:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/DhurghamAhmed/MemScope/main/install.ps1))) -Skills
```

| Option | Effect |
|---|---|
| `-Skills` | Also install the `memory-investigation` skill into `.claude/skills` in the current directory |
| `-InstallDir <path>` | Install somewhere other than `%LOCALAPPDATA%\Programs\memscope` |
| `-Version v0.1.0` | Install a specific release instead of the latest |
| `-NoPathSetup` | Leave your user `Path` alone |
| `-SkillsDir <path>` | Install the skill somewhere other than `.\.claude\skills` |

Running a script straight from the internet is a decision, not a default. Read
it first if you prefer:

```powershell
irm https://raw.githubusercontent.com/DhurghamAhmed/MemScope/main/install.ps1 -OutFile install.ps1
notepad install.ps1
./install.ps1 -Skills
```

### By hand

Download `memscope.exe` from the
[releases](https://github.com/DhurghamAhmed/MemScope/releases) and check it:

```powershell
(Get-FileHash .\memscope.exe -Algorithm SHA256).Hash.ToLower()
```

Compare against `SHA256SUMS.txt` in the same release. The file is unsigned and
calls `OpenProcess`, `ReadProcessMemory` and `WriteProcessMemory`, so SmartScreen
and some endpoint products will question it — trust the hash, not the warning.

GitHub also attests where each release was built. With the GitHub CLI:

```powershell
gh attestation verify memscope.exe --repo DhurghamAhmed/MemScope
```

Or build it yourself:

```powershell
cargo build --release
```

## 2. Register it

### With the plugin — server and skill together

The plugin reads `MEMSCOPE_BIN`, which `install.ps1` already set. If you
installed by hand, set it yourself:

```powershell
[Environment]::SetEnvironmentVariable(
  "MEMSCOPE_BIN", "C:\tools\memscope\memscope.exe", "User")
```

```
/plugin marketplace add DhurghamAhmed/MemScope
/plugin install memscope
```

Restart the session.

### By hand — server only

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

Project scope goes in `.mcp.json` at the project root; user scope goes through
`claude mcp add --scope user`. To get the skill as well, copy
`plugin/memscope/skills/memory-investigation/` into `.claude/skills/`.

## 3. Confirm it runs

```
/mcp
```

`memscope` should appear with 27 tools. Without a client:

```powershell
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' |
  .\memscope.exe serve
```

A JSON line naming `memscope` and a protocol revision means the server is fine
and any remaining problem is in the client configuration.

## 4. Using it

Ask for the result, not the tool calls. The skill supplies the procedure.

> Find the ammunition counter in PID 4812 and tell me how you proved it.

The agent attaches, scans, narrows after the value changes, and reports the
address with an evidence label — `candidate`, `behaviour_correlated` or
`restart_validated` — naming the test behind the label. One candidate is never
reported as proof.

> Express it as something that survives a restart.

Pointer paths and module offsets, each re-resolved before it is reported.

> Set it to 250.

Needs both write gates (below). The agent captures the original bytes, writes,
reads back, and reports `verified` with the before and after values.

### What the skill changes

Without it, an agent sees 27 tools and no order. With it, the agent knows that
narrowing follows a change made through the target itself, that a reread is
reported separately from the captured match, that dissection output is
heuristic, and that `watch_value` is bounded polling that can miss writes.

## 5. Enabling writes

The server starts read-only. A mutation needs **both** gates:

```json
"env": { "MEMSCOPE_ALLOW_WRITE": "1" }
```

- `MEMSCOPE_ALLOW_WRITE=1` is read at startup only, so add it to the `env` block
  and restart the session. Exactly `1` — `true`, `yes` and `on` are rejected.
- `confirm: true` on each mutating call.

Neither gate implies the other. A server started without the variable cannot be
talked into a write.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `memscope` missing from `/mcp` | The session was not restarted, or `command` points at a file that is not there. Run the path directly in a shell to check. |
| Plugin installs, server does not start | `MEMSCOPE_BIN` is unset for the account running the client. A variable set with `"User"` scope reaches only sessions started afterwards. |
| `install.ps1` aborts on a hash mismatch | The download did not match the published `SHA256SUMS.txt`. Nothing was installed. Retry; if it persists, open an issue rather than bypassing the check. |
| `ACCESS_DENIED` on attach | Windows refused the handle for that token. Expected for protected processes and for another user's processes from an unelevated session. |
| Writes refused with the variable set | The value is not exactly `1`, the server was not restarted after it was set, or the call omitted `confirm: true`. |
| Scan never finishes | No budget was given. Set `max_bytes_scanned` and `timeout_ms`. |
| `CONSISTENCY_UNAVAILABLE` | `consistency = paused` is deliberately refused. MemScope never suspends a target thread. |

## Next

- [Walkthrough](walkthrough.md) — the twelve-step investigation, end to end
- [Semantics](semantics.md) — addressing, write guarantees, error codes, protocol
- [Tool reference](tool-schemas.md) — input and output schema for all 27 tools
- [Architecture](architecture.md) — module split and unsafe invariants
- [Benchmarks](benchmarks.md) — every measured figure with its method
- [Target selection](target-selection.md) — what may be attached, and why
