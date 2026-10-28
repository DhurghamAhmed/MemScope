# MemScope plugin

Registers the MemScope MCP server and the investigation skill that drives it.

MemScope inspects the memory of Windows processes, explains the evidence behind
every result, and performs verified memory changes only when two separate gates
are open.

## Install

The plugin registers the server; it does not ship the binary. Get the binary
first.

1. Download `memscope.exe` from the
   [releases](https://github.com/DhurghamAhmed/MemScope/releases), verify it against
   `SHA256SUMS.txt`, and put it somewhere permanent.

2. Set `MEMSCOPE_BIN` to its full path, for the user account that runs Claude
   Code:

   ```powershell
   [Environment]::SetEnvironmentVariable(
     "MEMSCOPE_BIN", "C:\tools\memscope\memscope.exe", "User")
   ```

3. Install the plugin:

   ```
   /plugin marketplace add DhurghamAhmed/MemScope
   /plugin install memscope
   ```

4. Restart the session. `/mcp` should list `memscope` with 27 tools.

## Writes

The server starts read-only. A mutating call needs **both** gates:

- `MEMSCOPE_ALLOW_WRITE=1` in the server's environment, read at startup only.
  Exactly `1`; `true`, `yes` and `on` are rejected on purpose. Add it to the
  `env` block of the plugin's `.mcp.json` and restart the session.
- `confirm: true` on the call itself.

Neither gate implies the other, and the environment variable alone never
authorises a write.

## Requirements

Windows x64. Nothing else — the executable links the MSVC CRT statically and
imports only Windows system DLLs. Any PID may be selected; Windows decides
whether the current token can obtain the query, read or write handle.

## Documentation

Installing, confirming it runs, using the skill and troubleshooting:
<https://github.com/DhurghamAhmed/MemScope/blob/main/docs/getting-started.md>

Full tool reference, addressing rules, error codes and honesty rules:
<https://github.com/DhurghamAhmed/MemScope>
