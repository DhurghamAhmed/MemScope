# Security

## What this tool is

MemScope reads and, behind two gates, writes the memory of Windows processes.
It requests no privilege Windows would not already grant the calling token:
`OpenProcess` decides what is possible, and a denied handle is reported as a
denied handle. It contains no privilege escalation, no driver, no injection and
no evasion.

## The two write gates

A mutating call needs both, and neither implies the other:

- `MEMSCOPE_ALLOW_WRITE=1` in the server's environment, read at startup only.
  Exactly `1`.
- `confirm: true` on the call.

A server started without the environment variable cannot be talked into a write.

These are runtime gates. When the user has explicitly authorized a memory change
in an identified target, the agent can supply `confirm: true` for that operation
without requesting the same authorization again in chat. Read or analysis tasks
alone do not authorize memory changes. Original-byte capture, process identity
checks, writable-range checks and read-back verification remain in effect.

## Reporting a vulnerability

Open a private security advisory through the repository's Security tab rather
than a public issue. Include the Windows build, the tool and arguments, what you
expected and what happened.

In scope: a write that occurs with either gate closed, a read that returns bytes
the calling token should not reach, a crash reachable from a well-formed MCP
request, and any output that misrepresents what was observed.

Out of scope: the tool reading memory that Windows already grants the token —
that is its purpose.

## Antivirus and SmartScreen

Release binaries are unsigned and call `OpenProcess`, `ReadProcessMemory` and
`WriteProcessMemory`, so endpoint products may flag them. Verify the download
against the published SHA-256 rather than the warning, or build from source.
