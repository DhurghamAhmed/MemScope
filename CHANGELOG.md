# Changelog

Notable changes to MemScope. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/getting-started.md` — installing, registering, confirming the
  server runs, using the investigation skill, and troubleshooting.
- `docs/walkthrough.md` and `docs/semantics.md` — the twelve-step
  investigation and the addressing, write, error and protocol contracts, moved
  out of README.md.

- `install.ps1` — one-command install that verifies the published SHA-256
  before installing, sets `MEMSCOPE_BIN`, and optionally installs the
  investigation skill with `-Skills`.
- Build provenance attestation on each release, verifiable with
  `gh attestation verify`.
- An intended-use notice stating what the tool does not do and where the
  responsibility for authorization lies.
- Setup for Cursor, VS Code and Windsurf, the skill's equivalents in clients
  with no skill format, and why ChatGPT cannot run a local stdio server.

### Changed

- Added repository agent instructions for completing authorized tasks without
  repeated approval questions. Both investigation skills now accept existing
  explicit write authorization and choose workflow steps according to the task.
  Runtime write gates and memory integrity checks are unchanged.

## [0.1.0] — 2026-10-28

First release.

### Added

- 27 MCP tools over stdio: process and region enumeration, typed and raw reads
  with provenance, value and pattern scanning with narrowing, field grouping,
  watching, heuristic dissection, module-relative addressing, pointer paths and
  bounded pointer scans, restart validation, and gated write, undo and freeze.
- Two independent write gates: `MEMSCOPE_ALLOW_WRITE=1` at startup and
  `confirm: true` per call.
- Evidence labelling — `candidate`, `behaviour_correlated`, `restart_validated`
  — with the test behind each level stated.
- Protocol revisions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05.
- A single-file Windows x64 executable with the MSVC CRT linked statically.

### Known limitations

- Native paused mode is deliberately absent. No target thread is suspended, and
  `consistency = paused` is refused with `CONSISTENCY_UNAVAILABLE`.
- `PARTIAL_WRITE` is not proved against live memory: the pre-write region check
  refuses any range that is not wholly committed and writable.
- Verified on Windows 11 Pro 10.0.26200 only. The APIs used are available from
  Windows 7 onward, but nothing else was tested.
- The non-elevated proof is a medium-integrity token, not a fully UAC-filtered
  one.

[Unreleased]: https://github.com/DhurghamAhmed/MemScope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DhurghamAhmed/MemScope/releases/tag/v0.1.0
