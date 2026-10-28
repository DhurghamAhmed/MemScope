# Unrestricted target selection

Scope update requested on 2026-10-27. This replaces the original target-selection
requirements and their acceptance criteria in the historical reports.

`attach_process` accepts any live PID for which Windows grants the required query
and memory access. There are no allowlist, SHA-256 pin, installation-path,
same-owner SID, or self-target restrictions. This includes processes under Windows
and Program Files, games, other users' processes, and MemScope itself.

Windows still decides which access rights the current token can obtain. A denied
handle or page access is reported with its original OS error. The supported x64
and WOW64 architectures, address validation, retained-handle identity checks,
resource budgets, and two write gates continue to apply.

## Compatibility

- `MEMSCOPE_ALLOWLIST` is ignored. A missing, invalid, empty, changed or deleted
  legacy allowlist does not prevent startup, attachment, reads or confirmed writes.
- `Policy::load`, `reload`, and `revalidate` remain compatible with existing Rust
  callers; they no longer load or enforce target rules. New callers can use
  `Policy::default()`.
- `server_status.target_selection` is `unrestricted`, `policy_source` is
  `windows_access`, `policy_entries` is zero, and `denied_roots` is empty.
- The legacy `allowlisted` field is always `true`, including for a process whose
  memory Windows will not permit reading. Consult operation results for access.
- Executable hashes and owner SIDs are optional metadata. Empty strings indicate
  unavailable metadata. SHA-256 is measured when attaching if the file is readable;
  it is not compared with a pin or rehashed at scan/freeze checkpoints.
- Session identity uses the retained handle, PID and creation time. Changes to a
  file on disk or an old allowlist do not replace a running process.

## Verification

The updated suite replaces tests of removed target restrictions with checks of
the new behavior. It covers x64/WOW64 fixture attachment without an entry,
mismatched legacy pins, changed/deleted legacy files, self-attachment, continued
confirmed writes, and real MCP attachment and reading with missing, malformed,
empty and invalid-pin legacy files. Existing process-exit, PID replacement,
write-confirmation, undo, freeze lifecycle and cancellation checks remain.

The system/Program Files path-selection checks use metadata paths. No writes to
Windows processes, other users' processes or games are needed by these tests.
An actual cross-user session was not exercised; owner matching was removed from
the attach path, and owner metadata lookup failure no longer rejects attachment.

Each release publishes its own hash in `SHA256SUMS.txt`, which identifies the
artifact a given verification result applies to. Those results describe one
checkpoint: concurrent pointer-index edits and later added tests are not
covered by it.
