# Contributing

## Build

Windows x64, Rust 1.99.1 (`rust-toolchain.toml` pins it), MSVC linker.

```powershell
cargo build --release
```

## Gates

All four must pass before a change is ready. A change that compiles is not done.

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
& scripts/verify-nonelevated.ps1
```

`cargo test` needs the fixtures, which need `csc.exe` from .NET Framework 4.x
and MSVC `cl.exe`:

```powershell
& fixtures/build.ps1
& fixtures/verify.ps1
```

CI runs format, lint and the release build only. The test suite is local,
because the fixture compilers are not guaranteed on a hosted runner.

## Changing the tool surface

`TOOL_NAMES` in `src/mcp.rs` is mirrored in four other places. Change all five
together:

1. The array and the three tests at the bottom of `src/mcp.rs`.
2. `docs/tool-schemas.md` — regenerate, never hand-edit:
   `cargo run --bin schemas | Out-File -Encoding utf8 docs/tool-schemas.md`
3. The tool reference and tool count in `README.md`.
4. A case in `tests/phase9_mcp.rs`, which drives a real client over stdio.

## House rules

- Every measured figure traces to a raw log under `artifacts/`, with its method
  in `docs/benchmarks.md`. Do not quote a remembered number.
- The honesty rules in `README.md` are enforced by tests. Output that is more
  convenient but less honest is a regression even when the suite is green — add
  the test instead.
- Do not publish machine identifiers: hostnames, full SIDs, or absolute paths
  under a user profile.
