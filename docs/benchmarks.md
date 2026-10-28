# MemScope measured performance

Every number here was produced on this machine by the commands shown. Raw
per-run samples are in `artifacts/benchmark-raw.json` and
`artifacts/reference-benchmark-raw.json`.

Nothing in this document is estimated, scaled, or carried over from the original specification.
Where a figure from the original specification failed to reproduce, that is recorded as a finding
rather than smoothed over.

## 1. Method

```powershell
& fixtures/build.ps1                      # the benchmark needs the --bench fixture
cargo build --release --bin bench
./target/release/bench.exe                # writes artifacts/benchmark-raw.json

# same-machine reference comparison
$env:MEMSCOPE_REFERENCE = "<your clone of mcp-memory-mac>"
& "$env:MEMSCOPE_REFERENCE/.venv/Scripts/python.exe" -I scripts/reference-benchmark.py
```

| Parameter | Value |
|---|---|
| Machine | AMD Ryzen 7 7700X, 8 physical / 8 logical cores, 31.66 GiB RAM |
| OS | Windows 11 Pro 10.0.26200 build 26200, x64 |
| Toolchain | rustc 1.99.1, LLVM 23.1.1, target `x86_64-pc-windows-msvc` |
| Release flags | `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`, `strip="symbols"`, `+crt-static` |
| CPU features | AVX2 detected at run time (`is_x86_feature_detected!`) |
| Rayon threads | 8 |
| Workload | 128 MiB, deterministic LCG `state = state*1103515245 + 12345`, seed `0x1234ABCD`, with `0x4D454D53` planted every 1 000 000 int32 slots |
| Planted matches | 34, counted during the fill rather than assumed |
| Warm-up | 1 run, discarded |
| Measured runs | 5 |
| Reported | median, with min and max |
| Unit | **MB/s = mebibytes (1 048 576 bytes) of memory examined per second** |
| Consistency mode | `live` throughout; no target thread is ever suspended |

Timing boundaries follow the original specification: region enumeration, policy
validation, remote reads, comparison, result materialisation and cleanup are all
inside the end-to-end figure, and capture, comparison and materialisation are
also reported separately.

## 2. Comparison kernels (in-process buffer, no remote reads)

This isolates the comparison stage from `ReadProcessMemory`.

| Kernel | Median MB/s | Min | Max |
|---|---|---|---|
| int32 exact, scalar | 11 051.0 | 10 866.2 | 11 334.8 |
| int32 exact, AVX2 | **51 413.9** | 46 934.6 | 57 704.4 |
| int32 exact, AVX2 + rayon (8 threads, 4 MiB chunks) | 51 777.8 | 50 921.0 | 57 819.1 |

* **AVX2 over scalar: ×4.65.** Both kernels are tested for exact equivalence in
  `src/kernel.rs`, including on buffers that are not a whole number of vectors,
  so the fast path is not faster by finding less.
* **Rayon over AVX2: ×1.01.** Chunk parallelism was benchmarked as section 13
  asks and it does **not** help: at ~51 GB/s a single core already saturates
  memory bandwidth for this access pattern. The measurement is the reason the
  production sweep stays sequential; adding threads there would spend complexity
  for no measured gain. The bottleneck moved to capture — see §3.

## 3. End-to-end remote scans (fixture 128 MiB region)

| Case | Matches | Bytes visited | End to end | Remote capture | Comparison | Materialisation | Total latency |
|---|---|---|---|---|---|---|---|
| int32 exact | 34 | 128 MiB | **2 875.3** MB/s | 6 263.5 MB/s | 65 810.0 MB/s | 0.0 ms | 44.5 ms |
| int32 greater_than | 1 000 000 | 8 MiB | 453.2 MB/s | 6 240.3 MB/s | 641.1 MB/s | 0.0 ms | 17.6 ms |
| float exact | 0 | 128 MiB | 953.1 MB/s | 6 142.9 MB/s | 1 407.8 MB/s | 0.0 ms | 134.2 ms |
| double between | 1 000 000 | 31 MiB | 663.8 MB/s | 6 158.2 MB/s | 906.7 MB/s | 0.1 ms | 46.6 ms |

Reading this table honestly:

* **`int32 exact` is the only case on the AVX2 fast path.** Its comparison stage
  runs at 65 810 MB/s, so `ReadProcessMemory` at ~6 264 MB/s is the limit and the
  end-to-end figure (2 875.3 MB/s) reflects capture plus per-chunk overhead.
* **`greater_than` and `between` are ordering comparisons**, which cannot be done
  as a bitwise match, so they take the generic scalar path by design.
* **`float exact` also takes the generic path**, because the default float
  comparison is *tolerance*, not bitwise. A bitwise fast path would silently
  change the matching semantics, so it is used only when the caller explicitly
  asks for `FloatCompare::Exact`.
* **The two truncated rows visited less memory on purpose.** `greater_than` and
  `between` both hit `max_results = 1 000 000` and stopped, so they visited 8 MiB
  and 31 MiB rather than 128 MiB. Their MB/s is therefore *not* comparable with
  the full-sweep rows, and the scans correctly reported `truncated: true` with the
  total withheld.

### 3.1 A measured speedup, before and after

The kernel was written before it was wired into the scan. Both sets of numbers
below come from the same machine, the same workload and the same binary apart
from the fast path, so this is a comparable before/after:

| Stage | Generic path | AVX2 fast path | Speedup |
|---|---|---|---|
| `int32 exact` comparison | 1 477.2 MB/s | 65 810.0 MB/s | **×44.5** |
| `int32 exact` end to end | 948.9 MB/s | 2 875.3 MB/s | **×3.03** |
| `int32 exact` total latency | 134.8 ms | 44.5 ms | ×3.03 faster |

The end-to-end gain is much smaller than the comparison gain because capture
became the limit, which is exactly what §2 predicted.

## 4. Memory at scale

| Measurement | Value |
|---|---|
| Peak working set, benchmark process, 128 MiB scan | 134.3 MiB |
| Candidate storage, 1 000 000 retained int32 candidates | ~12 MB (8 B address + 4 B value each, flat typed buffers) |
| Unknown-value baseline, 128 KiB region | 128 KiB of raw chunks plus a per-page validity bitmap |
| Pointer index, 128 MiB region | 16 777 216 pointer-valued slots; see the correction below |

**Correction (2026-10-28).** The 256.0 MiB this row reported was the old
accounting's figure, 16 bytes per indexed slot. It was never what the index
allocated. A `HashMap<u64, Vec<u64>>` spends, per *distinct* value, one bucket
carrying the key, a vector header and a control byte: 33 bytes, which the
power-of-two bucket array spreads to between 38 and 75 depending on where the
table sits between growth steps, and the holder vector adds at least 8 more —
46 to 83 bytes in all. Measured on the live structure: **77.2 bytes per distinct
value at a million of them**, a 69 MB bucket array over 8 MB of holder vectors. Were all 16 777 216 slots of this
region distinct, the table alone would be 2^25 buckets, 1 056.0 MiB, over
128.0 MiB of holder vectors: **1 184.0 MiB**, not 256.0 MiB.

That figure is computed from the accounting model, which is unit-tested against
the real capacities; this row has not been re-measured since the fix, and the
`index_bytes` a scan now reports is the allocation rather than the estimate. The
budget enforces itself either way: `max_index_bytes` refuses the allocation that
would pass the cap, so the dense case ends as `index_complete: false` instead of
quietly using four times what it charged. The pointer index remains the one
structure that costs more than the memory it describes; §6 records replacing it
as outstanding work.

## 5. Pointer index build

| Measurement | Median MB/s | Min | Max |
|---|---|---|---|
| Pointer index build over 128 MiB | 31.2 | 28.7 | 32.3 |

## 6. Same-machine reference comparison

The Python reference
([`mcp-memory-mac`](https://github.com/DhurghamAhmed/mcp-memory-mac), HEAD
`e1d0fb2`) is importable on this host, so its **own comparison functions** were
run over a byte-identical 128 MiB workload, today, on this machine, with the
same warm-up and repetition counts.

| Operation | Reference | MemScope | Comparable? |
|---|---|---|---|
| int32 exact | 14 406.5 MB/s (numpy) | **51 413.9 MB/s** (AVX2 kernel) | **Yes — ×3.57** |
| int32 exact | 3 684.1 MB/s (`bytes.find`) | 51 413.9 MB/s (AVX2 kernel) | Yes — ×13.95 |
| int32 greater_than | 349.8 MB/s (numpy) | 641.1 MB/s (scan stage) | **No** |
| float exact | 443.5 MB/s (numpy) | 1 407.8 MB/s (scan stage) | **No** |
| double between | 1 224.3 MB/s (numpy) | 906.7 MB/s (scan stage) | **No** |
| int32 greater_than | 45.1 MB/s (pure Python loop, 8 MiB) | 641.1 MB/s (scan stage) | **No** |

**Only the `int32 exact` row is a clean comparison**, because both sides measure
the same thing: a comparison pass over an in-process buffer. For that row the
claim is **×3.57 over the reference's numpy path on this machine**.

**For every other operator the speedup claim is withheld.** The MemScope figures
in those rows come from the scan's comparison stage, which also includes chunk
iteration, bounds checking and candidate materialisation; the reference figures
are bare function calls over a buffer. They are not measuring the same work. Note
also that `double between` is *slower* in MemScope's scan stage (906.7) than in
the reference's bare numpy call (1 224.3) — that is reported here rather than
omitted.

### 6.1 The specification's historical figures do not reproduce

the original specification supplies figures attributed to this reference. Measured
today, on this machine, against the same reference code:

| Operation | Specification | Measured today | Verdict |
|---|---|---|---|
| int32 exact | 2 371 MB/s | 14 406.5 MB/s | **Does not reproduce** — 6.1× higher |
| float exact | 364 MB/s | 443.5 MB/s | Roughly reproduces (1.2× higher) |
| int32 greater_than | 1 357 MB/s | 349.8 MB/s | **Does not reproduce** — 3.9× lower |
| double between | 3 909 MB/s | 1 224.3 MB/s | **Does not reproduce** — 3.2× lower |
| Pointer index build | 146 MB/s | not measurable | The reference has no pointer index to run |

Three of the four figures are off by 3–6× in both directions, so the specification's
table cannot be used as a baseline for any claim. The likely causes — different
hardware, a different numpy version, or a different measurement boundary — cannot
be distinguished, because the original specification supplies no raw logs, no repetition count and
no unit definition. **This is why §6 compares against a run made today rather
than against the specification's numbers.**

## 7. What was not measured

* **Parallel capture.** `ReadProcessMemory` at ~6 264 MB/s is now the limit for
  the fast-path case. Issuing captures from several threads is the obvious next
  optimisation and is **not implemented or measured**; no claim is made about it.
* **WOW64 throughput.** Every figure here is from the x64 fixture. The WOW64
  fixture is covered by correctness tests across all phases but was not
  benchmarked, so no WOW64 performance claim is made.
* **Scaling past 128 MiB.** The budget machinery is tested, but no measurement
  was taken at multi-gigabyte scale.
* **Scalar-only hosts.** The scalar fallback is tested for correctness and
  benchmarked at 11 051.0 MB/s, but no machine without AVX2 was available, so the
  dispatch was never exercised on one.
