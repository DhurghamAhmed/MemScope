import io
import json
import os
import statistics
import sys
import time

REFERENCE = os.environ.get(
    "MEMSCOPE_REFERENCE",
    os.path.join(os.path.expanduser("~"), "Desktop", "apps", "mcp-memory-mac"),
)
WORKLOAD_BYTES = 128 * 1024 * 1024
WARMUP_RUNS = 1
MEASURED_RUNS = 5
NEEDLE = 0x4D454D53
PLANT_STRIDE = 1000000

sys.path.insert(0, os.path.join(REFERENCE, "src"))

try:
    from mcp_memory import scanner
    from mcp_memory.validation import Compare, ValueType
except Exception as exc:
    print("cannot import the reference scanner from %s: %s" % (REFERENCE, exc))
    print("set MEMSCOPE_REFERENCE to the reference checkout, or skip this comparison")
    raise SystemExit(3)


def build_workload():
    slots = WORKLOAD_BYTES // 4
    buf = bytearray(WORKLOAD_BYTES)
    state = 0x1234ABCD
    planted = 0
    mv = memoryview(buf)
    for index in range(slots):
        if index % PLANT_STRIDE == 0:
            value = NEEDLE
            planted += 1
        else:
            state = (state * 1103515245 + 12345) & 0xFFFFFFFF
            value = state
        mv[index * 4 : index * 4 + 4] = value.to_bytes(4, "little")
    return buf, planted


def mb_per_second(nbytes, seconds):
    if seconds <= 0:
        return 0.0
    return (nbytes / (1024.0 * 1024.0)) / seconds


def measure(name, fn, nbytes, expected=None):
    samples = []
    count = None
    for run in range(WARMUP_RUNS + MEASURED_RUNS):
        started = time.perf_counter()
        count = fn()
        elapsed = time.perf_counter() - started
        if run >= WARMUP_RUNS:
            samples.append(mb_per_second(nbytes, elapsed))
    if expected is not None and count != expected:
        raise SystemExit(
            "%s found %s matches, expected %s" % (name, count, expected)
        )
    median = statistics.median(samples)
    print(
        "  %-44s median %10.1f MB/s   (min %.1f, max %.1f, n=%d)"
        % (name, median, min(samples), max(samples), len(samples))
    )
    return {
        "name": name,
        "unit": "MB/s",
        "runs": len(samples),
        "median": median,
        "min": min(samples),
        "max": max(samples),
        "samples": samples,
        "matches": count,
    }


def main():
    print("reference benchmark (mcp-memory-mac scanner, same machine, same workload)")
    print("  reference:      %s" % REFERENCE)
    print("  python:         %s" % sys.version.split()[0])
    print("  numpy backend:  %s" % json.dumps(scanner.backend_info()))
    print("  vectorised:     %s" % scanner.vectorized())
    print("  warm-up runs:   %d" % WARMUP_RUNS)
    print("  measured runs:  %d" % MEASURED_RUNS)
    print("  unit:           MB/s = mebibytes of the buffer examined per second")
    print()

    buf, planted = build_workload()
    print(
        "  workload: %d MiB, deterministic LCG, %d planted copies of 0x%08x"
        % (WORKLOAD_BYTES // (1024 * 1024), planted, NEEDLE)
    )
    print()

    results = []
    needle_bytes = NEEDLE.to_bytes(4, "little")

    results.append(
        measure(
            "int32 exact (bytes.find fast path)",
            lambda: sum(
                1
                for _ in scanner._exact_byte_matches(
                    buf, len(buf), 0, needle_bytes, 4
                )
            ),
            len(buf),
        )
    )

    if scanner.vectorized():
        results.append(
            measure(
                "int32 exact (numpy)",
                lambda: len(
                    scanner._numeric_matches_np(
                        buf, len(buf), 0, ValueType.INT32, Compare.EXACT, NEEDLE, None
                    )
                ),
                len(buf),
            )
        )
        results.append(
            measure(
                "int32 greater_than (numpy)",
                lambda: len(
                    scanner._numeric_matches_np(
                        buf, len(buf), 0, ValueType.INT32, Compare.BIGGER_THAN, 0, None
                    )
                ),
                len(buf),
            )
        )
        results.append(
            measure(
                "float exact (numpy)",
                lambda: len(
                    scanner._numeric_matches_np(
                        buf, len(buf), 0, ValueType.FLOAT, Compare.EXACT, 0.1, None
                    )
                ),
                len(buf),
            )
        )
        results.append(
            measure(
                "double between (numpy)",
                lambda: len(
                    scanner._numeric_matches_np(
                        buf, len(buf), 0, ValueType.DOUBLE, Compare.BETWEEN, 0.0, 1.0
                    )
                ),
                len(buf),
            )
        )

    small = bytearray(buf[: 8 * 1024 * 1024])
    predicate = scanner.make_predicate(Compare.BIGGER_THAN, ValueType.INT32, 0, None)
    results.append(
        measure(
            "int32 greater_than (pure python loop, 8 MiB)",
            lambda: sum(
                1
                for _ in scanner._numeric_matches(
                    small, len(small), 0, ValueType.INT32, predicate
                )
            ),
            len(small),
        )
    )

    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "artifacts")
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    out = os.path.join(out_dir, "reference-benchmark-raw.json")
    document = {
        "tool": "reference-benchmark.py",
        "reference_path": REFERENCE,
        "python": sys.version,
        "numpy_backend": scanner.backend_info(),
        "vectorised": scanner.vectorized(),
        "workload_bytes": WORKLOAD_BYTES,
        "planted_matches": planted,
        "warmup_runs": WARMUP_RUNS,
        "measured_runs": MEASURED_RUNS,
        "unit_definition": "MB/s = mebibytes (1048576 bytes) of the buffer examined per second",
        "note": "These numbers measure the reference comparison functions over an in-process "
        "buffer, with no remote reads. They are comparable to the MemScope "
        "comparison-kernel figures, not to its end-to-end remote scan figures.",
        "measurements": results,
    }
    io.open(out, "w", encoding="utf-8").write(json.dumps(document, indent=2))
    print()
    print("raw measurements written to %s" % out)


if __name__ == "__main__":
    main()
