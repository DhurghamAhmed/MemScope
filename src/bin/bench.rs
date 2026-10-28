#![allow(clippy::result_large_err)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use memscope::kernel::{self, Kernel};
use memscope::mem::ValueType;
use memscope::policy::{Policy, sha256_file};
use memscope::scan::{self, Cancel, FirstScanRequest, Needle, Operator, RegionFilter, ScanBudget};
use memscope::target::{self, Session};
use memscope::wire::WireI64;
use rayon::prelude::*;
use serde_json::{Value, json};

const WORKLOAD_BYTES: usize = 128 * 1024 * 1024;
const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;

struct Measurement {
    name: String,
    unit: &'static str,
    samples: Vec<f64>,
}

impl Measurement {
    fn new(name: impl Into<String>, unit: &'static str) -> Self {
        Self {
            name: name.into(),
            unit,
            samples: Vec::new(),
        }
    }

    fn median(&self) -> f64 {
        let mut sorted = self.samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        if sorted.is_empty() {
            return 0.0;
        }
        sorted[sorted.len() / 2]
    }

    fn min(&self) -> f64 {
        self.samples.iter().copied().fold(f64::INFINITY, f64::min)
    }

    fn max(&self) -> f64 {
        self.samples
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max)
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "unit": self.unit,
            "runs": self.samples.len(),
            "median": self.median(),
            "min": self.min(),
            "max": self.max(),
            "samples": self.samples,
        })
    }

    fn report(&self) {
        println!(
            "  {:<44} median {:>10.1} {}   (min {:.1}, max {:.1}, n={})",
            self.name,
            self.median(),
            self.unit,
            self.min(),
            self.max(),
            self.samples.len()
        );
    }
}

fn mb_per_second(bytes: usize, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / (1024.0 * 1024.0)) / seconds
}

fn build_workload() -> (Vec<u8>, i32, u64) {
    let slots = WORKLOAD_BYTES / 4;
    let mut buffer = vec![0u8; WORKLOAD_BYTES];
    let mut state: u32 = 0x1234_ABCD;
    let needle = 0x4D45_4D53u32 as i32;
    let mut planted = 0u64;
    for index in 0..slots {
        let value = if index % 1_000_000 == 0 {
            planted += 1;
            needle
        } else {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            state as i32
        };
        buffer[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    (buffer, needle, planted)
}

fn bench_kernels(log: &mut Vec<Value>) {
    println!(
        "== comparison kernels over a {} MiB in-process buffer ==",
        WORKLOAD_BYTES / (1024 * 1024)
    );
    let (buffer, needle, planted) = build_workload();
    let needle_bytes = needle.to_le_bytes();
    println!(
        "  workload: deterministic LCG, {planted} planted copies of 0x{:08x}, 4-byte stride",
        needle as u32
    );

    let mut scalar = Measurement::new("int32 exact, scalar", "MB/s");
    let mut simd = Measurement::new("int32 exact, avx2", "MB/s");
    let mut parallel = Measurement::new("int32 exact, avx2 + rayon", "MB/s");

    let chunk = 4 * 1024 * 1024;
    let threads = rayon::current_num_threads();

    for run in 0..(WARMUP_RUNS + MEASURED_RUNS) {
        let measured = run >= WARMUP_RUNS;

        let mut out = Vec::new();
        let started = Instant::now();
        kernel::find_exact_4_with(Kernel::Scalar, &buffer, needle_bytes, 4, &mut out);
        let elapsed = started.elapsed();
        assert_eq!(
            out.len() as u64,
            planted,
            "scalar kernel found the wrong count"
        );
        if measured {
            scalar.samples.push(mb_per_second(buffer.len(), elapsed));
        }

        let mut out = Vec::new();
        let started = Instant::now();
        kernel::find_exact_4_with(Kernel::Avx2, &buffer, needle_bytes, 4, &mut out);
        let elapsed = started.elapsed();
        assert_eq!(
            out.len() as u64,
            planted,
            "avx2 kernel found the wrong count"
        );
        if measured {
            simd.samples.push(mb_per_second(buffer.len(), elapsed));
        }

        let started = Instant::now();
        let found: usize = buffer
            .par_chunks(chunk)
            .map(|slice| {
                let mut local = Vec::new();
                kernel::find_exact_4_with(Kernel::Avx2, slice, needle_bytes, 4, &mut local);
                local.len()
            })
            .sum();
        let elapsed = started.elapsed();
        assert_eq!(
            found as u64, planted,
            "parallel kernel found the wrong count"
        );
        if measured {
            parallel.samples.push(mb_per_second(buffer.len(), elapsed));
        }
    }

    scalar.report();
    simd.report();
    parallel.report();
    let speedup = if scalar.median() > 0.0 {
        simd.median() / scalar.median()
    } else {
        0.0
    };
    let parallel_speedup = if simd.median() > 0.0 {
        parallel.median() / simd.median()
    } else {
        0.0
    };
    println!("  avx2 over scalar:          x{speedup:.2}");
    println!("  rayon over avx2 ({threads} threads): x{parallel_speedup:.2}");

    log.push(json!({
        "group": "comparison_kernels",
        "workload_bytes": buffer.len(),
        "planted_matches": planted,
        "rayon_threads": threads,
        "parallel_chunk_bytes": chunk,
        "avx2_available": kernel::avx2_available(),
        "measurements": [scalar.to_json(), simd.to_json(), parallel.to_json()],
        "avx2_over_scalar": speedup,
        "rayon_over_avx2": parallel_speedup,
    }));
}

struct Fixture {
    child: Child,
    meta: Value,
}

impl Fixture {
    fn start(exe: &Path) -> Self {
        let mut child = Command::new(exe)
            .arg("--bench")
            .current_dir(exe.parent().expect("fixture dir"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the fixture");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("startup json");
        let meta: Value = serde_json::from_str(line.trim()).expect("startup json parses");
        let mut ready = String::new();
        reader.read_line(&mut ready).expect("ready");
        assert_eq!(ready.trim(), "ready");
        std::thread::spawn(move || {
            let mut sink = String::new();
            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });
        Self { child, meta }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bench_remote_scans(log: &mut Vec<Value>, fixture_exe: &Path) {
    println!();
    println!("== end-to-end remote scans against the fixture 128 MiB region ==");

    let dir = std::env::temp_dir().join("memscope-bench");
    std::fs::create_dir_all(&dir).expect("bench temp dir");
    let allowlist = dir.join("allowlist.json");
    let sha = sha256_file(fixture_exe, "bench").expect("hash the fixture");
    std::fs::write(
        &allowlist,
        serde_json::to_string_pretty(&json!({
            "schema": 1,
            "entries": [{ "path": fixture_exe.display().to_string(), "sha256": sha }]
        }))
        .expect("serialise"),
    )
    .expect("write allowlist");

    let fixture = Fixture::start(fixture_exe);
    let pid = fixture.meta["pid"].as_u64().expect("pid") as u32;
    let bench_base = u64::from_str_radix(
        fixture.meta["areas"]["bench"]["address"]
            .as_str()
            .expect("bench area; run the fixture with --bench")
            .trim_start_matches("0x"),
        16,
    )
    .expect("hex");
    let bench_size = fixture.meta["areas"]["bench"]["size"]
        .as_u64()
        .expect("bench size");
    let expected_matches = fixture.meta["datasets"]["bench_matches"]
        .as_u64()
        .expect("bench_matches");
    let needle = fixture.meta["datasets"]["bench_value"]
        .as_i64()
        .expect("bench_value");

    let mut policy = Policy::load(allowlist);
    let (session, _) = Session::attach(pid, &mut policy, "bench").expect("attach");
    let session_ref = session.read_ref();

    let filter = RegionFilter {
        min_address: Some(format!("0x{bench_base:x}")),
        max_address: Some(format!("0x{:x}", bench_base + bench_size)),
        ..Default::default()
    };
    let budget = ScanBudget {
        display_limit: 100,
        max_results: 1_000_000,
        max_snapshot_bytes: 512 * 1024 * 1024,
        max_bytes_scanned: 8 * 1024 * 1024 * 1024,
        timeout_ms: 300_000,
    };

    struct Case {
        name: &'static str,
        value_type: ValueType,
        operator: Operator,
        low: Option<Needle>,
        high: Option<Needle>,
    }

    let cases = vec![
        Case {
            name: "int32 exact",
            value_type: ValueType::Int32,
            operator: Operator::Exact,
            low: Some(Needle::Int {
                value: WireI64(needle),
            }),
            high: None,
        },
        Case {
            name: "int32 greater_than",
            value_type: ValueType::Int32,
            operator: Operator::GreaterThan,
            low: Some(Needle::Int { value: WireI64(0) }),
            high: None,
        },
        Case {
            name: "float exact",
            value_type: ValueType::Float,
            operator: Operator::Exact,
            low: Some(Needle::Float { value: 0.1 }),
            high: None,
        },
        Case {
            name: "double between",
            value_type: ValueType::Double,
            operator: Operator::Between,
            low: Some(Needle::Float { value: 0.0 }),
            high: Some(Needle::Float { value: 1.0 }),
        },
    ];

    let mut group = Vec::new();
    for Case {
        name,
        value_type,
        operator,
        low,
        high,
    } in cases
    {
        let mut end_to_end = Measurement::new(format!("{name}: end to end"), "MB/s");
        let mut capture = Measurement::new(format!("{name}: remote capture"), "MB/s");
        let mut compare = Measurement::new(format!("{name}: comparison"), "MB/s");
        let mut materialise = Measurement::new(format!("{name}: materialisation"), "ms");
        let mut total_ms = Measurement::new(format!("{name}: total latency"), "ms");
        let mut matches_seen = 0u64;
        let mut bytes_visited = 0u64;

        for run in 0..(WARMUP_RUNS + MEASURED_RUNS) {
            let request = FirstScanRequest {
                value_type,
                operator,
                needle: low.clone(),
                needle_high: high.clone(),
                pattern: None,
                filter: filter.clone(),
                alignment: None,
                budget: budget.clone(),
                float_compare: None,
            };
            let started = Instant::now();
            let (_state, outcome) =
                scan::first_scan(&session_ref, &request, Cancel::new(), || Ok(()), "bench")
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
            let wall = started.elapsed();

            if run < WARMUP_RUNS {
                continue;
            }
            bytes_visited = outcome.coverage.bytes_visited.0;
            matches_seen = outcome
                .total_matches
                .map(|m| m.0)
                .unwrap_or(outcome.retained as u64);
            let visited = bytes_visited as usize;
            end_to_end.samples.push(mb_per_second(visited, wall));
            capture.samples.push(mb_per_second(
                visited,
                Duration::from_micros(outcome.timing.capture_us.0),
            ));
            compare.samples.push(mb_per_second(
                visited,
                Duration::from_micros(outcome.timing.compare_us.0),
            ));
            materialise
                .samples
                .push(outcome.timing.materialise_us.0 as f64 / 1000.0);
            total_ms
                .samples
                .push(outcome.timing.total_us.0 as f64 / 1000.0);
        }

        println!();
        println!(
            "  {name}: {matches_seen} matches over {} MiB visited",
            bytes_visited / (1024 * 1024)
        );
        end_to_end.report();
        capture.report();
        compare.report();
        materialise.report();
        total_ms.report();

        if name == "int32 exact" {
            assert!(
                matches_seen >= expected_matches,
                "the int32 exact scan must find at least the {expected_matches} planted matches"
            );
        }

        group.push(json!({
            "case": name,
            "value_type": value_type.as_str(),
            "operator": operator.as_str(),
            "matches": matches_seen,
            "bytes_visited": bytes_visited,
            "measurements": [
                end_to_end.to_json(), capture.to_json(), compare.to_json(),
                materialise.to_json(), total_ms.to_json(),
            ],
        }));
    }

    let peak = target::peak_working_set_bytes().unwrap_or(0);
    println!();
    println!(
        "  peak working set of this benchmark process: {:.1} MiB",
        peak as f64 / (1024.0 * 1024.0)
    );

    log.push(json!({
        "group": "remote_scans",
        "fixture_pid": pid,
        "bench_region_bytes": bench_size,
        "expected_planted_matches": expected_matches,
        "cases": group,
        "peak_working_set_bytes": peak,
    }));

    drop(session);
}

fn bench_pointer_index(log: &mut Vec<Value>, fixture_exe: &Path) {
    println!();
    println!("== pointer index build ==");

    let dir = std::env::temp_dir().join("memscope-bench");
    let allowlist = dir.join("allowlist.json");
    let fixture = Fixture::start(fixture_exe);
    let pid = fixture.meta["pid"].as_u64().expect("pid") as u32;
    let bench_base = u64::from_str_radix(
        fixture.meta["areas"]["bench"]["address"]
            .as_str()
            .expect("bench area")
            .trim_start_matches("0x"),
        16,
    )
    .expect("hex");
    let bench_size = fixture.meta["areas"]["bench"]["size"]
        .as_u64()
        .expect("bench size");

    let mut policy = Policy::load(allowlist);
    let (session, _) = Session::attach(pid, &mut policy, "bench").expect("attach");
    let session_ref = session.read_ref();

    let mut throughput = Measurement::new("pointer index build", "MB/s");
    let mut entries_seen = 0u64;
    let mut index_bytes = 0u64;

    for run in 0..(WARMUP_RUNS + MEASURED_RUNS) {
        let request = memscope::ptr::PointerScanRequest {
            target: format!("0x{bench_base:x}"),
            max_depth: Some(1),
            max_offset: Some(0),
            offset_alignment: Some(8),
            max_results: Some(1),
            max_index_bytes: Some(2 * 1024 * 1024 * 1024),
            timeout_ms: Some(300_000),
            filter: RegionFilter {
                min_address: Some(format!("0x{bench_base:x}")),
                max_address: Some(format!("0x{:x}", bench_base + bench_size)),
                ..Default::default()
            },
            require_module_base: true,
        };
        let outcome =
            memscope::ptr::pointer_scan(&session_ref, &request, &Cancel::new(), || Ok(()), "bench")
                .expect("pointer scan");
        if run < WARMUP_RUNS {
            continue;
        }
        entries_seen = outcome.index_entries.0;
        index_bytes = outcome.index_bytes.0;
        throughput.samples.push(mb_per_second(
            outcome.bytes_indexed.0 as usize,
            Duration::from_micros(outcome.index_build_us.0),
        ));
    }

    throughput.report();
    println!(
        "  index held {entries_seen} pointer-valued slots in {:.1} MiB",
        index_bytes as f64 / (1024.0 * 1024.0)
    );

    log.push(json!({
        "group": "pointer_index",
        "bench_region_bytes": bench_size,
        "index_entries": entries_seen,
        "index_bytes": index_bytes,
        "measurements": [throughput.to_json()],
    }));

    drop(session);
}

fn main() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_exe = repo.join("fixtures/bin/x64/memscope-fixture.exe");
    if !fixture_exe.exists() {
        eprintln!(
            "{} is missing; run fixtures/build.ps1 first",
            fixture_exe.display()
        );
        std::process::exit(2);
    }

    println!("memscope benchmark");
    println!("  warm-up runs:   {WARMUP_RUNS}");
    println!("  measured runs:  {MEASURED_RUNS}");
    println!("  reported value: median, with min and max");
    println!("  unit:           MB/s means mebibytes of target memory examined per second");
    println!("  avx2 available: {}", kernel::avx2_available());
    println!("  rayon threads:  {}", rayon::current_num_threads());
    println!();

    let mut log: Vec<Value> = Vec::new();
    bench_kernels(&mut log);
    bench_remote_scans(&mut log, &fixture_exe);
    bench_pointer_index(&mut log, &fixture_exe);

    let artifacts = repo.join("artifacts");
    std::fs::create_dir_all(&artifacts).expect("artifacts dir");
    let out = artifacts.join("benchmark-raw.json");
    let document = json!({
        "tool": "memscope-bench",
        "version": memscope::VERSION,
        "recorded_at_unix_seconds": std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "warmup_runs": WARMUP_RUNS,
        "measured_runs": MEASURED_RUNS,
        "unit_definition": "MB/s = mebibytes (1048576 bytes) of target memory examined per second",
        "avx2_available": kernel::avx2_available(),
        "rayon_threads": rayon::current_num_threads(),
        "groups": log,
    });
    std::fs::write(
        &out,
        serde_json::to_string_pretty(&document).expect("serialise"),
    )
    .expect("write raw log");
    println!();
    println!("raw measurements written to {}", out.display());
}
