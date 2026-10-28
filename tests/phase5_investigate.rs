#![allow(clippy::result_large_err)]

mod common;

use common::{Fixture, allowlist_for};
use memscope::error::ErrorCode;
use memscope::investigate::{
    self, DissectRequest, Evidence, EvidenceLevel, MAX_WATCH_DURATION_MS, WatchRequest,
};
use memscope::mem::{ConsistencyMode, Decoded, ValueType};
use memscope::policy::Policy;
use memscope::scan::{
    self, Cancel, GroupFieldSpec, GroupScanRequest, Needle, Operator, RegionFilter, ScanBudget,
};
use memscope::target::Session;
use memscope::wire::{WireI64, WireU64};

struct Harness {
    fixture: Fixture,
    session: Session,
    _dir: tempfile::TempDir,
    _policy: Policy,
}

impl Harness {
    fn start(arch: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut policy = Policy::load(allowlist_for(dir.path(), arch));
        let fixture = Fixture::start(arch);
        let (session, _) = Session::attach(fixture.pid(), &mut policy, "attach_process")
            .unwrap_or_else(|e| panic!("{arch}: attach: {e}"));
        Self {
            fixture,
            session,
            _dir: dir,
            _policy: policy,
        }
    }

    fn filter_around(&self, area: &str) -> RegionFilter {
        let base = self.fixture.area(area);
        let size = self.fixture.meta["areas"][area]["size"]
            .as_u64()
            .expect("area size");
        RegionFilter {
            min_address: Some(format!("0x{:x}", base & !0xFFFF)),
            max_address: Some(format!("0x{:x}", base + size + 0x1_0000)),
            ..Default::default()
        }
    }
}

fn budget() -> ScanBudget {
    ScanBudget {
        display_limit: 100,
        max_results: 10_000,
        max_snapshot_bytes: 32 * 1024 * 1024,
        max_bytes_scanned: 128 * 1024 * 1024,
        timeout_ms: 20_000,
    }
}

fn counter_group(h: &Harness) -> GroupScanRequest {
    GroupScanRequest {
        fields: vec![
            GroupFieldSpec {
                name: "sentinel_before".to_owned(),
                value_type: ValueType::Uint32,
                offset: -4,
                operator: Operator::Exact,
                needle: Some(Needle::Uint {
                    value: WireU64(0xA5A5_A5A5),
                }),
                needle_high: None,
            },
            GroupFieldSpec {
                name: "counter".to_owned(),
                value_type: ValueType::Int32,
                offset: 0,
                operator: Operator::Exact,
                needle: Some(Needle::Int {
                    value: WireI64(100),
                }),
                needle_high: None,
            },
            GroupFieldSpec {
                name: "sentinel_after".to_owned(),
                value_type: ValueType::Uint32,
                offset: 4,
                operator: Operator::Exact,
                needle: Some(Needle::Uint {
                    value: WireU64(0x5A5A_5A5A),
                }),
                needle_high: None,
            },
        ],
        filter: h.filter_around("block"),
        alignment: Some(4),
        budget: budget(),
        float_compare: None,
    }
}

#[test]
fn a_group_scan_matches_typed_fields_at_fixed_offsets_with_field_level_evidence() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let counter = h.fixture.counter_address();

        let outcome = scan::group_scan(
            &h.session.read_ref(),
            &counter_group(&h),
            Cancel::new(),
            || Ok(()),
            "group_scan",
        )
        .unwrap_or_else(|e| panic!("{arch}: group_scan: {e}"));

        assert_eq!(outcome.field_count, 3, "{arch}");
        assert_eq!(outcome.min_offset, -4, "{arch}");
        assert_eq!(outcome.max_offset, 8, "{arch}");
        assert_eq!(outcome.span_bytes, 12, "{arch}");
        assert!(outcome.values_are_from_capture, "{arch}");
        assert!(!outcome.truncated, "{arch}");

        let hit = outcome
            .matches
            .iter()
            .find(|m| m.base_address_raw.0 == counter)
            .unwrap_or_else(|| {
                panic!(
                    "{arch}: the counter at 0x{counter:x} must be the base of a group match; got {:?}",
                    outcome
                        .matches
                        .iter()
                        .map(|m| m.base_address_raw.0)
                        .collect::<Vec<_>>()
                )
            });

        assert_eq!(hit.fields.len(), 3, "{arch}");
        assert_eq!(hit.span_start_raw.0, counter - 4, "{arch}");
        assert_eq!(hit.span_end_raw.0, counter + 8, "{arch}");

        let before = &hit.fields[0];
        assert_eq!(before.name, "sentinel_before", "{arch}");
        assert_eq!(before.offset, -4, "{arch}");
        assert_eq!(before.address_raw.0, counter - 4, "{arch}");
        assert_eq!(before.captured_raw, "a5a5a5a5", "{arch}");
        assert!(before.matched, "{arch}");

        let middle = &hit.fields[1];
        assert_eq!(middle.name, "counter", "{arch}");
        assert_eq!(middle.address_raw.0, counter, "{arch}");
        assert_eq!(middle.captured_raw, "64000000", "{arch}");
        match &middle.captured_decoded {
            Some(Decoded::Int { value }) => assert_eq!(value.0, 100, "{arch}"),
            other => panic!("{arch}: expected a decoded int, got {other:?}"),
        }

        let after = &hit.fields[2];
        assert_eq!(after.address_raw.0, counter + 4, "{arch}");
        assert_eq!(after.captured_raw, "5a5a5a5a", "{arch}");
    }
}

#[test]
fn a_group_scan_requires_every_field_to_match_at_once() {
    let h = Harness::start("x64");
    let mut request = counter_group(&h);
    request.fields[0].needle = Some(Needle::Uint {
        value: WireU64(0xDEAD_BEEF),
    });

    let outcome = scan::group_scan(
        &h.session.read_ref(),
        &request,
        Cancel::new(),
        || Ok(()),
        "group_scan",
    )
    .expect("group_scan");
    assert_eq!(
        outcome.retained, 0,
        "no base satisfies a sentinel that is not there"
    );
    assert_eq!(outcome.total_matches.expect("complete").0, 0);
}

#[test]
fn a_group_scan_refuses_delta_operators_and_variable_length_fields() {
    let h = Harness::start("x64");

    let mut delta = counter_group(&h);
    delta.fields[1].operator = Operator::Increased;
    let err = scan::group_scan(
        &h.session.read_ref(),
        &delta,
        Cancel::new(),
        || Ok(()),
        "group_scan",
    )
    .expect_err("a delta operator has no previous observation in a group scan");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let mut variable = counter_group(&h);
    variable.fields[1].value_type = ValueType::String;
    let err = scan::group_scan(
        &h.session.read_ref(),
        &variable,
        Cancel::new(),
        || Ok(()),
        "group_scan",
    )
    .expect_err("a string has no fixed size");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let mut empty = counter_group(&h);
    empty.fields.clear();
    assert_eq!(
        scan::group_scan(
            &h.session.read_ref(),
            &empty,
            Cancel::new(),
            || Ok(()),
            "group_scan"
        )
        .expect_err("no fields")
        .code,
        ErrorCode::InvalidArgument
    );

    let mut huge = counter_group(&h);
    huge.fields[2].offset = 1024 * 1024;
    assert_eq!(
        scan::group_scan(
            &h.session.read_ref(),
            &huge,
            Cancel::new(),
            || Ok(()),
            "group_scan"
        )
        .expect_err("the span is too large")
        .code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn watching_a_self_mutating_value_reports_timestamps_and_distinct_values() {
    let mut h = Harness::start("x64");
    assert_eq!(h.fixture.send("tick 20"), "tick=20");

    let outcome = investigate::watch_value(
        &h.session.read_ref(),
        &WatchRequest {
            address: format!("0x{:x}", h.fixture.counter_address()),
            value_type: ValueType::Int32,
            max_bytes: None,
            interval_ms: 10,
            duration_ms: 400,
            max_samples: Some(64),
            consistency: None,
        },
        || Ok(()),
        "watch_value",
    )
    .expect("watch");

    assert!(outcome.taken_samples > 5, "got {}", outcome.taken_samples);
    assert_eq!(outcome.failed_samples, 0);
    assert!(
        outcome.distinct_raw_values > 1,
        "a ticking counter must show more than one value, got {}",
        outcome.distinct_raw_values
    );
    assert_eq!(outcome.consistency, ConsistencyMode::Live);
    assert_eq!(outcome.interval_ms, 10);

    for window in outcome.samples.windows(2) {
        assert!(
            window[1].observed_at_unix_us.0 >= window[0].observed_at_unix_us.0,
            "sample timestamps must be non-decreasing"
        );
        assert!(window[1].elapsed_us.0 >= window[0].elapsed_us.0);
        assert!(window[0].readable);
        assert!(window[0].raw.is_some());
    }

    assert!(
        outcome
            .observation_limits
            .iter()
            .any(|l| l.contains("not instrumentation")),
        "the result must state that polling cannot see every write"
    );
    assert!(
        outcome
            .observation_limits
            .iter()
            .any(|l| l.contains("torn value")),
        "the result must state the tearing limitation"
    );

    assert_eq!(h.fixture.send("tick 0"), "tick=0");
}

#[test]
fn the_cooperative_pause_protocol_holds_a_watched_value_still() {
    let mut h = Harness::start("x64");
    assert_eq!(h.fixture.send("tick 20"), "tick=20");
    assert_eq!(h.fixture.send("pause"), "paused=1");

    let outcome = investigate::watch_value(
        &h.session.read_ref(),
        &WatchRequest {
            address: format!("0x{:x}", h.fixture.counter_address()),
            value_type: ValueType::Int32,
            max_bytes: None,
            interval_ms: 10,
            duration_ms: 300,
            max_samples: Some(64),
            consistency: None,
        },
        || Ok(()),
        "watch_value",
    )
    .expect("watch while paused");

    assert!(outcome.taken_samples > 5);
    assert_eq!(
        outcome.distinct_raw_values, 1,
        "the fixture cooperatively paused its own mutation, so every sample must agree"
    );
    assert_eq!(
        outcome.consistency,
        ConsistencyMode::Live,
        "a cooperative pause does not make this a natively paused observation, and the result \
         must not claim otherwise"
    );

    assert_eq!(h.fixture.send("resume"), "resumed=1");
    assert_eq!(h.fixture.send("tick 0"), "tick=0");
}

#[test]
fn a_natively_paused_watch_is_refused_as_consistency_unavailable() {
    let h = Harness::start("x64");
    let err = investigate::watch_value(
        &h.session.read_ref(),
        &WatchRequest {
            address: format!("0x{:x}", h.fixture.counter_address()),
            value_type: ValueType::Int32,
            max_bytes: None,
            interval_ms: 10,
            duration_ms: 100,
            max_samples: Some(4),
            consistency: Some(ConsistencyMode::Paused),
        },
        || Ok(()),
        "watch_value",
    )
    .expect_err("native pause is not implemented");
    assert_eq!(err.code, ErrorCode::ConsistencyUnavailable);
}

#[test]
fn watching_an_unreadable_address_counts_failed_samples_instead_of_inventing_values() {
    let h = Harness::start("x64");
    let outcome = investigate::watch_value(
        &h.session.read_ref(),
        &WatchRequest {
            address: format!("0x{:x}", h.fixture.area("noaccess")),
            value_type: ValueType::Int32,
            max_bytes: None,
            interval_ms: 10,
            duration_ms: 100,
            max_samples: Some(8),
            consistency: None,
        },
        || Ok(()),
        "watch_value",
    )
    .expect("a watch over an unreadable page still returns an honest record");

    assert!(outcome.taken_samples > 0);
    assert_eq!(
        outcome.failed_samples, outcome.taken_samples,
        "every sample over a PAGE_NOACCESS page must be recorded as failed"
    );
    assert_eq!(outcome.distinct_raw_values, 0);
    assert!(outcome.samples.iter().all(|s| !s.readable));
    assert!(outcome.samples.iter().all(|s| s.raw.is_none()));
}

#[test]
fn watch_bounds_are_enforced() {
    let h = Harness::start("x64");
    let base = WatchRequest {
        address: format!("0x{:x}", h.fixture.counter_address()),
        value_type: ValueType::Int32,
        max_bytes: None,
        interval_ms: 10,
        duration_ms: 100,
        max_samples: Some(4),
        consistency: None,
    };

    for bad in [
        WatchRequest {
            interval_ms: 0,
            ..base.clone()
        },
        WatchRequest {
            interval_ms: 100_000,
            ..base.clone()
        },
        WatchRequest {
            duration_ms: 0,
            ..base.clone()
        },
        WatchRequest {
            duration_ms: MAX_WATCH_DURATION_MS + 1,
            ..base.clone()
        },
        WatchRequest {
            max_samples: Some(0),
            ..base.clone()
        },
        WatchRequest {
            value_type: ValueType::String,
            max_bytes: None,
            ..base.clone()
        },
    ] {
        let err = investigate::watch_value(&h.session.read_ref(), &bad, || Ok(()), "watch_value")
            .expect_err("out-of-range watch arguments must be refused");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}

#[test]
fn dissecting_a_region_labels_every_inference_as_a_heuristic() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let outcome = investigate::dissect_region(
            &h.session.read_ref(),
            &DissectRequest {
                address: format!("0x{:x}", h.fixture.area("block")),
                length: 256,
                stride: None,
                consistency: None,
            },
            "dissect_region",
        )
        .unwrap_or_else(|e| panic!("{arch}: dissect: {e}"));

        assert!(outcome.analysis_is_heuristic, "{arch}");
        assert!(
            outcome.heuristic_warning.contains("inference"),
            "{arch}: the warning must say the analysis is inferred"
        );
        assert!(
            outcome.heuristic_warning.contains("No compiler layout"),
            "{arch}: the warning must disclaim compiler layout knowledge"
        );
        assert_eq!(outcome.actual_bytes, 256, "{arch}");
        assert!(outcome.complete, "{arch}");
        assert_eq!(
            outcome.stride,
            h.session.arch().pointer_width().bytes(),
            "{arch}"
        );
        assert!(!outcome.slots.is_empty(), "{arch}");

        for slot in &outcome.slots {
            for possible in &slot.possible_types {
                assert_eq!(possible.confidence, "heuristic", "{arch}");
                assert!(!possible.basis.is_empty(), "{arch}");
            }
        }
    }
}

#[test]
fn dissection_finds_the_pointer_to_node1_and_calls_it_a_candidate() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let slot_address = h.fixture.area("block") + h.fixture.layout("pointer_root");
        let node1 = u64::from_str_radix(
            h.fixture.meta["pointer_chain"]["node1"]
                .as_str()
                .expect("node1")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");

        let outcome = investigate::dissect_region(
            &h.session.read_ref(),
            &DissectRequest {
                address: format!("0x{:x}", h.fixture.area("block")),
                length: 256,
                stride: Some(h.session.arch().pointer_width().bytes()),
                consistency: None,
            },
            "dissect_region",
        )
        .expect("dissect");

        let found = outcome
            .pointer_candidates
            .iter()
            .find(|p| p.address_matches(slot_address))
            .unwrap_or_else(|| {
                panic!(
                    "{arch}: the pointer slot must be reported as pointer-like; got {:?}",
                    outcome
                        .pointer_candidates
                        .iter()
                        .map(|p| p.address.clone())
                        .collect::<Vec<_>>()
                )
            });
        assert_eq!(found.value_raw.0, node1, "{arch}");
        assert!(
            found.basis.contains("heuristic"),
            "{arch}: a pointer candidate must be labelled a heuristic, got {}",
            found.basis
        );
        assert!(
            found.points_into_region.is_some() || found.points_into_module.is_some(),
            "{arch}: the basis must name the mapping the value lands in"
        );
    }
}

#[test]
fn dissection_reports_strings_as_inferred_with_the_run_length_behind_them() {
    let h = Harness::start("x64");
    let strings_base = h.fixture.meta["strings"]["base"]
        .as_str()
        .expect("strings base");
    let strings_base = u64::from_str_radix(strings_base.trim_start_matches("0x"), 16).expect("hex");

    let outcome = investigate::dissect_region(
        &h.session.read_ref(),
        &DissectRequest {
            address: format!("0x{strings_base:x}"),
            length: 256,
            stride: Some(4),
            consistency: None,
        },
        "dissect_region",
    )
    .expect("dissect");

    assert!(
        outcome
            .strings
            .iter()
            .any(|s| s.text.contains("memscope-utf8") && s.encoding == "utf-8/ascii"),
        "the UTF-8 fixture string must be found; got {:?}",
        outcome.strings.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
    assert!(
        outcome
            .strings
            .iter()
            .any(|s| s.text.contains("memscope-utf16") && s.encoding == "utf-16le"),
        "the UTF-16LE fixture string must be found"
    );
    let terminated = outcome
        .strings
        .iter()
        .find(|s| s.text.contains("memscope-utf8"))
        .expect("the utf-8 string");
    assert!(terminated.terminated);
    assert!(
        terminated.basis.contains("printable"),
        "the basis must state the run-length heuristic, got {}",
        terminated.basis
    );
}

#[test]
fn dissection_bounds_are_enforced() {
    let h = Harness::start("x64");
    let base = format!("0x{:x}", h.fixture.area("block"));
    for (length, stride) in [
        (0usize, None),
        (1024 * 1024, None),
        (16, Some(0)),
        (16, Some(65)),
    ] {
        let err = investigate::dissect_region(
            &h.session.read_ref(),
            &DissectRequest {
                address: base.clone(),
                length,
                stride,
                consistency: None,
            },
            "dissect_region",
        )
        .expect_err("out-of-range dissect arguments must be refused");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}

#[test]
fn a_natively_paused_dissection_is_refused_too() {
    let h = Harness::start("x64");
    let err = investigate::dissect_region(
        &h.session.read_ref(),
        &DissectRequest {
            address: format!("0x{:x}", h.fixture.area("block")),
            length: 64,
            stride: None,
            consistency: Some(ConsistencyMode::Paused),
        },
        "dissect_region",
    )
    .expect_err("native pause is not implemented");
    assert_eq!(err.code, ErrorCode::ConsistencyUnavailable);
}

#[test]
fn evidence_is_promoted_only_by_an_independently_observed_change() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();
    let address = format!("0x{counter:x}");

    let (mut state, first) = scan::first_scan(
        &h.session.read_ref(),
        &memscope::scan::FirstScanRequest {
            value_type: ValueType::Int32,
            operator: Operator::Exact,
            needle: Some(Needle::Int {
                value: WireI64(100),
            }),
            needle_high: None,
            pattern: None,
            filter: h.filter_around("block"),
            alignment: None,
            budget: budget(),
            float_compare: None,
        },
        Cancel::new(),
        || Ok(()),
        "first_scan",
    )
    .expect("first scan");

    let candidate = Evidence::candidate(
        address.clone(),
        format!(
            "matched an exact int32 scan for 100 in scan {} ({} candidates retained)",
            first.scan_id, first.retained
        ),
    );
    assert_eq!(candidate.level, EvidenceLevel::Candidate);
    assert!(candidate.independent_observation.is_none());

    let fixture_reply = h.fixture.send("set 4242");
    assert_eq!(fixture_reply, "value=4242");

    let narrowed = scan::next_scan(
        &h.session.read_ref(),
        &mut state,
        &memscope::scan::NextScanRequest {
            operator: Operator::Changed,
            needle: None,
            baseline_source: memscope::scan::BaselineSource::PreviousScan,
            budget: budget(),
            float_compare: None,
            integer_overflow: None,
        },
        Cancel::new(),
        || Ok(()),
        "next_scan",
    )
    .expect("narrow");

    assert!(state.candidates.addresses.contains(&counter));

    let correlated = candidate.promote_to_behaviour_correlated(
        format!(
            "narrowed with the changed operator in scan {}; {} candidates survived",
            narrowed.scan_id, narrowed.retained
        ),
        format!("the fixture reported {fixture_reply} on its own control channel"),
    );
    assert_eq!(correlated.level, EvidenceLevel::BehaviourCorrelated);
    assert_eq!(correlated.address, address);
    assert!(
        correlated
            .independent_observation
            .as_deref()
            .expect("an independent observation")
            .contains("value=4242"),
        "the claim must name the independent observation behind it"
    );
    assert!(correlated.caveat.contains("not identity"));

    let json = serde_json::to_value(&correlated).expect("serialise");
    assert_eq!(json["level"], "behaviour_correlated");
    assert!(json["test_performed"].as_str().unwrap().contains("changed"));
}

trait PointerAddress {
    fn address_matches(&self, raw: u64) -> bool;
}

impl PointerAddress for investigate::DissectPointer {
    fn address_matches(&self, raw: u64) -> bool {
        u64::from_str_radix(self.address.trim_start_matches("0x"), 16)
            .map(|a| a == raw)
            .unwrap_or(false)
    }
}
