#![allow(clippy::result_large_err)]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};

use common::{Fixture, allowlist_for};
use memscope::error::{ErrorCode, OperationError, Result};
use memscope::mem::ValueType;
use memscope::policy::Policy;
use memscope::scan::{
    self, BaselineSource, Cancel, ExclusionReason, FirstScanRequest, ListResultsRequest, Needle,
    NextScanRequest, Operator, RegionFilter, RegionKind, RegionState, ScanBudget, ScanState,
    StopReason,
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
        Self::start_with_args(arch, &[])
    }

    fn start_with_args(arch: &str, args: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut policy = Policy::load(allowlist_for(dir.path(), arch));
        let fixture = Fixture::start_with_args(arch, args);
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

fn allow_everything() -> impl FnMut() -> Result<()> {
    || Ok(())
}

fn tight_budget() -> ScanBudget {
    ScanBudget {
        display_limit: 100,
        max_results: 100_000,
        max_snapshot_bytes: 64 * 1024 * 1024,
        max_bytes_scanned: 256 * 1024 * 1024,
        timeout_ms: 20_000,
    }
}

fn int32_exact(value: i64, filter: RegionFilter) -> FirstScanRequest {
    FirstScanRequest {
        value_type: ValueType::Int32,
        operator: Operator::Exact,
        needle: Some(Needle::Int {
            value: WireI64(value),
        }),
        needle_high: None,
        pattern: None,
        filter,
        alignment: None,
        budget: tight_budget(),
        float_compare: None,
    }
}

fn scan_for(h: &Harness, request: &FirstScanRequest) -> (ScanState, scan::ScanOutcome) {
    scan::first_scan(
        &h.session.read_ref(),
        request,
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .unwrap_or_else(|e| panic!("first_scan: {e}"))
}

#[test]
fn list_regions_reports_mapping_metadata_and_every_exclusion_reason() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let regions = scan::list_regions(
            &h.session.read_ref(),
            &RegionFilter {
                include_images: true,
                ..Default::default()
            },
            "list_regions",
        )
        .unwrap_or_else(|e| panic!("{arch}: list_regions: {e}"));

        assert!(
            regions.len() > 20,
            "{arch}: expected a populated region map"
        );

        let committed = regions
            .iter()
            .filter(|r| r.state == RegionState::Commit)
            .count();
        assert!(committed > 5, "{arch}");
        assert!(
            regions.iter().any(|r| r.kind == RegionKind::Image),
            "{arch}: images were requested"
        );
        assert!(
            regions.iter().any(|r| r.module.is_some()),
            "{arch}: at least one region must be attributed to a module"
        );
        assert!(
            regions
                .iter()
                .any(|r| r.protection == "PAGE_READWRITE" && r.eligible),
            "{arch}"
        );

        let noaccess_base = h.fixture.area("noaccess");
        let noaccess = regions
            .iter()
            .find(|r| r.base_raw.0 == noaccess_base)
            .unwrap_or_else(|| panic!("{arch}: the PAGE_NOACCESS page must appear in the map"));
        assert!(!noaccess.eligible, "{arch}");
        assert!(
            noaccess.exclusions.contains(&ExclusionReason::NoAccess),
            "{arch}: got {:?}",
            noaccess.exclusions
        );

        let guard_base = h.fixture.area("guard");
        let guard = regions
            .iter()
            .find(|r| r.base_raw.0 == guard_base)
            .unwrap_or_else(|| panic!("{arch}: the PAGE_GUARD page must appear in the map"));
        assert!(!guard.eligible, "{arch}");
        assert!(
            guard.exclusions.contains(&ExclusionReason::GuardPage),
            "{arch}: got {:?}",
            guard.exclusions
        );

        assert!(
            regions
                .iter()
                .any(|r| r.exclusions.contains(&ExclusionReason::NotCommitted)),
            "{arch}: reserved or free regions must be reported with a reason"
        );
    }
}

#[test]
fn a_region_filter_narrows_the_map_and_explains_what_it_dropped() {
    let h = Harness::start("x64");
    let regions = scan::list_regions(
        &h.session.read_ref(),
        &h.filter_around("duplicates"),
        "list_regions",
    )
    .expect("list_regions");

    let eligible: Vec<_> = regions.iter().filter(|r| r.eligible).collect();
    assert!(
        !eligible.is_empty(),
        "the duplicates area must stay eligible"
    );
    assert!(
        regions
            .iter()
            .any(|r| r.exclusions.contains(&ExclusionReason::OutsideAddressRange)),
        "regions outside the range must be listed with the reason, not silently dropped"
    );
}

#[test]
fn an_exact_scan_finds_a_known_fixture_value_on_both_architectures() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let counter = h.fixture.counter_address();
        let (_state, outcome) = scan_for(&h, &int32_exact(100, h.filter_around("block")));

        assert_eq!(outcome.stop_reason, StopReason::Completed, "{arch}");
        assert!(!outcome.truncated, "{arch}");
        assert!(outcome.total_matches_known, "{arch}");
        assert!(outcome.values_are_from_capture, "{arch}");
        assert!(
            outcome.displayed.iter().any(|c| c.address_raw.0 == counter),
            "{arch}: the counter at 0x{counter:x} must be among the matches"
        );
        let hit = outcome
            .displayed
            .iter()
            .find(|c| c.address_raw.0 == counter)
            .expect("the counter");
        assert_eq!(hit.captured_raw, "64000000", "{arch}");
        assert!(outcome.coverage.slots_examined.0 > 0, "{arch}");
        assert!(outcome.coverage.bytes_visited.0 > 0, "{arch}");
        assert!(outcome.timing.capture_us.0 > 0, "{arch}");
    }
}

#[test]
fn a_duplicate_value_scan_finds_all_one_thousand_and_twenty_four_copies() {
    let h = Harness::start("x64");
    let expected = h.fixture.meta["datasets"]["duplicate_count"]
        .as_u64()
        .expect("duplicate_count");
    let needle = h.fixture.meta["datasets"]["duplicate_value"]
        .as_i64()
        .expect("duplicate_value");

    let (_state, outcome) = scan_for(&h, &int32_exact(needle, h.filter_around("duplicates")));
    assert!(!outcome.truncated);
    let total = outcome
        .total_matches
        .expect("a complete scan knows its total");
    assert!(
        total.0 >= expected,
        "expected at least {expected} copies, found {}",
        total.0
    );
    assert_eq!(outcome.retained as u64, total.0);
}

#[test]
fn a_value_straddling_a_chunk_boundary_is_found_exactly_once() {
    let h = Harness::start("x64");
    let straddle_value = h.fixture.meta["datasets"]["boundary_straddle_value"]
        .as_i64()
        .expect("boundary_straddle_value");
    let straddle_offset = h.fixture.meta["datasets"]["boundary_straddle_offset"]
        .as_u64()
        .expect("boundary_straddle_offset");
    let expected_address = h.fixture.area("boundary") + straddle_offset;

    let (_state, outcome) = scan_for(
        &h,
        &FirstScanRequest {
            alignment: Some(1),
            ..int32_exact(straddle_value, h.filter_around("boundary"))
        },
    );

    assert!(!outcome.truncated);
    let hits: Vec<u64> = outcome
        .displayed
        .iter()
        .map(|c| c.address_raw.0)
        .filter(|a| *a == expected_address)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the straddling value must be reported exactly once, not duplicated at the chunk seam"
    );
    assert_eq!(
        outcome.total_matches.expect("complete").0,
        1,
        "only the planted value should match"
    );
}

#[test]
fn a_wildcard_pattern_scan_finds_the_known_float_bytes() {
    let h = Harness::start("x64");
    let tenth_address = h.fixture.area("block") + h.fixture.layout("f32_tenth");

    let (_state, outcome) = scan::first_scan(
        &h.session.read_ref(),
        &FirstScanRequest {
            value_type: ValueType::Bytes,
            operator: Operator::Pattern,
            needle: None,
            needle_high: None,
            pattern: Some("cd ?? cc 3d".to_owned()),
            filter: h.filter_around("block"),
            alignment: Some(1),
            budget: tight_budget(),
            float_compare: None,
        },
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .expect("pattern scan");

    assert!(
        outcome
            .displayed
            .iter()
            .any(|c| c.address_raw.0 == tenth_address),
        "the binary32 0.1 bytes must match cd ?? cc 3d"
    );
}

#[test]
fn an_invalid_pattern_is_refused_before_any_memory_is_touched() {
    let h = Harness::start("x64");
    for bad in ["", "cdc", "?? ?? ??", "c?", "zz"] {
        let err = scan::first_scan(
            &h.session.read_ref(),
            &FirstScanRequest {
                value_type: ValueType::Bytes,
                operator: Operator::Pattern,
                needle: None,
                needle_high: None,
                pattern: Some(bad.to_owned()),
                filter: h.filter_around("block"),
                alignment: Some(1),
                budget: tight_budget(),
                float_compare: None,
            },
            Cancel::new(),
            allow_everything(),
            "first_scan",
        )
        .expect_err("pattern should be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument, "pattern {bad:?}");
    }
}

#[test]
fn an_unknown_first_scan_reports_coverage_without_materialising_addresses() {
    let h = Harness::start("x64");
    let (state, outcome) = scan::first_scan(
        &h.session.read_ref(),
        &FirstScanRequest {
            value_type: ValueType::Int32,
            operator: Operator::Unknown,
            needle: None,
            needle_high: None,
            pattern: None,
            filter: h.filter_around("boundary"),
            alignment: None,
            budget: tight_budget(),
            float_compare: None,
        },
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .expect("unknown scan");

    assert_eq!(
        outcome.retained, 0,
        "an unknown scan must not materialise an address list"
    );
    assert!(outcome.displayed.is_empty());
    let baseline_id = outcome
        .baseline_id
        .expect("an unknown scan creates a baseline");
    assert!(baseline_id.starts_with("baseline-"));
    let slots = outcome.baseline_slot_count.expect("slot count").0;
    let valid = outcome.baseline_valid_slots.expect("valid slots").0;
    let bytes = outcome.baseline_bytes.expect("baseline bytes").0;
    assert!(slots > 0, "the baseline must report candidate slots");
    assert!(valid > 0 && valid <= slots);
    assert!(
        bytes >= 128 * 1024,
        "the 128 KiB boundary region was captured"
    );
    assert!(state.initial_baseline.is_some());
}

#[test]
fn an_oversized_unknown_baseline_is_truncated_with_the_snapshot_reason() {
    let h = Harness::start("x64");
    let (_state, outcome) = scan::first_scan(
        &h.session.read_ref(),
        &FirstScanRequest {
            value_type: ValueType::Int32,
            operator: Operator::Unknown,
            needle: None,
            needle_high: None,
            pattern: None,
            filter: RegionFilter::default(),
            alignment: None,
            budget: ScanBudget {
                max_snapshot_bytes: 64 * 1024,
                ..tight_budget()
            },
            float_compare: None,
        },
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .expect("unknown scan");

    assert_eq!(outcome.stop_reason, StopReason::MaxSnapshotBytes);
    assert!(outcome.truncated);
    assert!(
        !outcome.total_matches_known,
        "a truncated scan must not claim to know the total"
    );
    assert!(outcome.total_matches.is_none());
}

#[test]
fn narrowing_follows_independent_fixture_changes_on_both_architectures() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let counter = h.fixture.counter_address();

        let (mut state, first) = scan_for(&h, &int32_exact(100, h.filter_around("block")));
        assert!(
            state.candidates.addresses.contains(&counter),
            "{arch}: the counter must be a candidate after the exact scan"
        );
        let before = first.retained;

        assert_eq!(h.fixture.send("set 777"), "value=777", "{arch}");

        let changed = scan::next_scan(
            &h.session.read_ref(),
            &mut state,
            &NextScanRequest {
                operator: Operator::Changed,
                needle: None,
                baseline_source: BaselineSource::PreviousScan,
                budget: tight_budget(),
                float_compare: None,
                integer_overflow: None,
            },
            Cancel::new(),
            allow_everything(),
            "next_scan",
        )
        .unwrap_or_else(|e| panic!("{arch}: next_scan changed: {e}"));

        assert!(
            state.candidates.addresses.contains(&counter),
            "{arch}: the counter changed and must survive a changed narrowing"
        );
        assert!(
            changed.retained <= before,
            "{arch}: narrowing cannot grow the candidate set"
        );
        assert_eq!(changed.generation.0, 2, "{arch}");
        assert_eq!(
            changed.compared_against_scan_id.as_deref(),
            Some(first.scan_id.as_str()),
            "{arch}: the comparison must name the scan it compared against"
        );

        assert_eq!(h.fixture.send("add 23"), "value=800", "{arch}");
        let increased = scan::next_scan(
            &h.session.read_ref(),
            &mut state,
            &NextScanRequest {
                operator: Operator::IncreasedBy,
                needle: Some(Needle::Int { value: WireI64(23) }),
                baseline_source: BaselineSource::PreviousScan,
                budget: tight_budget(),
                float_compare: None,
                integer_overflow: None,
            },
            Cancel::new(),
            allow_everything(),
            "next_scan",
        )
        .unwrap_or_else(|e| panic!("{arch}: next_scan increased_by: {e}"));

        assert!(
            state.candidates.addresses.contains(&counter),
            "{arch}: the counter rose by exactly 23 and must survive increased_by"
        );
        assert_eq!(increased.generation.0, 3, "{arch}");

        assert_eq!(h.fixture.send("sub 300"), "value=500", "{arch}");
        scan::next_scan(
            &h.session.read_ref(),
            &mut state,
            &NextScanRequest {
                operator: Operator::Decreased,
                needle: None,
                baseline_source: BaselineSource::PreviousScan,
                budget: tight_budget(),
                float_compare: None,
                integer_overflow: None,
            },
            Cancel::new(),
            allow_everything(),
            "next_scan",
        )
        .unwrap_or_else(|e| panic!("{arch}: next_scan decreased: {e}"));
        assert!(
            state.candidates.addresses.contains(&counter),
            "{arch}: the counter fell and must survive a decreased narrowing"
        );

        let unchanged = scan::next_scan(
            &h.session.read_ref(),
            &mut state,
            &NextScanRequest {
                operator: Operator::Unchanged,
                needle: None,
                baseline_source: BaselineSource::PreviousScan,
                budget: tight_budget(),
                float_compare: None,
                integer_overflow: None,
            },
            Cancel::new(),
            allow_everything(),
            "next_scan",
        )
        .expect("next_scan unchanged");
        assert!(
            state.candidates.addresses.contains(&counter),
            "{arch}: nothing changed between those two reads"
        );
        assert_eq!(unchanged.operator, Operator::Unchanged, "{arch}");
    }
}

#[test]
fn an_unknown_baseline_narrows_against_the_initial_baseline_when_asked() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();

    let (mut state, first) = scan::first_scan(
        &h.session.read_ref(),
        &FirstScanRequest {
            value_type: ValueType::Int32,
            operator: Operator::Unknown,
            needle: None,
            needle_high: None,
            pattern: None,
            filter: h.filter_around("block"),
            alignment: None,
            budget: tight_budget(),
            float_compare: None,
        },
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .expect("unknown scan");
    let baseline_id = first.baseline_id.clone().expect("baseline");

    assert_eq!(h.fixture.send("set 4242"), "value=4242");

    let changed = scan::next_scan(
        &h.session.read_ref(),
        &mut state,
        &NextScanRequest {
            operator: Operator::Changed,
            needle: None,
            baseline_source: BaselineSource::InitialBaseline,
            budget: tight_budget(),
            float_compare: None,
            integer_overflow: None,
        },
        Cancel::new(),
        allow_everything(),
        "next_scan",
    )
    .expect("narrow against the initial baseline");

    assert_eq!(changed.baseline_source, BaselineSource::InitialBaseline);
    assert_eq!(changed.baseline_id.as_deref(), Some(baseline_id.as_str()));
    assert_eq!(
        changed.compared_against_scan_id.as_deref(),
        Some(baseline_id.as_str()),
        "comparing against the initial baseline must name the baseline, not a scan"
    );
    assert!(
        state.candidates.addresses.contains(&counter),
        "the counter changed from its baseline value"
    );
}

#[test]
fn asking_for_an_initial_baseline_that_was_never_captured_is_a_state_error() {
    let h = Harness::start("x64");
    let (mut state, _) = scan_for(&h, &int32_exact(100, h.filter_around("block")));

    let err = scan::next_scan(
        &h.session.read_ref(),
        &mut state,
        &NextScanRequest {
            operator: Operator::Changed,
            needle: None,
            baseline_source: BaselineSource::InitialBaseline,
            budget: tight_budget(),
            float_compare: None,
            integer_overflow: None,
        },
        Cancel::new(),
        allow_everything(),
        "next_scan",
    )
    .expect_err("an exact first scan captures no baseline");
    assert_eq!(err.code, ErrorCode::ScanStateInvalid);
}

#[test]
fn paginating_results_does_not_remove_undisplayed_candidates() {
    let h = Harness::start("x64");
    let needle = h.fixture.meta["datasets"]["duplicate_value"]
        .as_i64()
        .expect("duplicate_value");

    let (state, outcome) = scan_for(
        &h,
        &FirstScanRequest {
            budget: ScanBudget {
                display_limit: 10,
                ..tight_budget()
            },
            ..int32_exact(needle, h.filter_around("duplicates"))
        },
    );

    assert_eq!(outcome.displayed.len(), 10, "only ten were displayed");
    assert!(
        outcome.retained > 10,
        "but far more were retained for narrowing"
    );
    assert!(
        !outcome.truncated,
        "display pagination alone is not scan truncation"
    );
    assert!(outcome.total_matches_known);

    let page_two = scan::list_results(
        &h.session.read_ref(),
        &state,
        &ListResultsRequest {
            offset: 10,
            limit: Some(10),
            reread_current: false,
        },
        "list_results",
    )
    .expect("page two");

    assert_eq!(page_two.displayed.len(), 10);
    assert_eq!(page_two.retained, outcome.retained);
    assert!(page_two.display_pagination_only);
    assert!(page_two.values_are_from_capture);
    assert_ne!(
        page_two.displayed[0].address_raw.0, outcome.displayed[0].address_raw.0,
        "page two must show different candidates"
    );

    let past_end = scan::list_results(
        &h.session.read_ref(),
        &state,
        &ListResultsRequest {
            offset: outcome.retained + 1,
            limit: Some(10),
            reread_current: false,
        },
        "list_results",
    )
    .expect_err("an offset past the retained set is an argument error");
    assert_eq!(past_end.code, ErrorCode::InvalidArgument);
}

#[test]
fn a_later_reread_is_reported_separately_from_the_captured_match() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();
    let (state, _) = scan_for(&h, &int32_exact(100, h.filter_around("block")));

    assert_eq!(h.fixture.send("set 31337"), "value=31337");

    let listed = scan::list_results(
        &h.session.read_ref(),
        &state,
        &ListResultsRequest {
            offset: 0,
            limit: Some(100),
            reread_current: true,
        },
        "list_results",
    )
    .expect("list with reread");

    let captured = listed
        .displayed
        .iter()
        .find(|c| c.address_raw.0 == counter)
        .expect("the counter is a candidate");
    assert_eq!(
        captured.captured_raw, "64000000",
        "the captured value must stay as it was observed during the scan"
    );

    let current = listed
        .current_values
        .iter()
        .find(|v| v.address == captured.address)
        .expect("a reread entry for the counter");
    assert!(current.readable);
    assert_eq!(
        current.current_raw.as_deref(),
        Some("697a0000"),
        "the reread must show the new value, separately"
    );
    assert!(current.observed_at_unix_us.0 > 0);
    assert!(listed.values_are_from_capture);
}

#[test]
fn hitting_the_result_cap_reports_truncation_and_withholds_the_total() {
    let h = Harness::start("x64");
    let needle = h.fixture.meta["datasets"]["duplicate_value"]
        .as_i64()
        .expect("duplicate_value");

    let (_state, outcome) = scan_for(
        &h,
        &FirstScanRequest {
            budget: ScanBudget {
                max_results: 5,
                display_limit: 10,
                ..tight_budget()
            },
            ..int32_exact(needle, h.filter_around("duplicates"))
        },
    );

    assert_eq!(outcome.stop_reason, StopReason::MaxResults);
    assert!(outcome.truncated);
    assert!(!outcome.total_matches_known);
    assert!(outcome.total_matches.is_none());
    assert_eq!(outcome.retained, 5);
    assert!(outcome.coverage.regions_eligible > 0);
    assert!(outcome.coverage.bytes_eligible.0 > 0);
}

#[test]
fn a_byte_budget_stops_the_sweep_and_says_so() {
    let h = Harness::start("x64");
    let (_state, outcome) = scan_for(
        &h,
        &FirstScanRequest {
            filter: RegionFilter::default(),
            budget: ScanBudget {
                max_bytes_scanned: 64 * 1024,
                ..tight_budget()
            },
            ..int32_exact(0x1122_3344, RegionFilter::default())
        },
    );
    assert_eq!(outcome.stop_reason, StopReason::MaxBytesScanned);
    assert!(outcome.truncated);
    assert!(!outcome.total_matches_known);
    assert!(outcome.coverage.bytes_visited.0 >= 64 * 1024);
    assert!(outcome.coverage.bytes_eligible.0 > outcome.coverage.bytes_visited.0);
}

#[test]
fn a_cancelled_scan_stops_immediately_and_is_marked_truncated() {
    let h = Harness::start("x64");
    let cancel = Cancel::new();
    cancel.cancel();

    let (_state, outcome) = scan::first_scan(
        &h.session.read_ref(),
        &int32_exact(100, RegionFilter::default()),
        cancel,
        allow_everything(),
        "first_scan",
    )
    .expect("a cancelled scan still returns an honest outcome");

    assert_eq!(outcome.stop_reason, StopReason::Cancelled);
    assert!(outcome.truncated);
    assert!(!outcome.total_matches_known);
    assert_eq!(outcome.coverage.regions_visited, 0);
}

#[test]
fn a_policy_revocation_during_a_long_scan_aborts_it() {
    let h = Harness::start("x64");
    let calls = AtomicU32::new(0);
    let err = scan::first_scan(
        &h.session.read_ref(),
        &int32_exact(100, RegionFilter::default()),
        Cancel::new(),
        || {
            if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(OperationError::new(
                    ErrorCode::TargetNotAllowed,
                    "first_scan",
                    "the allowlist entry was removed mid-scan",
                ))
            } else {
                Ok(())
            }
        },
        "first_scan",
    )
    .expect_err("a revoked policy must abort the scan");

    assert_eq!(err.code, ErrorCode::TargetNotAllowed);
    assert!(
        calls.load(Ordering::Relaxed) >= 1,
        "the policy checkpoint must actually be reached during the sweep"
    );
}

#[test]
fn resetting_a_scan_reports_what_it_discarded() {
    let h = Harness::start("x64");
    let (state, outcome) = scan_for(&h, &int32_exact(100, h.filter_around("block")));
    let scan_id = state.scan_id.clone();
    let reset = scan::reset_scan(state);
    assert_eq!(reset.cleared_scan_id, scan_id);
    assert_eq!(reset.cleared_candidates, outcome.retained);
    assert!(!reset.cleared_baseline);
    assert_eq!(reset.generation.0, 1);
}

#[test]
fn an_unreadable_candidate_is_dropped_rather_than_treated_as_zero() {
    let mut h = Harness::start("x64");
    let protect_base = h.fixture.area("protect");
    let needle = h.fixture.meta["datasets"]["duplicate_value"]
        .as_i64()
        .expect("duplicate_value");

    let (mut state, first) = scan_for(&h, &int32_exact(needle, h.filter_around("protect")));
    assert!(
        state.candidates.addresses.contains(&protect_base),
        "the protect page holds the needle at its base"
    );
    assert!(first.retained > 0);

    assert!(
        h.fixture
            .send("protect noaccess")
            .starts_with("protect=noaccess")
    );

    let after = scan::next_scan(
        &h.session.read_ref(),
        &mut state,
        &NextScanRequest {
            operator: Operator::Unchanged,
            needle: None,
            baseline_source: BaselineSource::PreviousScan,
            budget: tight_budget(),
            float_compare: None,
            integer_overflow: None,
        },
        Cancel::new(),
        allow_everything(),
        "next_scan",
    )
    .expect("next_scan over a now-unreadable page");

    assert!(
        !state.candidates.addresses.contains(&protect_base),
        "an unreadable slot must be dropped, never compared as zeroes"
    );
    assert!(
        after.coverage.bytes_unreadable.0 > 0,
        "the unreadable bytes must be reported"
    );
    assert!(
        h.fixture.send("protect rw").starts_with("protect=rw"),
        "restore the page for cleanliness"
    );
}

#[test]
fn a_delta_operator_is_refused_in_a_first_scan_and_unknown_is_refused_in_a_next_scan() {
    let h = Harness::start("x64");
    let err = scan::first_scan(
        &h.session.read_ref(),
        &FirstScanRequest {
            operator: Operator::Increased,
            needle: None,
            ..int32_exact(100, h.filter_around("block"))
        },
        Cancel::new(),
        allow_everything(),
        "first_scan",
    )
    .expect_err("increased needs a previous observation");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let (mut state, _) = scan_for(&h, &int32_exact(100, h.filter_around("block")));
    let err = scan::next_scan(
        &h.session.read_ref(),
        &mut state,
        &NextScanRequest {
            operator: Operator::Unknown,
            needle: None,
            baseline_source: BaselineSource::PreviousScan,
            budget: tight_budget(),
            float_compare: None,
            integer_overflow: None,
        },
        Cancel::new(),
        allow_everything(),
        "next_scan",
    )
    .expect_err("unknown starts a baseline and belongs to first_scan");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn a_range_scan_finds_a_value_between_two_bounds() {
    let h = Harness::start("x64");
    let counter = h.fixture.counter_address();
    let (_state, outcome) = scan_for(
        &h,
        &FirstScanRequest {
            operator: Operator::Between,
            needle: Some(Needle::Int { value: WireI64(99) }),
            needle_high: Some(Needle::Int {
                value: WireI64(101),
            }),
            ..int32_exact(100, h.filter_around("block"))
        },
    );
    assert!(
        outcome.displayed.iter().any(|c| c.address_raw.0 == counter),
        "100 lies inside [99, 101]"
    );
}

#[test]
fn a_pointer_scan_by_value_finds_the_slot_holding_node1_at_the_target_width() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let node1 = u64::from_str_radix(
            h.fixture.meta["pointer_chain"]["node1"]
                .as_str()
                .expect("node1")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");
        let slot = h.fixture.area("block") + h.fixture.layout("pointer_root");

        let (_state, outcome) = scan::first_scan(
            &h.session.read_ref(),
            &FirstScanRequest {
                value_type: ValueType::Pointer,
                operator: Operator::Exact,
                needle: Some(Needle::Uint {
                    value: WireU64(node1),
                }),
                needle_high: None,
                pattern: None,
                filter: h.filter_around("block"),
                alignment: Some(1),
                budget: tight_budget(),
                float_compare: None,
            },
            Cancel::new(),
            allow_everything(),
            "first_scan",
        )
        .unwrap_or_else(|e| panic!("{arch}: pointer scan: {e}"));

        assert!(
            outcome.displayed.iter().any(|c| c.address_raw.0 == slot),
            "{arch}: the in-block pointer slot must match its own value"
        );
        let hit = outcome
            .displayed
            .iter()
            .find(|c| c.address_raw.0 == slot)
            .expect("the slot");
        assert_eq!(
            hit.captured_raw.len() / 2,
            h.session.arch().pointer_width().bytes(),
            "{arch}: the captured pointer is exactly one pointer wide"
        );
    }
}
