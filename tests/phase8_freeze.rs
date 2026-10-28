#![allow(clippy::result_large_err)]

mod common;

use std::sync::Once;
use std::time::{Duration, Instant};

use common::{Fixture, allowlist_for};
use memscope::error::{ErrorCode, OperationError};
use memscope::mem::ValueType;
use memscope::mutate::{
    self, FailureJournal, FreezeRegistry, FreezeRequest, FreezeStopReason, RestoreOutcome,
    UndoHistory, UndoRequest, UnfreezeRequest, WritePayload, WriteRequest,
};
use memscope::policy::Policy;
use memscope::scan::Needle;
use memscope::target::Session;
use memscope::wire::WireI64;

static GATE: Once = Once::new();

fn open_the_write_gate() {
    GATE.call_once(|| {
        unsafe { std::env::set_var(memscope::WRITE_ENABLE_VAR, "1") };
    });
    assert!(memscope::writes_enabled_in_environment());
}

struct Harness {
    fixture: Fixture,
    session: Session,
    registry: FreezeRegistry,
    history: UndoHistory,
    journal: FailureJournal,
    _dir: tempfile::TempDir,
    allowlist: std::path::PathBuf,
}

impl Harness {
    fn start(arch: &str) -> Self {
        open_the_write_gate();
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = allowlist_for(dir.path(), arch);
        let mut policy = Policy::load(allowlist.clone());
        let fixture = Fixture::start(arch);
        let (mut session, _) = Session::attach(fixture.pid(), &mut policy, "attach_process")
            .unwrap_or_else(|e| panic!("{arch}: attach: {e}"));
        session
            .enable_writes("write_memory")
            .expect("enable writes");
        Self {
            fixture,
            session,
            registry: FreezeRegistry::default(),
            history: UndoHistory::default(),
            journal: FailureJournal::default(),
            _dir: dir,
            allowlist,
        }
    }

    fn freeze(
        &mut self,
        value: i64,
        interval_ms: u64,
        lifetime_ms: u64,
    ) -> memscope::error::Result<mutate::FreezeOutcome> {
        self.freeze_checked(value, interval_ms, lifetime_ms, Box::new(|| Ok(())))
    }

    fn freeze_checked(
        &mut self,
        value: i64,
        interval_ms: u64,
        lifetime_ms: u64,
        check: Box<dyn Fn() -> memscope::error::Result<()> + Send>,
    ) -> memscope::error::Result<mutate::FreezeOutcome> {
        let session = self.session.read_ref();
        let handle = self.session.write_handle("freeze_value").expect("handle");
        mutate::freeze_value(
            &session,
            handle,
            &FreezeRequest {
                address: format!("0x{:x}", self.fixture.counter_address()),
                payload: WritePayload::Typed {
                    value_type: ValueType::Int32,
                    value: Needle::Int {
                        value: WireI64(value),
                    },
                },
                interval_ms,
                lifetime_ms,
                confirm: true,
            },
            &mut self.registry,
            check,
            "freeze_value",
        )
    }

    fn unfreeze(
        &mut self,
        id: &str,
        restore: bool,
        confirm: bool,
    ) -> memscope::error::Result<mutate::UnfreezeOutcome> {
        self.unfreeze_checked(id, restore, confirm, || Ok(()))
    }

    fn unfreeze_checked(
        &mut self,
        id: &str,
        restore: bool,
        confirm: bool,
        valid: impl Fn() -> memscope::error::Result<()>,
    ) -> memscope::error::Result<mutate::UnfreezeOutcome> {
        let session = self.session.read_ref();
        let handle = self.session.write_handle("unfreeze_value").expect("handle");
        mutate::unfreeze_value(
            &session,
            handle,
            &UnfreezeRequest {
                freeze_id: id.to_owned(),
                restore_original: restore,
                confirm,
            },
            &mut self.registry,
            valid,
            "unfreeze_value",
        )
    }

    fn wait_until_value(&mut self, expected: i64, timeout: Duration) -> Option<Duration> {
        let started = Instant::now();
        let wanted = format!("value={expected}");
        while started.elapsed() < timeout {
            if self.fixture.send("get") == wanted {
                return Some(started.elapsed());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }
}

#[test]
fn a_freeze_captures_the_pre_freeze_bytes_and_holds_the_value() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let outcome = h
            .freeze(555, 10, 3_000)
            .unwrap_or_else(|e| panic!("{arch}: freeze: {e}"));

        assert!(outcome.initial_write_verified, "{arch}");
        assert_eq!(outcome.original_raw, "64000000", "{arch}");
        assert_eq!(outcome.frozen_raw, "2b020000", "{arch}");
        assert_eq!(outcome.interval_ms, 10, "{arch}");
        assert_eq!(outcome.lifetime_ms, 3_000, "{arch}");
        assert!(outcome.started_at_unix_us.0 > 0, "{arch}");
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("never recorded in")),
            "{arch}: the result must say freeze writes are not undo entries"
        );

        assert_eq!(h.fixture.send("get"), "value=555", "{arch}");
        assert_eq!(
            h.history.len(),
            0,
            "{arch}: a freeze must not pollute undo history"
        );

        let id = outcome.freeze_id.clone();
        h.unfreeze(&id, false, false).expect("unfreeze");
    }
}

#[test]
fn a_freeze_restores_the_value_after_an_external_write_and_measures_it() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let outcome = h.freeze(777, 10, 5_000).expect("freeze");
        let id = outcome.freeze_id.clone();
        assert_eq!(h.fixture.send("get"), "value=777", "{arch}");

        assert_eq!(h.fixture.send("set 1"), "value=1", "{arch}");
        let recovery = h
            .wait_until_value(777, Duration::from_secs(3))
            .unwrap_or_else(|| panic!("{arch}: the freeze worker must restore the value"));
        assert!(
            recovery < Duration::from_secs(2),
            "{arch}: recovery took {recovery:?}"
        );

        assert_eq!(h.fixture.send("set 2"), "value=2", "{arch}");
        h.wait_until_value(777, Duration::from_secs(3))
            .unwrap_or_else(|| panic!("{arch}: the worker must keep correcting"));

        let frozen = mutate::list_frozen(&mut h.registry);
        let view = frozen
            .iter()
            .find(|v| v.freeze_id == id)
            .unwrap_or_else(|| panic!("{arch}: the freeze must be listed"));
        assert!(view.stats.running, "{arch}");
        assert!(view.stats.ticks.0 > 0, "{arch}");
        assert!(
            view.stats.corrections.0 >= 2,
            "{arch}: both external writes must have been corrected, got {}",
            view.stats.corrections.0
        );
        assert_eq!(view.stats.writes_failed.0, 0, "{arch}");
        assert!(
            view.stats.writes_ok.0 >= 2,
            "{arch}: corrections must be counted as successful writes"
        );
        assert!(
            view.stats.last_tick_latency_us.0 > 0,
            "{arch}: tick latency must be measured, not estimated"
        );
        assert!(
            view.stats.max_tick_latency_us.0 >= view.stats.last_tick_latency_us.0,
            "{arch}"
        );
        assert!(
            view.stats.first_correction_latency_us.is_some(),
            "{arch}: the latency of the first correction must be recorded"
        );

        h.unfreeze(&id, false, false).expect("unfreeze");
        assert_eq!(
            h.history.len(),
            0,
            "{arch}: no correction may appear in undo history"
        );
    }
}

#[test]
fn a_frozen_range_refuses_a_write_and_an_undo_across_it() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();

    let write_handle = h.session.write_handle("write_memory").expect("handle");
    let before = mutate::write_memory(
        &h.session.read_ref(),
        write_handle,
        &WriteRequest {
            address: format!("0x{counter:x}"),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int { value: WireI64(9) },
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        },
        &mut h.history,
        &mut h.journal,
        h.registry.ranges(),
        "write_memory",
    )
    .expect("a write before any freeze");
    let undo_id = before.undo_id.expect("undo id");

    let outcome = h.freeze(321, 20, 3_000).expect("freeze");
    let freeze_id = outcome.freeze_id.clone();

    let session = h.session.read_ref();
    let err = mutate::write_memory(
        &session,
        write_handle,
        &WriteRequest {
            address: format!("0x{counter:x}"),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int { value: WireI64(1) },
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        },
        &mut h.history,
        &mut h.journal,
        h.registry.ranges(),
        "write_memory",
    )
    .expect_err("the range is frozen");
    assert_eq!(err.code, ErrorCode::AddressFrozen);

    let err = mutate::undo_write(
        &session,
        write_handle,
        &UndoRequest {
            undo_id: undo_id.clone(),
            confirm: true,
            override_conflict: true,
        },
        &mut h.history,
        &mut h.journal,
        h.registry.ranges(),
        "undo_write",
    )
    .expect_err("undo across a frozen range is refused");
    assert_eq!(err.code, ErrorCode::AddressFrozen);

    h.unfreeze(&freeze_id, false, false).expect("unfreeze");
    assert!(
        h.registry.ranges().is_empty(),
        "unfreezing must release the range"
    );

    let session = h.session.read_ref();
    mutate::undo_write(
        &session,
        write_handle,
        &UndoRequest {
            undo_id,
            confirm: true,
            override_conflict: true,
        },
        &mut h.history,
        &mut h.journal,
        h.registry.ranges(),
        "undo_write",
    )
    .expect("undo works once the range is released");
}

#[test]
fn a_second_freeze_over_the_same_range_is_refused() {
    let mut h = Harness::start("x64");
    let first = h.freeze(10, 20, 3_000).expect("freeze");
    let err = h
        .freeze(20, 20, 3_000)
        .expect_err("overlapping freezes are serialised, not stacked");
    assert_eq!(err.code, ErrorCode::AddressFrozen);
    h.unfreeze(&first.freeze_id, false, false)
        .expect("unfreeze");
}

#[test]
fn freeze_bounds_are_enforced_and_both_gates_are_required() {
    let mut h = Harness::start("x64");

    for (interval, lifetime) in [
        (0u64, 1_000u64),
        (100_000, 1_000),
        (20, 0),
        (20, 10_000_000),
    ] {
        let err = h
            .freeze(1, interval, lifetime)
            .expect_err("out-of-range freeze arguments must be refused");
        assert_eq!(
            err.code,
            ErrorCode::InvalidArgument,
            "interval={interval} lifetime={lifetime}"
        );
    }

    let session = h.session.read_ref();
    let handle = h.session.write_handle("freeze_value").expect("handle");
    let err = mutate::freeze_value(
        &session,
        handle,
        &FreezeRequest {
            address: format!("0x{:x}", h.fixture.counter_address()),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int { value: WireI64(1) },
            },
            interval_ms: 20,
            lifetime_ms: 1_000,
            confirm: false,
        },
        &mut h.registry,
        Box::new(|| Ok(())),
        "freeze_value",
    )
    .expect_err("a freeze needs confirm=true");
    assert_eq!(err.code, ErrorCode::ConfirmationRequired);
    assert!(h.registry.is_empty());
}

#[test]
fn a_freeze_stops_itself_when_its_lifetime_elapses() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(42, 10, 250).expect("freeze");
    let id = outcome.freeze_id.clone();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let frozen = mutate::list_frozen(&mut h.registry);
        let view = frozen.iter().find(|v| v.freeze_id == id).expect("listed");
        if !view.stats.running {
            assert_eq!(
                view.stats.stop_reason,
                Some(FreezeStopReason::LifetimeElapsed),
                "the stop reason must be retained after the worker ends"
            );
            assert!(view.stats.ticks.0 > 0);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the freeze outlived its lifetime"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(
        h.registry.active_count(),
        0,
        "a worker that reached its lifetime must not still be active"
    );
    assert!(
        h.registry.ranges().is_empty(),
        "a finished worker must release its frozen range"
    );
    assert_eq!(
        h.fixture.send("get"),
        "value=42",
        "stopping does not restore bytes, and the result must not imply it does"
    );
}

#[test]
fn a_freeze_stops_at_the_first_fatal_error_and_keeps_the_reason() {
    let mut h = Harness::start("x64");
    let protect = h.fixture.area("protect");
    let session = h.session.read_ref();
    let handle = h.session.write_handle("freeze_value").expect("handle");

    let outcome = mutate::freeze_value(
        &session,
        handle,
        &FreezeRequest {
            address: format!("0x{protect:x}"),
            payload: WritePayload::Bytes {
                hex: "aabbccdd".to_owned(),
            },
            interval_ms: 10,
            lifetime_ms: 5_000,
            confirm: true,
        },
        &mut h.registry,
        Box::new(|| Ok(())),
        "freeze_value",
    )
    .expect("freeze the protect page");
    let id = outcome.freeze_id.clone();

    assert!(
        h.fixture
            .send("protect noaccess")
            .starts_with("protect=noaccess")
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let reason = loop {
        let frozen = mutate::list_frozen(&mut h.registry);
        let view = frozen.iter().find(|v| v.freeze_id == id).expect("listed");
        if !view.stats.running {
            break view.stats.stop_reason.expect("a stop reason");
        }
        assert!(
            Instant::now() < deadline,
            "the worker must stop on the error"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    assert!(
        reason.is_fatal(),
        "the worker must record a fatal stop reason, got {reason:?}"
    );
    assert_eq!(h.registry.active_count(), 0);
    let frozen = mutate::list_frozen(&mut h.registry);
    let view = frozen.iter().find(|v| v.freeze_id == id).expect("listed");
    assert!(
        view.stats.last_error.is_some(),
        "the error that stopped the worker must be retained"
    );

    assert!(h.fixture.send("protect rw").starts_with("protect=rw"));
}

#[test]
fn unfreeze_with_restore_stops_and_joins_before_restoring() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let outcome = h.freeze(888, 10, 5_000).expect("freeze");
        let id = outcome.freeze_id.clone();
        assert_eq!(h.fixture.send("get"), "value=888", "{arch}");

        let undone = h.unfreeze(&id, true, true).expect("unfreeze with restore");

        assert!(undone.stopped, "{arch}");
        assert!(undone.joined, "{arch}");
        assert_eq!(undone.restore, RestoreOutcome::Restored, "{arch}");
        assert!(undone.restore_verified, "{arch}");
        assert_eq!(undone.restored_raw.as_deref(), Some("64000000"), "{arch}");
        assert_eq!(undone.readback_raw.as_deref(), Some("64000000"), "{arch}");
        assert_eq!(undone.stop_reason, FreezeStopReason::Unfrozen, "{arch}");
        assert!(
            undone
                .notes
                .iter()
                .any(|n| n.contains("stopped and joined before")),
            "{arch}: the order must be stated"
        );

        assert_eq!(
            h.fixture.send("get"),
            "value=100",
            "{arch}: the fixture must confirm the pre-freeze value"
        );
        assert_eq!(h.registry.active_count(), 0, "{arch}");
        assert_eq!(
            h.history.len(),
            0,
            "{arch}: a restore is not an undo entry either"
        );
    }
}

#[test]
fn unfreeze_without_restore_leaves_the_frozen_value_and_says_so() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(999, 10, 5_000).expect("freeze");
    let undone = h
        .unfreeze(&outcome.freeze_id, false, false)
        .expect("unfreeze");

    assert_eq!(undone.restore, RestoreOutcome::NotRequested);
    assert!(!undone.restore_verified);
    assert!(undone.restored_raw.is_none());
    assert!(
        undone
            .notes
            .iter()
            .any(|n| n.contains("does not restore bytes")),
        "the result must state that stopping is not restoring"
    );
    assert_eq!(h.fixture.send("get"), "value=999");
}

#[test]
fn an_unconfirmed_restore_is_skipped_rather_than_performed() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(111, 10, 5_000).expect("freeze");
    let undone = h
        .unfreeze(&outcome.freeze_id, true, false)
        .expect("unfreeze");

    assert!(undone.stopped, "the worker is still stopped");
    assert_eq!(undone.restore, RestoreOutcome::SkippedUnauthorised);
    assert!(!undone.restore_verified);
    assert_eq!(
        h.fixture.send("get"),
        "value=111",
        "an unauthorised restore must not write"
    );
}

#[test]
fn a_revoked_authorisation_never_triggers_a_restore() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(222, 10, 5_000).expect("freeze");
    let id = outcome.freeze_id.clone();
    assert_eq!(h.fixture.send("get"), "value=222");

    std::fs::write(&h.allowlist, "{\"schema\": 1, \"entries\": []}").expect("revoke");

    let undone = h
        .unfreeze_checked(&id, true, true, || {
            Err(OperationError::new(
                ErrorCode::TargetNotAllowed,
                "unfreeze_value",
                "the allowlist entry was removed",
            ))
        })
        .expect("unfreeze still stops the worker");

    assert!(undone.stopped, "the worker must still be stopped");
    assert_eq!(
        undone.restore,
        RestoreOutcome::SkippedAuthorisationRevoked,
        "restoration after revocation must be skipped, not attempted"
    );
    assert!(!undone.restore_verified);
    assert!(undone.restored_raw.is_none());
    assert!(
        undone
            .notes
            .iter()
            .any(|n| n.contains("nothing was written after revocation")),
        "the result must say why restoration was skipped, got {:?}",
        undone.notes
    );
    assert_eq!(
        h.fixture.send("get"),
        "value=222",
        "memory must be left exactly as the freeze had it"
    );
    assert_eq!(h.registry.active_count(), 0);
}

#[test]
fn a_freeze_worker_stops_when_its_per_tick_authorisation_check_fails() {
    let mut h = Harness::start("x64");
    let outcome = h
        .freeze_checked(
            333,
            10,
            5_000,
            Box::new(|| {
                Err(OperationError::new(
                    ErrorCode::TargetNotAllowed,
                    "freeze_value",
                    "revoked before the first tick",
                ))
            }),
        )
        .expect("the initial write succeeds, then the worker checks authorisation");
    let id = outcome.freeze_id.clone();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let frozen = mutate::list_frozen(&mut h.registry);
        let view = frozen.iter().find(|v| v.freeze_id == id).expect("listed");
        if !view.stats.running {
            assert_eq!(
                view.stats.stop_reason,
                Some(FreezeStopReason::AuthorisationRevoked)
            );
            assert!(
                view.stats
                    .last_error
                    .as_deref()
                    .is_some_and(|e| e.contains("revoked")),
                "the revocation reason must be retained"
            );
            break;
        }
        assert!(Instant::now() < deadline, "the worker must stop promptly");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(h.registry.active_count(), 0);
}

#[test]
fn stopping_all_workers_is_deterministic_and_leaves_none_active() {
    let mut h = Harness::start("x64");
    let scratch = h.fixture.area("block") + h.fixture.layout("scratch");
    let session = h.session.read_ref();
    let handle = h.session.write_handle("freeze_value").expect("handle");

    let mut ids = Vec::new();
    for n in 0..4u64 {
        let outcome = mutate::freeze_value(
            &session,
            handle,
            &FreezeRequest {
                address: format!("0x{:x}", scratch + n * 8),
                payload: WritePayload::Bytes {
                    hex: format!("{:02x}{:02x}{:02x}{:02x}", n, n, n, n),
                },
                interval_ms: 10,
                lifetime_ms: 30_000,
                confirm: true,
            },
            &mut h.registry,
            Box::new(|| Ok(())),
            "freeze_value",
        )
        .unwrap_or_else(|e| panic!("freeze {n}: {e}"));
        ids.push(outcome.freeze_id);
    }

    assert_eq!(h.registry.active_count(), 4);
    assert_eq!(h.registry.ranges().len(), 4);

    let stopped = h
        .registry
        .stop_all(FreezeStopReason::ShutdownRequested, "detach_process");
    assert_eq!(stopped.len(), 4, "every worker must be stopped and joined");
    assert_eq!(h.registry.active_count(), 0);
    assert!(
        h.registry.ranges().is_empty(),
        "shutdown must release every frozen range"
    );

    let frozen = mutate::list_frozen(&mut h.registry);
    for id in &ids {
        let view = frozen.iter().find(|v| &v.freeze_id == id).expect("listed");
        assert!(!view.stats.running);
        assert_eq!(
            view.stats.stop_reason,
            Some(FreezeStopReason::ShutdownRequested),
            "the shutdown reason must be retained"
        );
    }

    assert_eq!(
        h.fixture.send("get"),
        "value=100",
        "shutdown must not restore bytes, and must not claim to"
    );
}

#[test]
fn dropping_the_registry_stops_every_worker() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(444, 10, 30_000).expect("freeze");
    assert_eq!(h.registry.active_count(), 1);

    let shared_stats = mutate::list_frozen(&mut h.registry)
        .into_iter()
        .find(|v| v.freeze_id == outcome.freeze_id)
        .expect("listed");
    assert!(shared_stats.stats.running);

    let registry = std::mem::take(&mut h.registry);
    drop(registry);

    assert_eq!(
        h.registry.active_count(),
        0,
        "the replacement registry holds nothing"
    );
    assert_eq!(
        h.fixture.send("ping"),
        "pong",
        "the fixture must still be responsive after worker shutdown"
    );
}

#[test]
fn a_freeze_from_another_session_cannot_be_unfrozen_here() {
    let mut h = Harness::start("x64");
    let outcome = h.freeze(555, 20, 5_000).expect("freeze");

    let mut other = Harness::start("x64");
    let session = other.session.read_ref();
    let handle = other
        .session
        .write_handle("unfreeze_value")
        .expect("handle");
    let err = mutate::unfreeze_value(
        &session,
        handle,
        &UnfreezeRequest {
            freeze_id: outcome.freeze_id.clone(),
            restore_original: true,
            confirm: true,
        },
        &mut h.registry,
        || Ok(()),
        "unfreeze_value",
    )
    .expect_err("the freeze belongs to a different session");
    assert_eq!(err.code, ErrorCode::ProcessReplaced);
    assert_eq!(h.registry.active_count(), 1, "the worker is untouched");
    assert_eq!(other.fixture.send("get"), "value=100");

    h.unfreeze(&outcome.freeze_id, true, true)
        .expect("unfreeze");
}

#[test]
fn unfreezing_an_unknown_id_is_an_argument_error() {
    let mut h = Harness::start("x64");
    let err = h
        .unfreeze("freeze-does-not-exist", false, false)
        .expect_err("unknown id");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}
