#![allow(clippy::result_large_err)]

mod common;

use common::{Fixture, allowlist_for};
use memscope::error::ErrorCode;
use memscope::mem::ValueType;
use memscope::mutate::{
    self, FailureJournal, FrozenRanges, UndoHistory, UndoRequest, WritePayload, WriteRequest,
};
use memscope::policy::Policy;
use memscope::scan::Needle;
use memscope::target::Session;
use memscope::wire::WireI64;

#[test]
fn this_binary_runs_with_the_write_gate_closed() {
    assert!(
        !memscope::writes_enabled_in_environment(),
        "this test binary deliberately never sets MEMSCOPE_ALLOW_WRITE; the open-gate cases live \
         in tests/phase7_writes.rs"
    );
}

#[test]
fn a_confirmed_write_is_still_refused_while_the_environment_gate_is_closed() {
    let err = mutate::require_write_authorisation(true, "write_memory")
        .expect_err("confirm alone must not authorise a write");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
    let step = err.next_step.expect("a next step");
    assert!(
        step.contains("MEMSCOPE_ALLOW_WRITE=1"),
        "the refusal must name the gate, got {step}"
    );
    assert!(
        step.contains("not changeable at run time"),
        "the refusal must say the gate is start-time only, got {step}"
    );
}

#[test]
fn an_unconfirmed_write_is_refused_too() {
    let err = mutate::require_write_authorisation(false, "write_memory").expect_err("no confirm");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
}

#[test]
fn write_memory_refuses_before_touching_the_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = Policy::load(allowlist_for(dir.path(), "x64"));
    let mut fixture = Fixture::start("x64");
    let (mut session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");

    let err = session
        .enable_writes("write_memory")
        .expect_err("no write handle may be acquired while the gate is closed");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
    assert!(!session.capabilities().write);

    let mut history = UndoHistory::default();
    let mut journal = FailureJournal::default();
    let frozen = FrozenRanges::default();
    let err = mutate::write_memory(
        &session.read_ref(),
        session.handle(),
        &WriteRequest {
            address: format!("0x{:x}", fixture.counter_address()),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int {
                    value: WireI64(999),
                },
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        },
        &mut history,
        &mut journal,
        &frozen,
        "write_memory",
    )
    .expect_err("the gate is closed");
    assert_eq!(err.code, ErrorCode::WriteDisabled);

    assert!(history.is_empty(), "no undo entry may be created");
    assert!(
        journal.is_empty(),
        "nothing was attempted, so nothing failed"
    );

    assert_eq!(
        fixture.send("get"),
        "value=100",
        "the fixture value must be untouched"
    );
    assert!(
        fixture.send("externals").starts_with("external_changes=0"),
        "the fixture must have observed no external change at all"
    );
}

#[test]
fn undo_is_refused_while_the_gate_is_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = Policy::load(allowlist_for(dir.path(), "x64"));
    let fixture = Fixture::start("x64");
    let (session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");

    let mut history = UndoHistory::default();
    let mut journal = FailureJournal::default();
    let frozen = FrozenRanges::default();
    let err = mutate::undo_write(
        &session.read_ref(),
        session.handle(),
        &UndoRequest {
            undo_id: "undo-1".to_owned(),
            confirm: true,
            override_conflict: false,
        },
        &mut history,
        &mut journal,
        &frozen,
        "undo_write",
    )
    .expect_err("restoration is a mutation and needs both gates");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
}
