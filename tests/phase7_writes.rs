#![allow(clippy::result_large_err)]

mod common;

use std::sync::Once;
use std::time::{Duration, Instant};

use common::{Fixture, allowlist_for};
use memscope::error::ErrorCode;
use memscope::mem::{self, ValueType};
use memscope::mutate::{
    self, FailureJournal, FrozenRanges, MutationStatus, UndoHistory, UndoRequest, WritePayload,
    WriteRequest,
};
use memscope::policy::Policy;
use memscope::scan::Needle;
use memscope::target::Session;
use memscope::wire::{Address, WireI64, WireU64};

static GATE: Once = Once::new();

fn open_the_write_gate() {
    GATE.call_once(|| {
        unsafe { std::env::set_var(memscope::WRITE_ENABLE_VAR, "1") };
    });
    assert!(
        memscope::writes_enabled_in_environment(),
        "this binary must run with the write gate open"
    );
}

struct Harness {
    fixture: Fixture,
    session: Session,
    history: UndoHistory,
    journal: FailureJournal,
    frozen: FrozenRanges,
    _dir: tempfile::TempDir,
    policy: Policy,
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
            .unwrap_or_else(|e| panic!("{arch}: enable_writes: {e}"));
        assert!(session.capabilities().write, "{arch}");
        Self {
            fixture,
            session,
            history: UndoHistory::default(),
            journal: FailureJournal::default(),
            frozen: FrozenRanges::default(),
            _dir: dir,
            policy,
            allowlist,
        }
    }

    fn write(&mut self, request: WriteRequest) -> memscope::error::Result<mutate::WriteOutcome> {
        let session = self.session.read_ref();
        let handle = self.session.write_handle("write_memory").expect("handle");
        mutate::write_memory(
            &session,
            handle,
            &request,
            &mut self.history,
            &mut self.journal,
            &self.frozen,
            "write_memory",
        )
    }

    fn undo(&mut self, request: UndoRequest) -> memscope::error::Result<mutate::UndoOutcome> {
        let session = self.session.read_ref();
        let handle = self.session.write_handle("undo_write").expect("handle");
        mutate::undo_write(
            &session,
            handle,
            &request,
            &mut self.history,
            &mut self.journal,
            &self.frozen,
            "undo_write",
        )
    }

    fn counter_request(&self, value: i64) -> WriteRequest {
        WriteRequest {
            address: format!("0x{:x}", self.fixture.counter_address()),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int {
                    value: WireI64(value),
                },
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        }
    }

    fn block(&self, field: &str) -> u64 {
        self.fixture.area("block") + self.fixture.layout(field)
    }

    fn read_hex(&self, address: u64, len: usize) -> String {
        mem::read_bytes(
            &self.session.read_ref(),
            Address(address),
            len,
            "read_bytes",
        )
        .expect("read")
        .provenance
        .raw
    }

    fn wait_for_external_change(&self, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(line) = self
                .fixture
                .stdout_lines()
                .into_iter()
                .find(|l| l.starts_with("external_change="))
            {
                return Some(line);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

#[test]
fn a_confirmed_write_is_verified_byte_for_byte_and_the_fixture_confirms_it() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let outcome = h
            .write(h.counter_request(31337))
            .unwrap_or_else(|e| panic!("{arch}: write: {e}"));

        assert_eq!(outcome.mutation_status, MutationStatus::Written, "{arch}");
        assert!(outcome.verified, "{arch}");
        assert_eq!(outcome.requested_bytes, 4, "{arch}");
        assert_eq!(outcome.bytes_written, 4, "{arch}");
        assert_eq!(outcome.original_raw, "64000000", "{arch}");
        assert_eq!(outcome.requested_raw, "697a0000", "{arch}");
        assert_eq!(outcome.readback_raw.as_deref(), Some("697a0000"), "{arch}");
        assert!(outcome.verified_at_unix_us.0 > 0, "{arch}");
        assert!(outcome.undo_id.is_some(), "{arch}");
        assert!(outcome.failed_operation_id.is_none(), "{arch}");
        assert!(
            outcome.region.committed && outcome.region.writable,
            "{arch}"
        );
        assert!(outcome.region.covers_whole_range, "{arch}");

        assert_eq!(
            h.fixture.send("get"),
            "value=31337",
            "{arch}: the fixture must report the new value through its own control channel"
        );
        let counter = h.fixture.counter_address();
        assert_eq!(
            h.fixture.send(&format!("read 0x{counter:x} 4")),
            "bytes=697a0000 area=block",
            "{arch}: the fixture must read the same bytes from its own memory"
        );

        let line = h
            .wait_for_external_change(Duration::from_secs(3))
            .unwrap_or_else(|| panic!("{arch}: the fixture watcher must observe the server write"));
        assert!(
            line.contains("->31337"),
            "{arch}: the fixture must report the change it observed, got {line}"
        );
        assert!(
            h.fixture.send("externals").contains("last=31337"),
            "{arch}: the fixture external-change counter must record the new value"
        );

        assert_eq!(h.journal.len(), 0, "{arch}");
        assert_eq!(h.history.len(), 1, "{arch}");
    }
}

#[test]
fn a_write_preserves_the_adjacent_sentinels() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let before_sentinel = h.read_hex(h.block("sentinel_before"), 4);
        let after_sentinel = h.read_hex(h.block("sentinel_after"), 4);
        assert_eq!(before_sentinel, "a5a5a5a5", "{arch}");
        assert_eq!(after_sentinel, "5a5a5a5a", "{arch}");

        h.write(h.counter_request(-1)).expect("write");

        assert_eq!(
            h.read_hex(h.block("sentinel_before"), 4),
            "a5a5a5a5",
            "{arch}: the write must not run backwards into the sentinel"
        );
        assert_eq!(
            h.read_hex(h.block("sentinel_after"), 4),
            "5a5a5a5a",
            "{arch}: the write must not run forwards into the sentinel"
        );
        assert_eq!(h.read_hex(h.block("counter"), 4), "ffffffff", "{arch}");
    }
}

#[test]
fn writing_binary32_one_tenth_verifies_as_cd_cc_cc_3d() {
    let mut h = Harness::start("x64");
    let scratch = h.block("scratch");

    let outcome = h
        .write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Typed {
                value_type: ValueType::Float,
                value: Needle::Float { value: 0.1 },
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect("write 0.1");

    assert!(outcome.verified);
    assert_eq!(outcome.requested_raw, "cdcccc3d");
    assert_eq!(outcome.readback_raw.as_deref(), Some("cdcccc3d"));
    assert_eq!(outcome.original_raw, "cccccccc");
    assert!(
        outcome
            .notes
            .iter()
            .any(|n| n.contains("different decimal rendering")),
        "the result must state that a different decimal rendering is not a failed write"
    );

    let read = mem::read_memory(
        &h.session.read_ref(),
        Address(scratch),
        ValueType::Float,
        None,
        None,
        "read_memory",
    )
    .expect("read back as a float");
    match read.decoded {
        Some(mem::Decoded::Float { value }) => {
            assert_eq!(value.repr, "0.1");
            assert_eq!(value.repr.parse::<f32>().unwrap(), 0.1f32);
        }
        other => panic!("expected a float, got {other:?}"),
    }
}

#[test]
fn a_string_write_only_clears_the_terminator_when_asked() {
    let mut h = Harness::start("x64");
    let scratch = h.block("scratch");

    let bare = h
        .write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Text {
                value_type: ValueType::String,
                text: "ab".to_owned(),
                include_terminator: false,
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect("write without terminator");
    assert!(bare.verified);
    assert_eq!(bare.requested_bytes, 2);
    assert_eq!(
        h.read_hex(scratch, 4),
        "6162cccc",
        "the byte after the text must be untouched, not implicitly cleared"
    );

    let terminated = h
        .write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Text {
                value_type: ValueType::String,
                text: "cd".to_owned(),
                include_terminator: true,
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect("write with terminator");
    assert!(terminated.verified);
    assert_eq!(terminated.requested_bytes, 3);
    assert_eq!(h.read_hex(scratch, 4), "636400cc");
}

#[test]
fn a_wildcard_payload_is_refused_and_nothing_is_written() {
    let mut h = Harness::start("x64");
    let scratch = h.block("scratch");
    let before = h.read_hex(scratch, 4);

    let err = h
        .write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Bytes {
                hex: "cd ?? cc 3d".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect_err("a wildcard cannot be written");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(h.read_hex(scratch, 4), before);
    assert!(h.history.is_empty());
    assert!(h.journal.is_empty());
}

#[test]
fn an_inaccessible_or_unwritable_range_is_refused_without_changing_protection() {
    let mut h = Harness::start("x64");

    let err = h
        .write(WriteRequest {
            address: format!("0x{:x}", h.fixture.area("noaccess")),
            payload: WritePayload::Bytes {
                hex: "01020304".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect_err("a PAGE_NOACCESS page is not writable");
    assert_eq!(err.code, ErrorCode::InvalidAddress);
    let step = err.next_step.expect("a next step");
    assert!(
        step.contains("never changes page protection"),
        "the refusal must state that protection is not forced, got {step}"
    );

    assert!(
        h.fixture
            .send("protect noaccess")
            .starts_with("protect=noaccess")
    );
    let err = h
        .write(WriteRequest {
            address: format!("0x{:x}", h.fixture.area("protect")),
            payload: WritePayload::Bytes {
                hex: "01020304".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect_err("the page was just made inaccessible");
    assert_eq!(err.code, ErrorCode::InvalidAddress);
    assert!(h.fixture.send("protect rw").starts_with("protect=rw"));

    assert!(h.history.is_empty());
}

#[test]
fn an_original_byte_guard_refuses_a_write_when_memory_already_moved_on() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();

    assert_eq!(h.fixture.send("set 555"), "value=555");
    let err = h
        .write(WriteRequest {
            address: format!("0x{counter:x}"),
            payload: WritePayload::Typed {
                value_type: ValueType::Int32,
                value: Needle::Int {
                    value: WireI64(777),
                },
            },
            confirm: true,
            expect_original_raw: Some("64000000".to_owned()),
            attempt_recovery_on_failure: true,
        })
        .expect_err("the original bytes are no longer 100");
    assert_eq!(err.code, ErrorCode::UndoConflict);
    assert_eq!(h.fixture.send("get"), "value=555", "nothing was written");
    assert!(h.history.is_empty());
}

#[test]
fn undo_restores_the_exact_original_bytes_and_the_fixture_sees_it() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let outcome = h.write(h.counter_request(4242)).expect("write");
        let undo_id = outcome.undo_id.clone().expect("undo id");
        assert_eq!(h.fixture.send("get"), "value=4242", "{arch}");

        let undone = h
            .undo(UndoRequest {
                undo_id: undo_id.clone(),
                confirm: true,
                override_conflict: false,
            })
            .unwrap_or_else(|e| panic!("{arch}: undo: {e}"));

        assert!(undone.verified, "{arch}");
        assert_eq!(undone.bytes_written, 4, "{arch}");
        assert_eq!(undone.original_raw, "64000000", "{arch}");
        assert_eq!(undone.bytes_before_undo, "92100000", "{arch}");
        assert_eq!(undone.readback_raw.as_deref(), Some("64000000"), "{arch}");
        assert!(!undone.conflict_overridden, "{arch}");

        assert_eq!(
            h.fixture.send("get"),
            "value=100",
            "{arch}: the fixture must report the restored value"
        );
        assert_eq!(
            h.history.len(),
            0,
            "{arch}: a consumed undo entry is removed"
        );

        let err = h
            .undo(UndoRequest {
                undo_id,
                confirm: true,
                override_conflict: false,
            })
            .expect_err("the entry was consumed");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}

#[test]
fn undo_refuses_a_conflict_unless_it_is_explicitly_overridden() {
    let mut h = Harness::start("x64");
    let outcome = h.write(h.counter_request(1000)).expect("write");
    let undo_id = outcome.undo_id.expect("undo id");

    assert_eq!(h.fixture.send("set 2000"), "value=2000");

    let err = h
        .undo(UndoRequest {
            undo_id: undo_id.clone(),
            confirm: true,
            override_conflict: false,
        })
        .expect_err("something else changed the memory");
    assert_eq!(err.code, ErrorCode::UndoConflict);
    assert_eq!(
        h.fixture.send("get"),
        "value=2000",
        "a refused undo must not write"
    );
    assert_eq!(h.history.len(), 1, "the entry is retained after a conflict");

    let forced = h
        .undo(UndoRequest {
            undo_id,
            confirm: true,
            override_conflict: true,
        })
        .expect("an explicitly overridden undo");
    assert!(forced.verified);
    assert!(forced.conflict_overridden);
    assert_eq!(forced.bytes_before_undo, "d0070000");
    assert_eq!(h.fixture.send("get"), "value=100");
    assert!(
        forced
            .notes
            .iter()
            .any(|n| n.contains("conflict was explicitly overridden")),
        "the override must be stated in the result"
    );
}

#[test]
fn an_undo_entry_from_another_session_is_never_applied() {
    let mut h = Harness::start("x64");
    let outcome = h.write(h.counter_request(123)).expect("write");
    let undo_id = outcome.undo_id.expect("undo id");

    let mut other = Harness::start("x64");
    let err = mutate::undo_write(
        &other.session.read_ref(),
        other.session.write_handle("undo_write").expect("handle"),
        &UndoRequest {
            undo_id: undo_id.clone(),
            confirm: true,
            override_conflict: false,
        },
        &mut h.history,
        &mut h.journal,
        &h.frozen,
        "undo_write",
    )
    .expect_err("the entry belongs to a different session and process");
    assert_eq!(err.code, ErrorCode::ProcessReplaced);
    assert_eq!(h.history.len(), 1, "the entry is retained, not consumed");
    assert_eq!(
        other.fixture.send("get"),
        "value=100",
        "the other fixture must be untouched"
    );
}

#[test]
fn a_frozen_range_refuses_both_a_write_and_an_undo_across_it() {
    let mut h = Harness::start("x64");
    let counter = h.fixture.counter_address();
    let outcome = h.write(h.counter_request(10)).expect("write");
    let undo_id = outcome.undo_id.expect("undo id");

    h.frozen.insert("freeze-1", counter, 4);

    let err = h
        .write(h.counter_request(20))
        .expect_err("the range is frozen");
    assert_eq!(err.code, ErrorCode::AddressFrozen);

    let err = h
        .undo(UndoRequest {
            undo_id: undo_id.clone(),
            confirm: true,
            override_conflict: false,
        })
        .expect_err("undo across a frozen range is refused");
    assert_eq!(err.code, ErrorCode::AddressFrozen);

    assert!(h.frozen.remove("freeze-1"));
    let undone = h
        .undo(UndoRequest {
            undo_id,
            confirm: true,
            override_conflict: false,
        })
        .expect("undo works once the range is unfrozen");
    assert!(undone.verified);
}

#[test]
fn overlapping_mutations_each_capture_the_state_they_actually_found() {
    let mut h = Harness::start("x64");
    let scratch = h.block("scratch");

    let first = h
        .write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Bytes {
                hex: "11111111".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect("first write");
    assert_eq!(first.original_raw, "cccccccc");

    let second = h
        .write(WriteRequest {
            address: format!("0x{:x}", scratch + 2),
            payload: WritePayload::Bytes {
                hex: "2222".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect("overlapping write");
    assert_eq!(
        second.original_raw, "1111",
        "the second write must capture what the first left, not the pre-first state"
    );
    assert_eq!(h.read_hex(scratch, 4), "11112222");

    let second_id = second.undo_id.expect("undo id");
    let first_id = first.undo_id.expect("undo id");

    h.undo(UndoRequest {
        undo_id: second_id,
        confirm: true,
        override_conflict: false,
    })
    .expect("undo the newer write first");
    assert_eq!(h.read_hex(scratch, 4), "11111111");

    h.undo(UndoRequest {
        undo_id: first_id,
        confirm: true,
        override_conflict: false,
    })
    .expect("then undo the older one");
    assert_eq!(
        h.read_hex(scratch, 4),
        "cccccccc",
        "unwinding in reverse order restores the original state exactly"
    );
}

#[test]
fn a_write_after_the_process_exits_fails_and_creates_no_undo_entry() {
    let mut h = Harness::start("x64");
    assert_eq!(h.fixture.send("exit"), "bye");
    assert_eq!(h.fixture.wait_for_exit(Duration::from_secs(5)), Some(0));

    let deadline = Instant::now() + Duration::from_secs(5);
    while h.session.liveness() == memscope::target::Liveness::Alive && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    let err = h
        .write(h.counter_request(1))
        .expect_err("the process is gone");
    assert!(
        matches!(
            err.code,
            ErrorCode::InvalidAddress | ErrorCode::PartialRead | ErrorCode::PartialWrite
        ),
        "got {}",
        err.code
    );
    assert!(h.history.is_empty(), "no undo entry may be created");

    assert_eq!(
        h.session
            .ensure_live("write_memory")
            .expect_err("gone")
            .code,
        ErrorCode::ProcessGone
    );
}

#[test]
fn editing_a_legacy_allowlist_does_not_block_confirmed_writes() {
    let mut h = Harness::start("x64");
    h.write(h.counter_request(7)).expect("first write");
    std::fs::write(&h.allowlist, "invalid legacy JSON").expect("rewrite");
    h.session
        .ensure_identity(&mut h.policy, "write_memory")
        .expect("identity remains valid");
    h.write(h.counter_request(8))
        .expect("confirmed write remains available");
    assert_eq!(h.fixture.send("get"), "value=8");
}

#[test]
fn a_write_whose_original_capture_is_incomplete_is_never_attempted() {
    let mut h = Harness::start("x64");
    let protect = h.fixture.area("protect");
    assert!(
        h.fixture
            .send("protect noaccess")
            .starts_with("protect=noaccess")
    );

    let err = h
        .write(WriteRequest {
            address: format!("0x{protect:x}"),
            payload: WritePayload::Bytes {
                hex: "01020304".to_owned(),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .expect_err("the original bytes cannot be captured");
    assert!(
        matches!(err.code, ErrorCode::InvalidAddress | ErrorCode::PartialRead),
        "got {}",
        err.code
    );
    assert!(h.history.is_empty());
    assert!(h.fixture.send("protect rw").starts_with("protect=rw"));
}

#[test]
fn a_pointer_write_uses_the_target_width() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        let scratch = h.block("scratch");
        let expected_width = h.session.arch().pointer_width().bytes();

        let outcome = h
            .write(WriteRequest {
                address: format!("0x{scratch:x}"),
                payload: WritePayload::Typed {
                    value_type: ValueType::Pointer,
                    value: Needle::Uint {
                        value: WireU64(0x1122_3344),
                    },
                },
                confirm: true,
                expect_original_raw: None,
                attempt_recovery_on_failure: true,
            })
            .unwrap_or_else(|e| panic!("{arch}: write: {e}"));

        assert!(outcome.verified, "{arch}");
        assert_eq!(outcome.requested_bytes, expected_width, "{arch}");
        assert_eq!(
            outcome.requested_raw.len() / 2,
            expected_width,
            "{arch}: a pointer payload is exactly one pointer wide"
        );
    }
}

#[test]
fn undo_history_stays_bounded_under_many_writes() {
    let mut h = Harness::start("x64");
    h.history = UndoHistory::new(4, 1024);
    let scratch = h.block("scratch");

    for n in 0..10u8 {
        h.write(WriteRequest {
            address: format!("0x{scratch:x}"),
            payload: WritePayload::Bytes {
                hex: format!("{n:02x}{n:02x}{n:02x}{n:02x}"),
            },
            confirm: true,
            expect_original_raw: None,
            attempt_recovery_on_failure: true,
        })
        .unwrap_or_else(|e| panic!("write {n}: {e}"));
    }

    assert_eq!(h.history.len(), 4, "the history is capped at four entries");
    assert_eq!(h.history.dropped(), 6, "the evictions are counted");
    let views = h.history.views(Some(h.session.id()));
    assert_eq!(views.len(), 4);
    assert_eq!(
        views.last().expect("newest").written_raw,
        "09090909",
        "the newest write is retained"
    );
}

#[test]
fn a_failed_verification_is_journalled_with_recovery_evidence_and_no_undo_entry() {
    let mut h = Harness::start("x64");

    let mut observed = None;
    for _ in 0..40 {
        assert_eq!(h.fixture.send("churn 200"), "churn=200");
        for _ in 0..200 {
            match h.write(h.counter_request(0)) {
                Ok(outcome) => {
                    assert_eq!(outcome.mutation_status, MutationStatus::Written);
                    h.history.clear_session(h.session.id());
                }
                Err(err) => {
                    observed = Some(err);
                    break;
                }
            }
        }
        if observed.is_some() {
            break;
        }
    }
    assert_eq!(h.fixture.send("churn 0"), "churn=0");

    let err = observed.expect(
        "while the fixture increments the counter in a tight loop, a write must eventually \
         fail its read-back verification; if this never happened the failure path is \
         untested",
    );
    assert_eq!(
        err.code,
        ErrorCode::VerifyFailed,
        "the whole payload was written, so this is a verification failure, not a short write"
    );
    assert_eq!(
        h.history.len(),
        0,
        "a write that failed verification must never produce an undo entry"
    );
    assert_eq!(
        h.journal.len(),
        1,
        "it must be recorded in the failure journal"
    );

    let failure = &h.journal.entries()[0];
    assert_eq!(failure.operation, "write_memory");
    assert_eq!(failure.requested_bytes, 4);
    assert_eq!(failure.bytes_written, 4);
    assert_eq!(failure.requested_raw, "00000000");
    assert_ne!(
        failure.readback_raw.as_deref(),
        Some("00000000"),
        "the read-back must differ, which is why verification failed"
    );
    assert!(failure.memory_may_have_changed);
    assert!(
        failure.recovery_attempted,
        "recovery was requested, so it must have been attempted"
    );
    assert!(
        !failure.recovery_note.is_empty(),
        "the recovery outcome must be stated either way"
    );
    assert!(
        failure.recovery_note.contains("restored")
            || failure.recovery_note.contains("did NOT verify"),
        "the recovery note must say plainly what happened, got {}",
        failure.recovery_note
    );

    let step = err.next_step.expect("a next step");
    assert!(
        step.contains(&failure.id),
        "the error must point at the journal entry holding the recovery evidence, got {step}"
    );
    assert!(
        step.contains("Memory may already have changed"),
        "the error must warn that memory changed, got {step}"
    );
}
