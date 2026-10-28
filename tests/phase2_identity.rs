mod common;

use std::time::Duration;

use common::{Fixture, allowlist_for, fixture_exe, require_fixtures, write_allowlist};
use memscope::error::ErrorCode;
use memscope::policy::{Policy, sha256_file};
use memscope::target::{self, Liveness, ProcessIdentity, Session};
use memscope::wire::{PointerWidth, TargetArch};

fn policy_for(arch: &str, dir: &std::path::Path) -> Policy {
    Policy::load(allowlist_for(dir, arch))
}

#[test]
fn fixtures_are_built() {
    require_fixtures();
}

#[test]
fn a_fixture_attaches_with_metadata_and_a_bound_session_identity() {
    for arch in ["x64", "x86"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut policy = policy_for(arch, dir.path());
        let fixture = Fixture::start(arch);

        let (session, authorisation) =
            Session::attach(fixture.pid(), &mut policy, "attach_process")
                .unwrap_or_else(|e| panic!("{arch}: attach failed: {e}"));

        assert_eq!(session.pid(), fixture.pid(), "{arch}");
        assert!(!session.id().is_empty(), "{arch}: session id");
        assert!(session.id().contains(&fixture.pid().to_string()), "{arch}");

        let expected_arch = if arch == "x64" {
            TargetArch::X64
        } else {
            TargetArch::X86Wow64
        };
        assert_eq!(session.arch(), expected_arch, "{arch}");

        let expected_width = if arch == "x64" {
            PointerWidth::Eight
        } else {
            PointerWidth::Four
        };
        assert_eq!(session.arch().pointer_width(), expected_width, "{arch}");

        let measured = sha256_file(&fixture_exe(arch), "test").expect("hash");
        assert_eq!(session.exe_sha256(), measured, "{arch}");
        assert_eq!(authorisation.measured_sha256, measured, "{arch}");

        let own = target::current_user_sid("test").expect("own sid");
        assert!(session.owner_sid().eq_ignore_ascii_case(&own), "{arch}");

        let caps = session.capabilities();
        assert!(caps.read, "{arch}: a read session must report read");
        assert!(
            !caps.write,
            "{arch}: no write handle is held until authorised"
        );
        assert!(!caps.suspend, "{arch}: suspension is not implemented");

        assert!(
            !session.identity().creation_time.is_empty(),
            "{arch}: creation time must bind the session"
        );
    }
}

#[test]
fn the_fixture_stays_alive_and_responsive_across_five_liveness_checks() {
    for arch in ["x64", "x86"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut policy = policy_for(arch, dir.path());
        let mut fixture = Fixture::start(arch);
        let (session, _) =
            Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");

        for round in 1..=5 {
            assert_eq!(
                session.liveness(),
                Liveness::Alive,
                "{arch}: liveness check {round}"
            );
            session
                .ensure_live("read_memory")
                .unwrap_or_else(|e| panic!("{arch}: ensure_live {round}: {e}"));
        }

        assert_eq!(
            fixture.send("ping"),
            "pong",
            "{arch}: the fixture must still answer its control channel"
        );
        assert_eq!(fixture.send("get"), "value=100", "{arch}");
    }
}

#[test]
fn an_unlisted_fixture_attaches_without_a_policy_entry() {
    for arch in ["x64", "x86"] {
        let mut policy = Policy::default();
        let fixture = Fixture::start(arch);
        let (session, _) = Session::attach(fixture.pid(), &mut policy, "attach_process")
            .expect("no allowlist is required");
        assert_eq!(session.pid(), fixture.pid());
        session
            .ensure_identity(&mut policy, "read_memory")
            .expect("bound identity");
    }
}

#[test]
fn a_legacy_mismatched_pin_does_not_block_attachment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = write_allowlist(dir.path(), &[(fixture_exe("x64"), "0".repeat(64))]);
    let mut policy = Policy::load(allowlist);
    let fixture = Fixture::start("x64");
    let (session, _) = Session::attach(fixture.pid(), &mut policy, "attach_process")
        .expect("legacy pins are not enforced");
    assert_eq!(session.pid(), fixture.pid());
}

#[test]
fn a_missing_pid_is_refused_with_the_os_code_preserved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let err = Session::attach(0xFFFF_FFF0, &mut policy, "attach_process")
        .expect_err("that pid is not running");
    assert!(
        matches!(
            err.code,
            ErrorCode::ProcessGone | ErrorCode::PermissionDenied
        ),
        "got {}",
        err.code
    );
    assert!(err.context.win32_error.is_some());
}

#[test]
fn a_process_that_exits_is_reported_as_gone_not_as_an_address_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let mut fixture = Fixture::start("x64");
    let (session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");
    assert_eq!(session.liveness(), Liveness::Alive);

    assert_eq!(fixture.send("exit"), "bye");
    assert_eq!(
        fixture.wait_for_exit(Duration::from_secs(5)),
        Some(0),
        "the fixture should exit gracefully"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while session.liveness() == Liveness::Alive && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(session.liveness(), Liveness::Exited);

    let err = session
        .ensure_live("read_memory")
        .expect_err("the process is gone");
    assert_eq!(err.code, ErrorCode::ProcessGone);
    assert_eq!(err.context.pid, Some(fixture.pid()));
    assert_eq!(err.context.session_id.as_deref(), Some(session.id()));
}

#[test]
fn editing_a_legacy_allowlist_does_not_invalidate_a_live_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let mut policy = Policy::load(allowlist.clone());
    let fixture = Fixture::start("x64");
    let (session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");
    std::fs::write(&allowlist, "invalid legacy JSON").expect("rewrite");
    session
        .ensure_identity(&mut policy, "read_memory")
        .expect("legacy file is ignored");
    assert_eq!(session.liveness(), Liveness::Alive);
}

#[test]
fn deleting_a_legacy_allowlist_does_not_invalidate_a_live_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allowlist = allowlist_for(dir.path(), "x64");
    let mut policy = Policy::load(allowlist.clone());
    let fixture = Fixture::start("x64");
    let (session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");
    std::fs::remove_file(&allowlist).expect("remove legacy policy");
    session
        .ensure_identity(&mut policy, "read_memory")
        .expect("legacy file is ignored");
}

#[test]
fn writes_are_refused_while_the_environment_gate_is_closed() {
    assert!(
        !memscope::writes_enabled_in_environment(),
        "this test requires MEMSCOPE_ALLOW_WRITE to be unset"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let fixture = Fixture::start("x64");
    let (mut session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");

    let err = session
        .enable_writes("write_memory")
        .expect_err("the environment gate is closed");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
    assert!(!session.capabilities().write);

    let err = session
        .write_handle("write_memory")
        .expect_err("no write handle");
    assert_eq!(err.code, ErrorCode::WriteDisabled);
}

#[test]
fn repeated_attach_and_detach_leaks_no_handles() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let fixture = Fixture::start("x64");

    for _ in 0..5 {
        let (session, _) =
            Session::attach(fixture.pid(), &mut policy, "attach_process").expect("warm-up attach");
        drop(session);
    }
    let before = target::own_handle_count().expect("handle count");

    for round in 0..40 {
        let (session, _) = Session::attach(fixture.pid(), &mut policy, "attach_process")
            .unwrap_or_else(|e| panic!("attach {round}: {e}"));
        assert_eq!(session.liveness(), Liveness::Alive);
        drop(session);
    }

    let after = target::own_handle_count().expect("handle count");
    assert!(
        after <= before + 4,
        "40 attach/detach cycles grew the handle count from {before} to {after}"
    );
}

#[test]
fn enumeration_includes_the_fixture_and_the_server_without_selection_restrictions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let fixture = Fixture::start("x64");

    let processes = target::list_processes(&mut policy, "list_processes").expect("enumerate");

    let entry = processes
        .iter()
        .find(|p| p.pid == fixture.pid())
        .expect("the fixture must appear in the enumeration");
    assert!(entry.allowlisted, "the fixture is allowlisted and pinned");
    assert!(entry.owned_by_current_user);
    assert_eq!(entry.arch, Some(TargetArch::X64));
    assert!(entry.exe_path.is_some());
    assert!(entry.creation_time.is_some());

    let me = processes
        .iter()
        .find(|p| p.pid == target::own_pid())
        .expect("the server itself must be listed");
    assert!(me.allowlisted);
    assert!(me.limitation.is_none());
}

#[test]
fn a_simulated_pid_reuse_is_reported_as_replaced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = policy_for("x64", dir.path());
    let fixture = Fixture::start("x64");
    let (session, _) =
        Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");

    let real = session.identity().clone();
    let reused = ProcessIdentity {
        pid: real.pid,
        creation_time: format!("{}", real.creation_time.parse::<u64>().unwrap() + 1),
        exe_canonical: real.exe_canonical.clone(),
    };
    let err = target::compare_identity(&real, &reused, "read_memory")
        .expect_err("SIMULATED: a later creation time on the same PID is a different process");
    assert_eq!(err.code, ErrorCode::ProcessReplaced);
}
