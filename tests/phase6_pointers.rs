#![allow(clippy::result_large_err)]

mod common;

use common::{Fixture, allowlist_for};
use memscope::error::ErrorCode;
use memscope::mem::{self, Decoded, ValueType};
use memscope::policy::Policy;
use memscope::ptr::{
    self, FindReferencesRequest, PointerPathSpec, PointerScanRequest, RescanVerdict,
    StoredPointerPath,
};
use memscope::scan::{Cancel, RegionFilter};
use memscope::target::Session;
use memscope::wire::{Address, PointerWidth, WireU64};

struct Harness {
    fixture: Fixture,
    session: Session,
    modules: Vec<ptr::ModuleInfo>,
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
        let modules = ptr::list_modules(&session.read_ref(), "list_modules").expect("list_modules");
        Self {
            fixture,
            session,
            modules,
            _dir: dir,
            _policy: policy,
        }
    }

    fn chain(&self) -> (String, u64, Vec<i64>, i64, i64) {
        let pc = &self.fixture.meta["pointer_chain"];
        let module = pc["anchor_module"]
            .as_str()
            .expect("anchor_module")
            .to_owned();
        let rva = u64::from_str_radix(
            pc["root_rva"]
                .as_str()
                .expect("root_rva")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex rva");
        let offsets: Vec<i64> = pc["deref_offsets"]
            .as_array()
            .expect("deref_offsets")
            .iter()
            .map(|v| v.as_i64().expect("offset"))
            .collect();
        let final_offset = pc["final_offset"].as_i64().expect("final_offset");
        let leaf_value = pc["leaf_value"].as_i64().expect("leaf_value");
        (module, rva, offsets, final_offset, leaf_value)
    }

    fn path_spec(&self) -> PointerPathSpec {
        let (module, rva, offsets, final_offset, _) = self.chain();
        PointerPathSpec {
            base: format!("{module}+0x{rva:x}"),
            deref_offsets: offsets,
            final_offset,
        }
    }

    fn hex_meta(&self, group: &str, key: &str) -> u64 {
        u64::from_str_radix(
            self.fixture.meta[group][key]
                .as_str()
                .unwrap_or_else(|| panic!("{group}.{key}"))
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex")
    }
}

#[test]
fn resolve_address_handles_absolute_module_base_and_module_relative_forms() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let (module, rva, _, _, _) = h.chain();
        let anchor_base = h.hex_meta("pointer_chain", "anchor_base");
        let root_address = h.hex_meta("pointer_chain", "root_address");
        let session = h.session.read_ref();

        let absolute = ptr::resolve_address(
            &session,
            &h.modules,
            &format!("0x{root_address:x}"),
            "resolve_address",
        )
        .expect("absolute");
        assert_eq!(absolute.form, "absolute", "{arch}");
        assert_eq!(absolute.address_raw.0, root_address, "{arch}");
        assert_eq!(
            absolute.module.as_ref().map(|m| m.name.as_str()),
            Some(module.as_str()),
            "{arch}: an absolute address inside a module must be attributed to it"
        );

        let base = ptr::resolve_address(&session, &h.modules, &module, "resolve_address")
            .expect("module base");
        assert_eq!(base.form, "module_base", "{arch}");
        assert_eq!(base.address_raw.0, anchor_base, "{arch}");

        let relative = ptr::resolve_address(
            &session,
            &h.modules,
            &format!("{module}+0x{rva:x}"),
            "resolve_address",
        )
        .expect("module relative");
        assert_eq!(relative.form, "module_relative", "{arch}");
        assert_eq!(
            relative.address_raw.0, root_address,
            "{arch}: module+rva must land exactly on the anchor root"
        );
        assert_eq!(
            relative.module.as_ref().map(|m| m.spec.clone()),
            Some(format!("{module}+0x{rva:x}")),
            "{arch}"
        );
        assert!(
            relative.stability.contains("not a guarantee"),
            "{arch}: a module-relative address must carry the stability caveat"
        );

        let negative = ptr::resolve_address(
            &session,
            &h.modules,
            &format!("{module}+0x{:x}", rva + 0x10),
            "resolve_address",
        )
        .expect("positive offset");
        let back = ptr::resolve_address(
            &session,
            &h.modules,
            &format!("{}-0x10", negative.module.as_ref().unwrap().spec),
            "resolve_address",
        );
        assert!(
            back.is_err() || back.unwrap().address_raw.0 == root_address,
            "{arch}"
        );
    }
}

#[test]
fn resolve_address_refuses_an_unknown_or_empty_module() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    for bad in [
        "",
        "   ",
        "definitely-not-loaded.dll+0x10",
        "definitely-not-loaded.dll",
    ] {
        let err = ptr::resolve_address(&session, &h.modules, bad, "resolve_address")
            .expect_err("unknown module");
        assert_eq!(err.code, ErrorCode::InvalidArgument, "input {bad:?}");
    }
}

#[test]
fn a_pointer_path_resolves_through_the_fixture_chain_on_both_architectures() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let (_, _, offsets, final_offset, leaf_value) = h.chain();
        let session = h.session.read_ref();

        let resolution =
            ptr::resolve_pointer_path(&session, &h.modules, &h.path_spec(), "resolve_pointer_path")
                .unwrap_or_else(|e| panic!("{arch}: resolve_pointer_path: {e}"));

        assert!(resolution.resolved, "{arch}: {:?}", resolution.failure);
        assert_eq!(resolution.hops.len(), offsets.len(), "{arch}");
        assert!(resolution.final_offset_applied(final_offset), "{arch}");
        assert_eq!(
            resolution.pointer_width,
            h.session.arch().pointer_width().bytes(),
            "{arch}"
        );
        assert!(
            resolution
                .dereference_order
                .contains("added to the current address"),
            "{arch}: the dereference order must be stated"
        );

        let node1 = h.hex_meta("pointer_chain", "node1");
        let node2 = h.hex_meta("pointer_chain", "node2");
        let leaf = h.hex_meta("pointer_chain", "leaf");
        assert_eq!(
            resolution.hops[0].pointer_value_raw.map(|v| v.0),
            Some(node1),
            "{arch}: hop 0 must land on node1"
        );
        assert_eq!(
            resolution.hops[1].pointer_value_raw.map(|v| v.0),
            Some(node2),
            "{arch}: hop 1 must land on node2"
        );
        assert_eq!(
            resolution.hops[2].pointer_value_raw.map(|v| v.0),
            Some(leaf),
            "{arch}: hop 2 must land on the leaf"
        );
        for hop in &resolution.hops {
            assert!(hop.readable, "{arch}: hop {} unreadable", hop.index);
            assert_eq!(
                hop.raw.as_ref().expect("raw").len() / 2,
                h.session.arch().pointer_width().bytes(),
                "{arch}: each hop reads exactly one target-width pointer"
            );
        }

        let value_address = resolution.value_address_raw.expect("value address").0;
        assert_eq!(
            value_address, leaf,
            "{arch}: final_offset is 0 on this chain"
        );

        let read = mem::read_memory(
            &session,
            Address(value_address),
            ValueType::Int32,
            None,
            None,
            "read_memory",
        )
        .expect("read the leaf");
        match read.decoded {
            Some(Decoded::Int { value }) => assert_eq!(value.0, leaf_value, "{arch}"),
            other => panic!("{arch}: expected an int, got {other:?}"),
        }
    }
}

#[test]
fn a_wow64_path_reads_four_byte_pointers_and_an_x64_path_reads_eight() {
    let narrow = Harness::start("x86");
    let wide = Harness::start("x64");

    assert_eq!(narrow.session.arch().pointer_width(), PointerWidth::Four);
    assert_eq!(wide.session.arch().pointer_width(), PointerWidth::Eight);

    for (h, expected) in [(&narrow, 4usize), (&wide, 8usize)] {
        let session = h.session.read_ref();
        let resolution =
            ptr::resolve_pointer_path(&session, &h.modules, &h.path_spec(), "resolve_pointer_path")
                .expect("resolve");
        assert!(resolution.resolved);
        assert_eq!(resolution.pointer_width, expected);
        for hop in &resolution.hops {
            assert_eq!(hop.raw.as_ref().unwrap().len() / 2, expected);
        }
    }

    let session = narrow.session.read_ref();
    let guard_slot = narrow.fixture.area("block") + narrow.fixture.layout("pointer_guard_after");
    let guard = mem::read_memory(
        &session,
        Address(guard_slot),
        ValueType::Uint64,
        None,
        None,
        "read_memory",
    )
    .expect("guard");
    match guard.decoded {
        Some(Decoded::Uint { value }) => assert_eq!(
            value.0, 0xDEAD_BEEF_CAFE_BABE,
            "the bytes after a WOW64 pointer are deliberately non-zero, so a wrong-width read \
             would have produced a visibly wrong pointer"
        ),
        other => panic!("expected a uint, got {other:?}"),
    }

    let slot = narrow.fixture.area("block") + narrow.fixture.layout("pointer_root");
    let as_pointer = mem::read_memory(
        &session,
        Address(slot),
        ValueType::Pointer,
        None,
        None,
        "read_memory",
    )
    .expect("pointer");
    let node1 = narrow.hex_meta("pointer_chain", "node1");
    match as_pointer.decoded {
        Some(Decoded::Pointer { raw_value, .. }) => assert_eq!(raw_value.0, node1),
        other => panic!("expected a pointer, got {other:?}"),
    }
    let as_eight = mem::read_memory(
        &session,
        Address(slot),
        ValueType::Uint64,
        None,
        None,
        "read_memory",
    )
    .expect("eight bytes");
    match as_eight.decoded {
        Some(Decoded::Uint { value }) => assert_ne!(
            value.0, node1,
            "reading eight bytes at a four-byte pointer must give a different, wrong value"
        ),
        other => panic!("expected a uint, got {other:?}"),
    }
}

#[test]
fn an_overlong_path_and_an_overflowing_offset_are_refused() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();

    let err = ptr::resolve_pointer_path(
        &session,
        &h.modules,
        &PointerPathSpec {
            base: h.path_spec().base,
            deref_offsets: vec![0; 64],
            final_offset: 0,
        },
        "resolve_pointer_path",
    )
    .expect_err("too many hops");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = ptr::resolve_pointer_path(
        &session,
        &h.modules,
        &PointerPathSpec {
            base: format!("0x{:x}", u64::MAX - 2),
            deref_offsets: vec![64],
            final_offset: 0,
        },
        "resolve_pointer_path",
    )
    .expect_err("the offset leaves the address space");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn a_broken_hop_is_reported_with_the_hop_that_failed() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    let noaccess = h.fixture.area("noaccess");

    let resolution = ptr::resolve_pointer_path(
        &session,
        &h.modules,
        &PointerPathSpec {
            base: format!("0x{noaccess:x}"),
            deref_offsets: vec![0],
            final_offset: 0,
        },
        "resolve_pointer_path",
    )
    .expect("an unresolvable path still returns an honest record");

    assert!(!resolution.resolved);
    assert_eq!(resolution.failed_at_hop, Some(0));
    assert!(resolution.value_address.is_none());
    assert!(!resolution.hops[0].readable);
    assert!(
        resolution
            .failure
            .expect("a failure reason")
            .contains("could not read")
    );
}

#[test]
fn find_references_locates_the_slot_that_holds_node1() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let session = h.session.read_ref();
        let node1 = h.hex_meta("pointer_chain", "node1");
        let slot = h.fixture.area("block") + h.fixture.layout("pointer_root");
        let block_base = h.fixture.area("block");

        let outcome = ptr::find_references(
            &session,
            &FindReferencesRequest {
                target: format!("0x{node1:x}"),
                filter: RegionFilter {
                    min_address: Some(format!("0x{:x}", block_base & !0xFFFF)),
                    max_address: Some(format!("0x{:x}", block_base + 0x2_0000)),
                    ..Default::default()
                },
                alignment: Some(1),
                max_results: Some(256),
                max_bytes_scanned: Some(16 * 1024 * 1024),
                timeout_ms: Some(10_000),
            },
            &Cancel::new(),
            || Ok(()),
            "find_references",
        )
        .unwrap_or_else(|e| panic!("{arch}: find_references: {e}"));

        assert_eq!(
            outcome.pointer_width,
            h.session.arch().pointer_width().bytes(),
            "{arch}"
        );
        assert!(
            outcome.hits.iter().any(|hit| hit.address_raw.0 == slot),
            "{arch}: the in-block pointer slot must be reported as a reference to node1"
        );
        assert!(
            outcome
                .limitations
                .iter()
                .any(|l| l.contains("No instruction is decoded")),
            "{arch}: the limitation about instruction decoding must be stated"
        );
        assert!(
            outcome
                .limitations
                .iter()
                .any(|l| l.contains("data search only")),
            "{arch}"
        );
    }
}

#[test]
fn a_pointer_scan_finds_a_module_relative_path_to_node1() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    let node1 = h.hex_meta("pointer_chain", "node1");
    let anchor_base = h.hex_meta("pointer_chain", "anchor_base");
    let (module, rva, _, _, _) = h.chain();

    let outcome = ptr::pointer_scan(
        &session,
        &PointerScanRequest {
            target: format!("0x{node1:x}"),
            max_depth: Some(1),
            max_offset: Some(0),
            offset_alignment: Some(8),
            max_results: Some(64),
            max_index_bytes: Some(32 * 1024 * 1024),
            timeout_ms: Some(20_000),
            filter: RegionFilter {
                min_address: Some(format!("0x{anchor_base:x}")),
                max_address: Some(format!("0x{:x}", anchor_base + 0x20_0000)),
                include_images: true,
                ..Default::default()
            },
            require_module_base: true,
        },
        &Cancel::new(),
        || Ok(()),
        "pointer_scan",
    )
    .expect("pointer_scan");

    assert!(outcome.index_entries.0 > 0, "the index must hold entries");
    assert!(outcome.bytes_indexed.0 > 0);
    assert!(outcome.index_values > 0);
    assert!(outcome.index_values as u64 <= outcome.index_entries.0);
    assert_eq!(outcome.budget_bytes.0, 32 * 1024 * 1024);
    assert!(
        outcome.index_bytes.0 >= outcome.index_values as u64 * 33 + outcome.index_entries.0 * 8,
        "the reported index size must cover one bucket per distinct value and one slot per          holder: {} bytes for {} values and {} holders",
        outcome.index_bytes.0,
        outcome.index_values,
        outcome.index_entries.0
    );
    assert!(outcome.peak_bytes.0 >= outcome.index_bytes.0 + outcome.search_bytes.0.min(1));
    assert!(
        outcome.peak_bytes.0 <= outcome.budget_bytes.0,
        "the index and the search frontier together must stay inside the budget"
    );
    assert!(outcome.budget_note.contains("max_index_bytes"));
    assert!(
        outcome.coverage_note.contains("eligible regions"),
        "coverage must be reported"
    );
    assert!(
        outcome.dereference_order.contains("deref_offsets"),
        "the dereference order must be stated"
    );
    assert!(outcome.stability.contains("not a guarantee"));

    let expected = format!("{module}+0x{rva:x}");
    let found = outcome
        .paths
        .iter()
        .find(|p| p.base.eq_ignore_ascii_case(&expected))
        .unwrap_or_else(|| {
            panic!(
                "the anchor root must be found as a module-relative base; got {:?}",
                outcome
                    .paths
                    .iter()
                    .map(|p| p.base.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert!(found.base_is_module_relative);
    assert_eq!(found.deref_offsets, vec![0]);
    assert_eq!(found.depth, 1);
    assert!(
        found.verified,
        "a reported path must be re-resolved and verified to reach the target"
    );
}

#[test]
fn pointer_scan_bounds_are_enforced() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    let node1 = h.hex_meta("pointer_chain", "node1");
    let base = PointerScanRequest {
        target: format!("0x{node1:x}"),
        max_depth: Some(1),
        max_offset: Some(0),
        offset_alignment: Some(8),
        max_results: Some(4),
        max_index_bytes: Some(1024 * 1024),
        timeout_ms: Some(5_000),
        filter: RegionFilter::default(),
        require_module_base: true,
    };

    for bad in [
        PointerScanRequest {
            max_depth: Some(0),
            ..base.clone()
        },
        PointerScanRequest {
            max_depth: Some(99),
            ..base.clone()
        },
        PointerScanRequest {
            max_offset: Some(1024 * 1024),
            ..base.clone()
        },
    ] {
        let err = ptr::pointer_scan(&session, &bad, &Cancel::new(), || Ok(()), "pointer_scan")
            .expect_err("out-of-range pointer scan arguments must be refused");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    let cancel = Cancel::new();
    cancel.cancel();
    let cancelled = ptr::pointer_scan(
        &session,
        &PointerScanRequest {
            filter: RegionFilter {
                include_images: true,
                ..Default::default()
            },
            ..base
        },
        &cancel,
        || Ok(()),
        "pointer_scan",
    )
    .expect("a cancelled pointer scan still reports honestly");
    assert!(cancelled.truncated);
    assert!(!cancelled.index_complete);
}

#[test]
fn a_tight_index_budget_truncates_instead_of_overrunning() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    let node1 = h.hex_meta("pointer_chain", "node1");

    for cap in [64 * 1024usize, 256 * 1024, 1024 * 1024] {
        let outcome = ptr::pointer_scan(
            &session,
            &PointerScanRequest {
                target: format!("0x{node1:x}"),
                max_depth: Some(2),
                max_offset: Some(64),
                offset_alignment: Some(8),
                max_results: Some(256),
                max_index_bytes: Some(cap),
                timeout_ms: Some(20_000),
                filter: RegionFilter {
                    include_images: true,
                    ..Default::default()
                },
                require_module_base: false,
            },
            &Cancel::new(),
            || Ok(()),
            "pointer_scan",
        )
        .expect("a budgeted pointer scan");

        assert_eq!(outcome.budget_bytes.0, cap as u64);
        assert!(
            outcome.peak_bytes.0 <= cap as u64,
            "a {cap}-byte budget held {} bytes",
            outcome.peak_bytes.0
        );
        assert_eq!(
            outcome.index_bytes.0 + outcome.search_bytes.0,
            outcome.peak_bytes.0
        );
        if !outcome.index_complete {
            assert!(outcome.truncated, "an incomplete index must be declared");
        }
    }
}

#[test]
fn a_rescan_distinguishes_survived_broken_elsewhere_and_unverified() {
    let h = Harness::start("x64");
    let session = h.session.read_ref();
    let spec = h.path_spec();
    let leaf = h.hex_meta("pointer_chain", "leaf");

    let leaf_bytes = mem::read_bytes(&session, Address(leaf), 4, "read_bytes")
        .expect("read the leaf")
        .provenance
        .raw;

    let stored = vec![
        StoredPointerPath {
            id: "survives".to_owned(),
            session_id: h.session.id().to_owned(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: Some(leaf_bytes.clone()),
            expected_address_raw: None,
        },
        StoredPointerPath {
            id: "elsewhere".to_owned(),
            session_id: h.session.id().to_owned(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: Some("deadbeef".to_owned()),
            expected_address_raw: None,
        },
        StoredPointerPath {
            id: "broken".to_owned(),
            session_id: h.session.id().to_owned(),
            base: format!("0x{:x}", h.fixture.area("noaccess")),
            deref_offsets: vec![0],
            final_offset: 0,
            expected_value_raw: Some(leaf_bytes.clone()),
            expected_address_raw: None,
        },
        StoredPointerPath {
            id: "unverified-no-oracle".to_owned(),
            session_id: h.session.id().to_owned(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: None,
            expected_address_raw: None,
        },
        StoredPointerPath {
            id: "unverified-stale-address".to_owned(),
            session_id: "s-from-a-previous-run".to_owned(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: None,
            expected_address_raw: Some(WireU64(leaf)),
        },
    ];

    let results =
        ptr::rescan_pointer_paths(&session, &stored, 4, "rescan_pointer_paths").expect("rescan");
    let verdict = |id: &str| {
        results
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    };

    assert_eq!(verdict("survives").verdict, RescanVerdict::Survived);
    assert_eq!(
        verdict("elsewhere").verdict,
        RescanVerdict::ResolvedElsewhere
    );
    assert_eq!(verdict("broken").verdict, RescanVerdict::Broken);
    assert_eq!(
        verdict("unverified-no-oracle").verdict,
        RescanVerdict::ResolvedUnverified
    );

    let stale = verdict("unverified-stale-address");
    assert_eq!(stale.verdict, RescanVerdict::ResolvedUnverified);
    assert!(
        stale.reason.contains("not a valid oracle"),
        "an absolute address from another session must be rejected as an oracle, got {}",
        stale.reason
    );

    let same_session_address = ptr::rescan_pointer_paths(
        &session,
        &[StoredPointerPath {
            id: "same-session-address".to_owned(),
            session_id: h.session.id().to_owned(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: None,
            expected_address_raw: Some(WireU64(leaf)),
        }],
        4,
        "rescan_pointer_paths",
    )
    .expect("rescan");
    assert_eq!(same_session_address[0].verdict, RescanVerdict::Survived);
    assert!(same_session_address[0].oracle.contains("same session"));
}

#[test]
fn a_module_relative_path_survives_a_restart_and_is_checked_against_the_new_run() {
    let arch = "x64";
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = Policy::load(allowlist_for(dir.path(), arch));

    let (spec, first_leaf, first_value, first_session_id) = {
        let mut fixture = Fixture::start(arch);
        let (session, _) =
            Session::attach(fixture.pid(), &mut policy, "attach_process").expect("attach");
        let modules = ptr::list_modules(&session.read_ref(), "list_modules").expect("list_modules");

        let pc = &fixture.meta["pointer_chain"];
        let module = pc["anchor_module"].as_str().expect("module").to_owned();
        let rva = u64::from_str_radix(
            pc["root_rva"]
                .as_str()
                .expect("rva")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");
        let offsets: Vec<i64> = pc["deref_offsets"]
            .as_array()
            .expect("offsets")
            .iter()
            .map(|v| v.as_i64().expect("offset"))
            .collect();
        let spec = PointerPathSpec {
            base: format!("{module}+0x{rva:x}"),
            deref_offsets: offsets,
            final_offset: pc["final_offset"].as_i64().expect("final"),
        };

        let resolution =
            ptr::resolve_pointer_path(&session.read_ref(), &modules, &spec, "resolve_pointer_path")
                .expect("resolve");
        assert!(resolution.resolved);
        let leaf = resolution.value_address_raw.expect("value address").0;

        let chain_reply = fixture.send("chain");
        assert!(
            chain_reply.contains(&format!("leaf=0x{leaf:x}")),
            "the fixture must independently agree on the leaf address; got {chain_reply}"
        );

        let value = mem::read_bytes(&session.read_ref(), Address(leaf), 4, "read_bytes")
            .expect("read")
            .provenance
            .raw;
        (spec, leaf, value, session.id().to_owned())
    };

    let mut restarted = Fixture::start(arch);
    let (session, _) =
        Session::attach(restarted.pid(), &mut policy, "attach_process").expect("re-attach");
    let modules = ptr::list_modules(&session.read_ref(), "list_modules").expect("list_modules");
    assert_ne!(
        session.id(),
        first_session_id,
        "a restart must produce a new session"
    );

    let resolution =
        ptr::resolve_pointer_path(&session.read_ref(), &modules, &spec, "resolve_pointer_path")
            .expect("resolve after restart");
    assert!(
        resolution.resolved,
        "the module-relative path must resolve in the new run: {:?}",
        resolution.failure
    );
    let new_leaf = resolution.value_address_raw.expect("value address").0;

    let chain_reply = restarted.send("chain");
    assert!(
        chain_reply.contains(&format!("leaf=0x{new_leaf:x}")),
        "the restarted fixture must independently confirm the resolved address; got {chain_reply}"
    );
    assert!(
        chain_reply.contains("value=1337"),
        "the fixture must independently confirm the leaf value; got {chain_reply}"
    );

    assert_ne!(
        new_leaf, first_leaf,
        "the fixture leaf lives on the managed heap, which is placed afresh in every process,          so a restart must move it; if it did not move, this test would prove nothing about          module-relative stability"
    );

    let new_value = mem::read_bytes(&session.read_ref(), Address(new_leaf), 4, "read_bytes")
        .expect("read")
        .provenance
        .raw;
    assert_eq!(
        new_value, first_value,
        "the independent value oracle must match across the restart"
    );

    let stale_absolute = ptr::rescan_pointer_paths(
        &session.read_ref(),
        &[StoredPointerPath {
            id: "stale-heap-address".to_owned(),
            session_id: first_session_id.clone(),
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: None,
            expected_address_raw: Some(WireU64(first_leaf)),
        }],
        4,
        "rescan_pointer_paths",
    )
    .expect("rescan");
    assert_eq!(
        stale_absolute[0].verdict,
        RescanVerdict::ResolvedUnverified,
        "an absolute address from the previous run is not a valid restart oracle"
    );

    let with_value_oracle = ptr::rescan_pointer_paths(
        &session.read_ref(),
        &[StoredPointerPath {
            id: "value-oracle".to_owned(),
            session_id: first_session_id,
            base: spec.base.clone(),
            deref_offsets: spec.deref_offsets.clone(),
            final_offset: spec.final_offset,
            expected_value_raw: Some(first_value),
            expected_address_raw: None,
        }],
        4,
        "rescan_pointer_paths",
    )
    .expect("rescan");
    assert_eq!(
        with_value_oracle[0].verdict,
        RescanVerdict::Survived,
        "with an independent value oracle the path is validated across the restart"
    );
}

trait FinalOffsetApplied {
    fn final_offset_applied(&self, expected: i64) -> bool;
}

impl FinalOffsetApplied for ptr::PointerPathResolution {
    fn final_offset_applied(&self, expected: i64) -> bool {
        match (self.value_address_raw, self.hops.last()) {
            (Some(value), Some(last)) => {
                let cursor = last.pointer_value_raw.map(|v| v.0).unwrap_or(0);
                value.0 as i128 - cursor as i128 == expected as i128
            }
            _ => false,
        }
    }
}
