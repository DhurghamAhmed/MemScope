mod common;

use common::{Fixture, allowlist_for};
use memscope::error::ErrorCode;
use memscope::mem::{self, BatchItemRequest, ConsistencyMode, Decoded, StructFieldSpec, ValueType};
use memscope::policy::Policy;
use memscope::target::Session;
use memscope::wire::{Address, FloatClass, PointerWidth};

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

    fn block(&self, field: &str) -> Address {
        Address(self.fixture.area("block") + self.fixture.layout(field))
    }

    fn read(&self, address: Address, value_type: ValueType) -> mem::ReadResult {
        mem::read_memory(
            &self.session.read_ref(),
            address,
            value_type,
            None,
            None,
            "read_memory",
        )
        .unwrap_or_else(|e| panic!("read {} as {}: {e}", address, value_type.as_str()))
    }

    fn int(&self, field: &str, value_type: ValueType) -> i64 {
        match self.read(self.block(field), value_type).decoded {
            Some(Decoded::Int { value }) => value.0,
            other => panic!("{field}: expected an int, got {other:?}"),
        }
    }

    fn uint(&self, field: &str, value_type: ValueType) -> u64 {
        match self.read(self.block(field), value_type).decoded {
            Some(Decoded::Uint { value }) => value.0,
            other => panic!("{field}: expected a uint, got {other:?}"),
        }
    }
}

#[test]
fn every_integer_limit_reads_back_exactly_on_both_architectures() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        assert_eq!(
            h.int("i8_min", ValueType::Int8),
            i64::from(i8::MIN),
            "{arch}"
        );
        assert_eq!(
            h.int("i8_max", ValueType::Int8),
            i64::from(i8::MAX),
            "{arch}"
        );
        assert_eq!(h.uint("u8_min", ValueType::Uint8), 0, "{arch}");
        assert_eq!(
            h.uint("u8_max", ValueType::Uint8),
            u64::from(u8::MAX),
            "{arch}"
        );
        assert_eq!(
            h.int("i16_min", ValueType::Int16),
            i64::from(i16::MIN),
            "{arch}"
        );
        assert_eq!(
            h.int("i16_max", ValueType::Int16),
            i64::from(i16::MAX),
            "{arch}"
        );
        assert_eq!(h.uint("u16_min", ValueType::Uint16), 0, "{arch}");
        assert_eq!(
            h.uint("u16_max", ValueType::Uint16),
            u64::from(u16::MAX),
            "{arch}"
        );
        assert_eq!(
            h.int("i32_min", ValueType::Int32),
            i64::from(i32::MIN),
            "{arch}"
        );
        assert_eq!(
            h.int("i32_max", ValueType::Int32),
            i64::from(i32::MAX),
            "{arch}"
        );
        assert_eq!(h.uint("u32_min", ValueType::Uint32), 0, "{arch}");
        assert_eq!(
            h.uint("u32_max", ValueType::Uint32),
            u64::from(u32::MAX),
            "{arch}"
        );
        assert_eq!(h.int("i64_min", ValueType::Int64), i64::MIN, "{arch}");
        assert_eq!(h.int("i64_max", ValueType::Int64), i64::MAX, "{arch}");
        assert_eq!(h.uint("u64_max", ValueType::Uint64), u64::MAX, "{arch}");
    }
}

#[test]
fn a_full_width_sixty_four_bit_value_crosses_the_wire_without_precision_loss() {
    let h = Harness::start("x64");
    let result = h.read(h.block("u64_max"), ValueType::Uint64);
    let json = serde_json::to_value(&result).expect("serialise");
    assert_eq!(json["decoded"]["value"], "18446744073709551615");
    assert_eq!(json["raw"], "ffffffffffffffff");

    let signed = h.read(h.block("i64_min"), ValueType::Int64);
    let json = serde_json::to_value(&signed).expect("serialise");
    assert_eq!(json["decoded"]["value"], "-9223372036854775808");
}

#[test]
fn the_counter_and_its_adjacent_sentinels_read_back_intact() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        assert_eq!(h.int("counter", ValueType::Int32), 100, "{arch}");
        assert_eq!(
            h.uint("sentinel_before", ValueType::Uint32),
            0xA5A5_A5A5,
            "{arch}"
        );
        assert_eq!(
            h.uint("sentinel_after", ValueType::Uint32),
            0x5A5A_5A5A,
            "{arch}"
        );
    }
}

#[test]
fn binary32_one_tenth_reads_as_cd_cc_cc_3d_with_a_round_tripping_repr() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let result = h.read(h.block("f32_tenth"), ValueType::Float);
        assert_eq!(result.provenance.raw, "cdcccc3d", "{arch}");
        match result.decoded {
            Some(Decoded::Float { value }) => {
                assert_eq!(value.class, FloatClass::Finite, "{arch}");
                assert_eq!(value.repr, "0.1", "{arch}");
                assert_eq!(value.repr.parse::<f32>().unwrap(), 0.1f32, "{arch}");
            }
            other => panic!("{arch}: expected a float, got {other:?}"),
        }
    }
}

#[test]
fn non_finite_and_signed_zero_floats_read_back_as_tagged_classes() {
    let h = Harness::start("x64");
    let cases = [
        ("f32_nan", ValueType::Float, FloatClass::Nan),
        ("f32_pos_inf", ValueType::Float, FloatClass::Infinity),
        ("f32_neg_zero", ValueType::Float, FloatClass::Finite),
        (
            "f64_neg_inf",
            ValueType::Double,
            FloatClass::NegativeInfinity,
        ),
        ("f64_nan", ValueType::Double, FloatClass::Nan),
    ];
    for (field, value_type, expected) in cases {
        let result = h.read(h.block(field), value_type);
        match result.decoded {
            Some(Decoded::Float { value }) => {
                assert_eq!(value.class, expected, "{field}");
                if expected == FloatClass::Finite {
                    assert!(value.negative_zero, "{field} must report negative zero");
                } else {
                    assert!(
                        value.value.is_none(),
                        "{field} must carry no JSON number for {expected:?}"
                    );
                }
                let json = serde_json::to_string(&value).expect("serialise");
                serde_json::from_str::<serde_json::Value>(&json)
                    .unwrap_or_else(|e| panic!("{field} produced invalid JSON: {e}"));
            }
            other => panic!("{field}: expected a float, got {other:?}"),
        }
    }

    let double_tenth = h.read(h.block("f64_tenth"), ValueType::Double);
    assert_eq!(double_tenth.provenance.raw, "9a9999999999b93f");
}

#[test]
fn a_pointer_reads_at_the_targets_width_despite_non_zero_neighbours() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let expected_width = if arch == "x64" {
            PointerWidth::Eight
        } else {
            PointerWidth::Four
        };
        assert_eq!(h.session.arch().pointer_width(), expected_width, "{arch}");

        let node1 = u64::from_str_radix(
            h.fixture.meta["pointer_chain"]["node1"]
                .as_str()
                .expect("node1")
                .trim_start_matches("0x"),
            16,
        )
        .expect("hex");

        let result = h.read(h.block("pointer_root"), ValueType::Pointer);
        assert_eq!(
            result.provenance.actual_bytes,
            expected_width.bytes(),
            "{arch}"
        );
        match result.decoded {
            Some(Decoded::Pointer { raw_value, .. }) => {
                assert_eq!(raw_value.0, node1, "{arch}: the pointer must equal node1");
            }
            other => panic!("{arch}: expected a pointer, got {other:?}"),
        }

        let guard = h.read(h.block("pointer_guard_after"), ValueType::Uint64);
        match guard.decoded {
            Some(Decoded::Uint { value }) => assert_eq!(
                value.0, 0xDEAD_BEEF_CAFE_BABE,
                "{arch}: the guard proves the neighbours are non-zero"
            ),
            other => panic!("{arch}: expected a uint, got {other:?}"),
        }
    }
}

#[test]
fn every_string_case_reports_terminator_truncation_and_decoding_honestly() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let base = h.fixture.meta["strings"]["base"]
            .as_str()
            .expect("strings base");
        let base = u64::from_str_radix(base.trim_start_matches("0x"), 16).expect("hex");
        let offset = |name: &str| -> u64 {
            h.fixture.meta["strings"][name]
                .as_u64()
                .unwrap_or_else(|| panic!("strings.{name}"))
        };
        let text = |addr: u64, vt: ValueType, max_bytes: usize, max_chars: Option<usize>| {
            let result = mem::read_memory(
                &h.session.read_ref(),
                Address(addr),
                vt,
                Some(max_bytes),
                max_chars,
                "read_memory",
            )
            .expect("string read");
            match result.decoded {
                Some(Decoded::Text { value }) => value,
                other => panic!("expected text, got {other:?}"),
            }
        };

        let terminated = text(
            base + offset("utf8_terminated"),
            ValueType::String,
            32,
            None,
        );
        assert_eq!(terminated.text.as_deref(), Some("memscope-utf8"), "{arch}");
        assert!(terminated.terminator_found, "{arch}");
        assert_eq!(terminated.bytes_consumed, 14, "{arch}");
        assert!(!terminated.output_truncated, "{arch}");

        let unterminated = text(
            base + offset("utf8_unterminated"),
            ValueType::String,
            13,
            None,
        );
        assert_eq!(
            unterminated.text.as_deref(),
            Some("no-terminator"),
            "{arch}"
        );
        assert!(
            !unterminated.terminator_found,
            "{arch}: a missing terminator must be reported as missing"
        );
        assert!(!unterminated.output_truncated, "{arch}");

        let truncated = text(
            base + offset("utf8_terminated"),
            ValueType::String,
            32,
            Some(4),
        );
        assert!(truncated.terminator_found, "{arch}");
        assert!(
            truncated.output_truncated,
            "{arch}: output truncation is distinct from a missing terminator"
        );
        assert_eq!(truncated.text.as_deref(), Some("mems"), "{arch}");

        let invalid = text(base + offset("utf8_invalid"), ValueType::String, 16, None);
        assert!(invalid.text.is_none(), "{arch}");
        assert!(invalid.decode_error.is_some(), "{arch}");
        assert!(invalid.terminator_found, "{arch}");

        let utf16 = text(
            base + offset("utf16_terminated"),
            ValueType::String16,
            64,
            None,
        );
        assert_eq!(utf16.text.as_deref(), Some("memscope-utf16"), "{arch}");
        assert!(utf16.terminator_found, "{arch}");
        assert_eq!(
            utf16.bytes_consumed, 30,
            "{arch}: the terminator is a whole code unit"
        );

        let utf16_unterminated = text(
            base + offset("utf16_unterminated"),
            ValueType::String16,
            14,
            None,
        );
        assert_eq!(
            utf16_unterminated.text.as_deref(),
            Some("no-term"),
            "{arch}"
        );
        assert!(!utf16_unterminated.terminator_found, "{arch}");

        let surrogate = text(
            base + offset("utf16_lone_surrogate"),
            ValueType::String16,
            16,
            None,
        );
        assert!(surrogate.text.is_none(), "{arch}");
        assert!(surrogate.decode_error.is_some(), "{arch}");
    }
}

#[test]
fn a_read_result_carries_full_provenance() {
    let h = Harness::start("x64");
    let result = h.read(h.block("counter"), ValueType::Int32);
    let p = &result.provenance;

    assert_eq!(p.session_id, h.session.id());
    assert_eq!(p.pid, h.fixture.pid());
    assert_eq!(p.creation_time, h.session.identity().creation_time);
    assert_eq!(
        p.address,
        h.block("counter").to_canonical(PointerWidth::Eight)
    );
    assert_eq!(p.requested_bytes, 4);
    assert_eq!(p.actual_bytes, 4);
    assert!(p.complete);
    assert_eq!(p.raw, "64000000");
    assert!(p.observed_at_unix_us.0 > 1_700_000_000_000_000);
    assert_eq!(p.consistency, ConsistencyMode::Live);
    assert!(p.win32_error.is_none());

    let json = serde_json::to_value(&result).expect("serialise");
    for key in [
        "session_id",
        "pid",
        "creation_time",
        "address",
        "requested_bytes",
        "actual_bytes",
        "complete",
        "raw",
        "observed_at_unix_us",
        "elapsed_us",
        "consistency",
    ] {
        assert!(json.get(key).is_some(), "provenance is missing {key}");
    }
}

#[test]
fn an_inaccessible_page_is_refused_rather_than_read_as_zeroes() {
    let h = Harness::start("x64");
    let noaccess = h.fixture.area("noaccess");
    let err = mem::read_memory(
        &h.session.read_ref(),
        Address(noaccess),
        ValueType::Int32,
        None,
        None,
        "read_memory",
    )
    .expect_err("a PAGE_NOACCESS page must not read as zeroes");
    assert!(
        matches!(err.code, ErrorCode::PartialRead | ErrorCode::InvalidAddress),
        "got {}",
        err.code
    );
    assert!(
        err.context.win32_error.is_some(),
        "the OS code must survive"
    );

    let guard = h.fixture.area("guard");
    let err = mem::read_memory(
        &h.session.read_ref(),
        Address(guard),
        ValueType::Int32,
        None,
        None,
        "read_memory",
    )
    .expect_err("a PAGE_GUARD page must not read as zeroes");
    assert!(matches!(
        err.code,
        ErrorCode::PartialRead | ErrorCode::InvalidAddress
    ));
}

#[test]
fn a_read_that_runs_off_the_end_of_a_mapping_reports_the_prefix_it_actually_got() {
    let h = Harness::start("x64");
    let protect_base = h.fixture.area("protect");
    let page = 4096usize;

    let result = mem::read_bytes(
        &h.session.read_ref(),
        Address(protect_base),
        page,
        "read_bytes",
    )
    .expect("the committed page itself is readable");
    assert_eq!(result.provenance.actual_bytes, page);
    assert!(result.provenance.complete);

    let over = mem::read_bytes(
        &h.session.read_ref(),
        Address(protect_base),
        page * 4,
        "read_bytes",
    );
    match over {
        Ok(partial) => {
            assert!(
                !partial.provenance.complete,
                "a read past the mapping must not be reported complete"
            );
            assert!(partial.provenance.actual_bytes >= page);
            assert!(partial.provenance.actual_bytes < page * 4);
            assert_eq!(
                partial.provenance.raw.len(),
                partial.provenance.actual_bytes * 2,
                "raw hex must describe exactly the bytes that were read, never zero fill"
            );
            assert!(partial.provenance.win32_error.is_some());
        }
        Err(e) => assert_eq!(e.code, ErrorCode::PartialRead),
    }
}

#[test]
fn a_protection_change_makes_a_previously_readable_page_unreadable() {
    let mut h = Harness::start("x64");
    let protect_base = h.fixture.area("protect");

    let before = mem::read_memory(
        &h.session.read_ref(),
        Address(protect_base),
        ValueType::Uint32,
        None,
        None,
        "read_memory",
    )
    .expect("readable while PAGE_READWRITE");
    assert_eq!(before.provenance.raw, "44332211");

    assert!(
        h.fixture
            .send("protect noaccess")
            .starts_with("protect=noaccess")
    );

    let err = mem::read_memory(
        &h.session.read_ref(),
        Address(protect_base),
        ValueType::Uint32,
        None,
        None,
        "read_memory",
    )
    .expect_err("the page is now PAGE_NOACCESS");
    assert!(matches!(
        err.code,
        ErrorCode::PartialRead | ErrorCode::InvalidAddress
    ));

    assert!(h.fixture.send("protect rw").starts_with("protect=rw"));
    let after = mem::read_memory(
        &h.session.read_ref(),
        Address(protect_base),
        ValueType::Uint32,
        None,
        None,
        "read_memory",
    )
    .expect("readable again");
    assert_eq!(after.provenance.raw, "44332211");
}

#[test]
fn an_unaligned_scalar_read_still_decodes_from_the_bytes_at_that_address() {
    let h = Harness::start("x64");
    let block = h.fixture.area("block");

    let aligned = mem::read_bytes(&h.session.read_ref(), Address(block), 16, "read_bytes")
        .expect("read the first 16 bytes");
    let raw = aligned.provenance.raw;

    let unaligned = mem::read_memory(
        &h.session.read_ref(),
        Address(block + 1),
        ValueType::Uint32,
        None,
        None,
        "read_memory",
    )
    .expect("an unaligned read is permitted and must not be cast unchecked");
    assert_eq!(unaligned.provenance.raw, raw[2..10]);
    match unaligned.decoded {
        Some(Decoded::Uint { value }) => assert_eq!(value.0, 0x64A5_A5A5),
        other => panic!("expected a uint, got {other:?}"),
    }
}

#[test]
fn one_inaccessible_batch_item_does_not_erase_the_successful_ones() {
    let h = Harness::start("x64");
    let items = vec![
        BatchItemRequest {
            address: format!("0x{:x}", h.block("counter").0),
            value_type: ValueType::Int32,
            max_bytes: None,
            max_chars: None,
        },
        BatchItemRequest {
            address: format!("0x{:x}", h.fixture.area("noaccess")),
            value_type: ValueType::Int32,
            max_bytes: None,
            max_chars: None,
        },
        BatchItemRequest {
            address: format!("0x{:x}", h.block("sentinel_before").0),
            value_type: ValueType::Uint32,
            max_bytes: None,
            max_chars: None,
        },
        BatchItemRequest {
            address: "not-hex".to_owned(),
            value_type: ValueType::Int32,
            max_bytes: None,
            max_chars: None,
        },
    ];

    let batch = mem::read_batch(&h.session.read_ref(), &items, "read_batch").expect("batch");
    assert_eq!(batch.summary.requested, 4);
    assert_eq!(batch.summary.succeeded, 2);
    assert_eq!(batch.summary.failed, 2);
    assert!(
        !batch.summary.atomic_snapshot,
        "a batch is never an atomic snapshot"
    );

    assert!(batch.items[0].result.is_some());
    assert!(batch.items[1].error.is_some());
    assert!(batch.items[2].result.is_some());
    assert_eq!(
        batch.items[3].error.as_ref().expect("bad address").code,
        ErrorCode::InvalidArgument
    );

    let first = batch.items[0].result.as_ref().unwrap();
    let third = batch.items[2].result.as_ref().unwrap();
    assert!(
        third.provenance.observed_at_unix_us.0 >= first.provenance.observed_at_unix_us.0,
        "each item keeps its own observation time"
    );
}

#[test]
fn a_struct_read_uses_declared_offsets_and_never_infers_packing() {
    for arch in ["x64", "x86"] {
        let h = Harness::start(arch);
        let fields = vec![
            StructFieldSpec {
                name: "sentinel_before".to_owned(),
                value_type: ValueType::Uint32,
                offset: h.fixture.layout("sentinel_before"),
                max_bytes: None,
                max_chars: None,
            },
            StructFieldSpec {
                name: "counter".to_owned(),
                value_type: ValueType::Int32,
                offset: h.fixture.layout("counter"),
                max_bytes: None,
                max_chars: None,
            },
            StructFieldSpec {
                name: "sentinel_after".to_owned(),
                value_type: ValueType::Uint32,
                offset: h.fixture.layout("sentinel_after"),
                max_bytes: None,
                max_chars: None,
            },
            StructFieldSpec {
                name: "f32_tenth".to_owned(),
                value_type: ValueType::Float,
                offset: h.fixture.layout("f32_tenth"),
                max_bytes: None,
                max_chars: None,
            },
            StructFieldSpec {
                name: "root".to_owned(),
                value_type: ValueType::Pointer,
                offset: h.fixture.layout("pointer_root"),
                max_bytes: None,
                max_chars: None,
            },
        ];

        let result = mem::read_struct(
            &h.session.read_ref(),
            Address(h.fixture.area("block")),
            &fields,
            Some(h.fixture.layout("block_size") as usize),
            "read_struct",
        )
        .unwrap_or_else(|e| panic!("{arch}: read_struct: {e}"));

        assert_eq!(result.fields.len(), 5, "{arch}");
        assert!(result.layout_source.contains("caller-declared"), "{arch}");
        assert_eq!(result.declared_size, 256, "{arch}");

        for field in &result.fields {
            assert!(
                field.error.is_none(),
                "{arch}: {} -> {:?}",
                field.name,
                field.error
            );
        }
        assert_eq!(result.fields[0].raw, "a5a5a5a5", "{arch}");
        assert_eq!(result.fields[1].raw, "64000000", "{arch}");
        assert_eq!(result.fields[2].raw, "5a5a5a5a", "{arch}");
        assert_eq!(result.fields[3].raw, "cdcccc3d", "{arch}");
        assert_eq!(
            result.fields[4].raw.len() / 2,
            h.session.arch().pointer_width().bytes(),
            "{arch}: a pointer field is read at the target width"
        );
    }
}

#[test]
fn a_struct_whose_declared_size_is_too_small_is_refused() {
    let h = Harness::start("x64");
    let fields = vec![StructFieldSpec {
        name: "far".to_owned(),
        value_type: ValueType::Uint64,
        offset: 200,
        max_bytes: None,
        max_chars: None,
    }];
    let err = mem::read_struct(
        &h.session.read_ref(),
        Address(h.fixture.area("block")),
        &fields,
        Some(16),
        "read_struct",
    )
    .expect_err("the field ends past the declared size");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn the_fixture_confirms_what_the_server_read() {
    for arch in ["x64", "x86"] {
        let mut h = Harness::start(arch);
        assert_eq!(h.fixture.send("set 123456"), "value=123456", "{arch}");

        let server = h.read(h.block("counter"), ValueType::Int32);
        match server.decoded {
            Some(Decoded::Int { value }) => assert_eq!(value.0, 123_456, "{arch}"),
            other => panic!("{arch}: expected an int, got {other:?}"),
        }

        let counter_address = h.block("counter").0;
        let reply = h.fixture.send(&format!("read 0x{counter_address:x} 4"));
        assert_eq!(
            reply, "bytes=40e20100 area=block",
            "{arch}: the fixture must independently agree with the server"
        );
        assert_eq!(server.provenance.raw, "40e20100", "{arch}");
    }
}

#[test]
fn reading_a_scalar_of_the_wrong_kind_through_the_string_path_is_an_argument_error() {
    let h = Harness::start("x64");
    let err = mem::read_memory(
        &h.session.read_ref(),
        h.block("counter"),
        ValueType::String,
        None,
        None,
        "read_memory",
    )
    .expect_err("a string read without max_bytes is unbounded");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("max_bytes"), "got {}", err.message);
}

#[test]
fn an_address_outside_the_wow64_address_space_is_refused_by_width() {
    let h = Harness::start("x86");
    let err = mem::read_memory(
        &h.session.read_ref(),
        Address(0x7FF6_0000_12A0),
        ValueType::Int32,
        None,
        None,
        "read_memory",
    )
    .expect_err("a 48-bit address cannot exist in a WOW64 target");
    assert_eq!(err.code, ErrorCode::UnsupportedPointerWidth);
}
