use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, OperationError, Result};
use crate::mem::{self, ConsistencyMode, SessionRef, ValueType};
use crate::ptr::{self, ModuleInfo};
use crate::scan::{self, RegionFilter, RegionInfo};
use crate::wire::{Address, WireU64, hex};

pub const MIN_WATCH_INTERVAL_MS: u64 = 1;
pub const MAX_WATCH_INTERVAL_MS: u64 = 10_000;
pub const MAX_WATCH_DURATION_MS: u64 = 60_000;
pub const MAX_WATCH_SAMPLES: usize = 10_000;
pub const MAX_DISSECT_BYTES: usize = 64 * 1024;
pub const MIN_DISSECT_STRING_CHARS: usize = 4;

pub fn require_consistency(requested: ConsistencyMode, operation: &str) -> Result<ConsistencyMode> {
    match requested {
        ConsistencyMode::Live => Ok(ConsistencyMode::Live),
        ConsistencyMode::Paused => Err(OperationError::new(
            ErrorCode::ConsistencyUnavailable,
            operation,
            "a natively paused observation is not implemented in this build",
        )
        .with_next_step(
            "This server never suspends target threads. For a deterministic observation, \
             pause the target through its own cooperative protocol and then read; the result \
             will still be reported as consistency=live, which is what it is.",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Candidate,
    BehaviourCorrelated,
    RestartValidated,
}

impl EvidenceLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::BehaviourCorrelated => "behaviour_correlated",
            Self::RestartValidated => "restart_validated",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub level: EvidenceLevel,
    pub address: String,
    pub test_performed: String,
    pub independent_observation: Option<String>,
    pub caveat: String,
}

impl Evidence {
    pub fn candidate(address: impl Into<String>, how_found: impl Into<String>) -> Self {
        Self {
            level: EvidenceLevel::Candidate,
            address: address.into(),
            test_performed: how_found.into(),
            independent_observation: None,
            caveat: "One candidate is not proof of a variable's identity. This address merely \
                     held a matching value when it was observed."
                .to_owned(),
        }
    }

    pub fn behaviour_correlated(
        address: impl Into<String>,
        test_performed: impl Into<String>,
        independent_observation: impl Into<String>,
    ) -> Self {
        Self {
            level: EvidenceLevel::BehaviourCorrelated,
            address: address.into(),
            test_performed: test_performed.into(),
            independent_observation: Some(independent_observation.into()),
            caveat: "The value tracked an independently observed change in the target. That \
                     establishes correlation across the tests performed, not identity."
                .to_owned(),
        }
    }

    pub fn restart_validated(
        address: impl Into<String>,
        test_performed: impl Into<String>,
        independent_observation: impl Into<String>,
    ) -> Self {
        Self {
            level: EvidenceLevel::RestartValidated,
            address: address.into(),
            test_performed: test_performed.into(),
            independent_observation: Some(independent_observation.into()),
            caveat: "The location resolved again after a restart and matched an independent \
                     oracle. Module offsets and pointer paths remain candidates for stability, \
                     not guarantees across binary updates."
                .to_owned(),
        }
    }

    pub fn promote_to_behaviour_correlated(
        self,
        test_performed: impl Into<String>,
        independent_observation: impl Into<String>,
    ) -> Self {
        Self::behaviour_correlated(self.address, test_performed, independent_observation)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WatchRequest {
    pub address: String,
    pub value_type: ValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    pub interval_ms: u64,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_samples: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<ConsistencyMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSample {
    pub index: usize,
    pub observed_at_unix_us: WireU64,
    pub elapsed_us: WireU64,
    pub readable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<mem::Decoded>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchOutcome {
    pub session_id: String,
    pub address: String,
    pub value_type: ValueType,
    pub interval_ms: u64,
    pub duration_ms: u64,
    pub planned_samples: usize,
    pub taken_samples: usize,
    pub failed_samples: usize,
    pub dropped_intervals: usize,
    pub distinct_raw_values: usize,
    pub samples: Vec<WatchSample>,
    pub consistency: ConsistencyMode,
    pub observation_limits: Vec<String>,
}

pub fn watch_value(
    session: &SessionRef,
    request: &WatchRequest,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<WatchOutcome> {
    let consistency = require_consistency(
        request.consistency.unwrap_or(ConsistencyMode::Live),
        operation,
    )?;

    if request.interval_ms < MIN_WATCH_INTERVAL_MS || request.interval_ms > MAX_WATCH_INTERVAL_MS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "interval_ms {} must be between {MIN_WATCH_INTERVAL_MS} and {MAX_WATCH_INTERVAL_MS}",
                request.interval_ms
            ),
        ));
    }
    if request.duration_ms == 0 || request.duration_ms > MAX_WATCH_DURATION_MS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "duration_ms {} must be between 1 and {MAX_WATCH_DURATION_MS}",
                request.duration_ms
            ),
        ));
    }

    let address =
        Address::parse_hex(&request.address, operation)?.check_width(session.width, operation)?;
    let item_size = match request.value_type {
        ValueType::String | ValueType::String16 | ValueType::Bytes => {
            request.max_bytes.ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("watching a {} needs max_bytes", request.value_type.as_str()),
                )
            })?
        }
        other => other
            .size_for(session.width)
            .expect("every remaining type is fixed size"),
    };
    if item_size == 0 || item_size > mem::MAX_STRING_BYTES {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("watch width {item_size} is out of range"),
        ));
    }

    let planned = (request.duration_ms / request.interval_ms).max(1) as usize;
    let cap = request
        .max_samples
        .unwrap_or(MAX_WATCH_SAMPLES)
        .min(MAX_WATCH_SAMPLES);
    if cap == 0 {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "max_samples must be at least 1",
        ));
    }
    let planned = planned.min(cap);

    let interval = Duration::from_millis(request.interval_ms);
    let deadline = Duration::from_millis(request.duration_ms);
    let started = Instant::now();

    let mut samples = Vec::with_capacity(planned);
    let mut failed = 0usize;
    let mut dropped = 0usize;
    let mut distinct: Vec<String> = Vec::new();
    let mut next_due = Duration::ZERO;

    while samples.len() < planned && started.elapsed() < deadline {
        if samples.len().is_multiple_of(64) {
            policy_check()?;
        }
        let now = started.elapsed();
        if now < next_due {
            std::thread::sleep(next_due - now);
        } else if now > next_due + interval {
            let behind = (now - next_due).as_millis() as u64 / request.interval_ms.max(1);
            dropped += behind as usize;
            next_due = now;
        }

        let raw = mem::read_raw(session.handle, address, item_size);
        let readable = raw.bytes.len() == item_size;
        if !readable {
            failed += 1;
        }
        let raw_hex = readable.then(|| hex(&raw.bytes));
        if let Some(text) = &raw_hex
            && !distinct.iter().any(|d| d == text)
        {
            distinct.push(text.clone());
        }
        let decoded = if readable {
            match request.value_type {
                ValueType::String => Some(mem::Decoded::Text {
                    value: mem::decode_utf8(&raw.bytes, None),
                }),
                ValueType::String16 => Some(mem::Decoded::Text {
                    value: mem::decode_utf16le(&raw.bytes, None),
                }),
                ValueType::Bytes => Some(mem::Decoded::Bytes),
                other => mem::decode_scalar(other, &raw.bytes, session.width, operation).ok(),
            }
        } else {
            None
        };

        samples.push(WatchSample {
            index: samples.len(),
            observed_at_unix_us: WireU64(raw.observed_at_unix_us),
            elapsed_us: WireU64(started.elapsed().as_micros() as u64),
            readable,
            raw: raw_hex,
            decoded,
        });
        next_due += interval;
    }

    Ok(WatchOutcome {
        session_id: session.id.clone(),
        address: address.to_canonical(session.width),
        value_type: request.value_type,
        interval_ms: request.interval_ms,
        duration_ms: request.duration_ms,
        planned_samples: planned,
        taken_samples: samples.len(),
        failed_samples: failed,
        dropped_intervals: dropped,
        distinct_raw_values: distinct.len(),
        samples,
        consistency,
        observation_limits: vec![
            "This is bounded polling, not instrumentation. Writes that happen and are \
             overwritten between two samples are not observed and cannot be."
                .to_owned(),
            format!(
                "Each sample is an independent read at its own timestamp; {} samples at {} ms \
                 cover at most {} ms of wall clock, not every intermediate value.",
                planned, request.interval_ms, request.duration_ms
            ),
            "A sample taken while the target was mid-write can show a torn value; nothing here \
             serialises against the target's own writes."
                .to_owned(),
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DissectRequest {
    pub address: String,
    pub length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stride: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency: Option<ConsistencyMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PossibleType {
    pub value_type: ValueType,
    pub basis: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<mem::Decoded>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectSlot {
    pub offset: usize,
    pub address: String,
    pub raw: String,
    pub possible_types: Vec<PossibleType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectString {
    pub offset: usize,
    pub address: String,
    pub encoding: String,
    pub text: String,
    pub byte_length: usize,
    pub terminated: bool,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectPointer {
    pub offset: usize,
    pub address: String,
    pub value: String,
    pub value_raw: WireU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub points_into_module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub points_into_region: Option<String>,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissectOutcome {
    pub session_id: String,
    pub address: String,
    pub requested_bytes: usize,
    pub actual_bytes: usize,
    pub complete: bool,
    pub stride: usize,
    pub analysis_is_heuristic: bool,
    pub heuristic_warning: String,
    pub slots: Vec<DissectSlot>,
    pub strings: Vec<DissectString>,
    pub pointer_candidates: Vec<DissectPointer>,
    pub consistency: ConsistencyMode,
    pub observed_at_unix_us: WireU64,
}

fn looks_like_ascii_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|b| matches!(**b, 0x20..=0x7E | b'\t'))
        .count()
}

fn utf16_run(bytes: &[u8]) -> usize {
    let mut count = 0usize;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        let low = bytes[index];
        let high = bytes[index + 1];
        if high != 0 || !matches!(low, 0x20..=0x7E | b'\t') {
            break;
        }
        count += 1;
        index += 2;
    }
    count
}

pub fn dissect_region(
    session: &SessionRef,
    request: &DissectRequest,
    operation: &str,
) -> Result<DissectOutcome> {
    let consistency = require_consistency(
        request.consistency.unwrap_or(ConsistencyMode::Live),
        operation,
    )?;
    if request.length == 0 || request.length > MAX_DISSECT_BYTES {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "length {} must be between 1 and {MAX_DISSECT_BYTES}",
                request.length
            ),
        ));
    }
    let stride = request.stride.unwrap_or(session.width.bytes());
    if stride == 0 || stride > 64 {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("stride {stride} must be between 1 and 64"),
        ));
    }

    let base =
        Address::parse_hex(&request.address, operation)?.check_width(session.width, operation)?;
    base.checked_add(request.length as u64, operation)?;

    let raw = mem::read_raw(session.handle, base, request.length);
    if raw.bytes.is_empty() {
        let mut err = OperationError::new(
            ErrorCode::InvalidAddress,
            operation,
            format!(
                "nothing was readable at {}",
                base.to_canonical(session.width)
            ),
        )
        .with_session(&session.id)
        .with_address(base.to_canonical(session.width));
        if let Some(code) = raw.win32_error {
            err = err.with_win32(code, crate::win::error_message(code));
        }
        return Err(err);
    }
    let bytes = &raw.bytes;

    let modules: Vec<ModuleInfo> = ptr::list_modules(session, operation).unwrap_or_default();
    let regions: Vec<RegionInfo> = scan::list_regions(
        session,
        &RegionFilter {
            include_images: true,
            ..Default::default()
        },
        operation,
    )
    .unwrap_or_default();

    let mut slots = Vec::new();
    let mut pointer_candidates = Vec::new();
    let pointer_size = session.width.bytes();

    let mut offset = 0usize;
    while offset + stride <= bytes.len() {
        let slot = &bytes[offset..offset + stride];
        let slot_address = Address(base.0 + offset as u64);
        let mut possible = Vec::new();

        if stride >= 4 {
            let as_i32 = i32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
            possible.push(PossibleType {
                value_type: ValueType::Int32,
                basis: format!("first four bytes decode to {as_i32}"),
                confidence: "heuristic".to_owned(),
                decoded: mem::decode_scalar(ValueType::Int32, slot, session.width, operation).ok(),
            });
            let as_f32 = f32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
            if as_f32.is_finite() && as_f32 != 0.0 && as_f32.abs() > 1e-6 && as_f32.abs() < 1e9 {
                possible.push(PossibleType {
                    value_type: ValueType::Float,
                    basis: format!(
                        "first four bytes decode to the plausible finite float {as_f32}"
                    ),
                    confidence: "heuristic".to_owned(),
                    decoded: mem::decode_scalar(ValueType::Float, slot, session.width, operation)
                        .ok(),
                });
            }
        }
        if stride >= 8 {
            let as_f64 = f64::from_le_bytes([
                slot[0], slot[1], slot[2], slot[3], slot[4], slot[5], slot[6], slot[7],
            ]);
            if as_f64.is_finite() && as_f64 != 0.0 && as_f64.abs() > 1e-9 && as_f64.abs() < 1e12 {
                possible.push(PossibleType {
                    value_type: ValueType::Double,
                    basis: format!("eight bytes decode to the plausible finite double {as_f64}"),
                    confidence: "heuristic".to_owned(),
                    decoded: mem::decode_scalar(ValueType::Double, slot, session.width, operation)
                        .ok(),
                });
            }
        }

        if stride >= pointer_size {
            let value = match pointer_size {
                4 => u64::from(u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]])),
                _ => u64::from_le_bytes([
                    slot[0], slot[1], slot[2], slot[3], slot[4], slot[5], slot[6], slot[7],
                ]),
            };
            if value != 0 && value <= session.width.max_address() {
                let module = ptr::module_for(&modules, value).map(|m| m.name.clone());
                let region = regions
                    .iter()
                    .find(|r| r.eligible && value >= r.base_raw.0 && value < r.end_raw.0)
                    .map(|r| format!("{} {}", r.base, r.protection));
                if module.is_some() || region.is_some() {
                    possible.push(PossibleType {
                        value_type: ValueType::Pointer,
                        basis: "the slot value falls inside a committed readable mapping"
                            .to_owned(),
                        confidence: "heuristic".to_owned(),
                        decoded: mem::decode_scalar(
                            ValueType::Pointer,
                            slot,
                            session.width,
                            operation,
                        )
                        .ok(),
                    });
                    pointer_candidates.push(DissectPointer {
                        offset,
                        address: slot_address.to_canonical(session.width),
                        value: Address(value).to_canonical(session.width),
                        value_raw: WireU64(value),
                        points_into_module: module,
                        points_into_region: region,
                        basis: "pointer-like because the value lands inside a committed, \
                                readable mapping of this target; this is a heuristic, not a \
                                proven pointer"
                            .to_owned(),
                    });
                }
            }
        }

        slots.push(DissectSlot {
            offset,
            address: slot_address.to_canonical(session.width),
            raw: hex(slot),
            possible_types: possible,
        });
        offset += stride;
    }

    let mut strings = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let ascii = looks_like_ascii_run(&bytes[index..]);
        if ascii >= MIN_DISSECT_STRING_CHARS {
            let terminated = bytes.get(index + ascii) == Some(&0);
            strings.push(DissectString {
                offset: index,
                address: Address(base.0 + index as u64).to_canonical(session.width),
                encoding: "utf-8/ascii".to_owned(),
                text: String::from_utf8_lossy(&bytes[index..index + ascii]).into_owned(),
                byte_length: ascii,
                terminated,
                basis: format!(
                    "{ascii} consecutive printable bytes, {} a NUL terminator",
                    if terminated {
                        "followed by"
                    } else {
                        "not followed by"
                    }
                ),
            });
            index += ascii + usize::from(terminated);
            continue;
        }
        let units = utf16_run(&bytes[index..]);
        if units >= MIN_DISSECT_STRING_CHARS {
            let byte_length = units * 2;
            let terminated = bytes.get(index + byte_length) == Some(&0)
                && bytes.get(index + byte_length + 1) == Some(&0);
            let text: String = bytes[index..index + byte_length]
                .chunks(2)
                .map(|pair| char::from(pair[0]))
                .collect();
            strings.push(DissectString {
                offset: index,
                address: Address(base.0 + index as u64).to_canonical(session.width),
                encoding: "utf-16le".to_owned(),
                text,
                byte_length,
                terminated,
                basis: format!(
                    "{units} consecutive printable UTF-16LE code units, {} a two-byte terminator",
                    if terminated {
                        "followed by"
                    } else {
                        "not followed by"
                    }
                ),
            });
            index += byte_length + if terminated { 2 } else { 0 };
            continue;
        }
        index += 1;
    }

    Ok(DissectOutcome {
        session_id: session.id.clone(),
        address: base.to_canonical(session.width),
        requested_bytes: request.length,
        actual_bytes: bytes.len(),
        complete: raw.complete(),
        stride,
        analysis_is_heuristic: true,
        heuristic_warning: "Every type, string and pointer below is an inference from byte \
                            patterns alone. No compiler layout, debug information or symbol \
                            table was consulted, and nothing here establishes what the target \
                            actually stores at these addresses."
            .to_owned(),
        slots,
        strings,
        pointer_candidates,
        consistency,
        observed_at_unix_us: WireU64(raw.observed_at_unix_us),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_natively_paused_observation_is_refused_by_name() {
        let err = require_consistency(ConsistencyMode::Paused, "watch_value")
            .expect_err("paused mode is not implemented");
        assert_eq!(err.code, ErrorCode::ConsistencyUnavailable);
        let step = err.next_step.expect("a next step");
        assert!(
            step.contains("cooperative"),
            "the refusal must point at the cooperative alternative, got {step}"
        );
    }

    #[test]
    fn a_live_observation_is_accepted_and_reported_as_live() {
        assert_eq!(
            require_consistency(ConsistencyMode::Live, "watch_value").expect("live"),
            ConsistencyMode::Live
        );
    }

    #[test]
    fn evidence_levels_are_ordered_and_each_carries_the_test_behind_it() {
        assert!(EvidenceLevel::Candidate < EvidenceLevel::BehaviourCorrelated);
        assert!(EvidenceLevel::BehaviourCorrelated < EvidenceLevel::RestartValidated);

        let candidate = Evidence::candidate("0x1000", "matched an exact int32 scan for 100");
        assert_eq!(candidate.level, EvidenceLevel::Candidate);
        assert!(candidate.independent_observation.is_none());
        assert!(candidate.caveat.contains("not proof"));
        assert!(candidate.test_performed.contains("exact int32 scan"));

        let correlated = candidate.promote_to_behaviour_correlated(
            "narrowed with changed after the fixture was set to 777",
            "the fixture reported value=777 on its own control channel",
        );
        assert_eq!(correlated.level, EvidenceLevel::BehaviourCorrelated);
        assert_eq!(correlated.address, "0x1000");
        assert!(correlated.independent_observation.is_some());
        assert!(correlated.caveat.contains("not identity"));

        let restarted = Evidence::restart_validated(
            "0x1000",
            "resolved anchor.dll+0xac000 after a restart",
            "the fixture reported the same leaf value 1337",
        );
        assert_eq!(restarted.level, EvidenceLevel::RestartValidated);
        assert!(restarted.caveat.contains("not guarantees"));
    }

    #[test]
    fn every_evidence_level_has_a_wire_name() {
        for level in [
            EvidenceLevel::Candidate,
            EvidenceLevel::BehaviourCorrelated,
            EvidenceLevel::RestartValidated,
        ] {
            let json = serde_json::to_string(&level).expect("serialise");
            assert_eq!(json, format!("\"{}\"", level.as_str()));
        }
    }

    #[test]
    fn a_printable_run_is_measured_but_stops_at_the_first_non_printable_byte() {
        assert_eq!(looks_like_ascii_run(b"hello\0world"), 5);
        assert_eq!(looks_like_ascii_run(b"\x01abc"), 0);
        assert_eq!(looks_like_ascii_run(b"abc"), 3);
    }

    #[test]
    fn a_utf16_run_counts_code_units_not_bytes() {
        let bytes = [b'a', 0, b'b', 0, b'c', 0, 0, 0];
        assert_eq!(utf16_run(&bytes), 3);
        let not_utf16 = [b'a', b'b', b'c', 0];
        assert_eq!(utf16_run(&not_utf16), 0);
    }
}
