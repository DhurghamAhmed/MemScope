use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};

use crate::error::{ErrorCode, OperationError, Result};
use crate::mem::{self, SessionRef, ValueType};
use crate::scan::Needle;
use crate::win;
use crate::wire::{Address, PointerWidth, WireU64, hex, parse_hex_bytes};

pub const MAX_WRITE_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_UNDO_ENTRIES: usize = 256;
pub const DEFAULT_MAX_UNDO_BYTES: usize = 8 * 1024 * 1024;

pub fn require_write_authorisation(confirm: bool, operation: &str) -> Result<()> {
    if !crate::writes_enabled_in_environment() {
        return Err(OperationError::new(
            ErrorCode::WriteDisabled,
            operation,
            format!(
                "{} is not set to 1, so this server cannot modify memory",
                crate::WRITE_ENABLE_VAR
            ),
        )
        .with_next_step(
            "Restart the server with MEMSCOPE_ALLOW_WRITE=1. This gate is deliberately not \
             changeable at run time.",
        ));
    }
    if !confirm {
        return Err(OperationError::new(
            ErrorCode::ConfirmationRequired,
            operation,
            "this mutation needs confirm=true on the call",
        )
        .with_next_step(
            "Re-issue the call with confirm=true. The environment gate alone never authorises a \
             write.",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WritePayload {
    Typed {
        value_type: ValueType,
        value: Needle,
    },
    Bytes {
        hex: String,
    },
    Text {
        value_type: ValueType,
        text: String,
        #[serde(default)]
        include_terminator: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedPayload {
    pub bytes: Vec<u8>,
    pub value_type: ValueType,
    pub description: String,
    pub includes_terminator: bool,
}

fn out_of_range(operation: &str, value: impl std::fmt::Display, target: &str) -> OperationError {
    OperationError::new(
        ErrorCode::InvalidArgument,
        operation,
        format!("{value} does not fit in {target}"),
    )
    .with_next_step("A value that does not fit is refused; it is never truncated or wrapped.")
}

pub fn encode_payload(
    payload: &WritePayload,
    width: PointerWidth,
    operation: &str,
) -> Result<EncodedPayload> {
    match payload {
        WritePayload::Bytes { hex: text } => {
            if text.contains('?') {
                return Err(OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    "a wildcard byte pattern cannot be a write payload",
                )
                .with_next_step(
                    "A write must state every byte it will put in memory. Use a concrete hex \
                     payload.",
                ));
            }
            let bytes = parse_hex_bytes(text, operation)?;
            Ok(EncodedPayload {
                description: format!("{} raw bytes", bytes.len()),
                value_type: ValueType::Bytes,
                includes_terminator: false,
                bytes,
            })
        }
        WritePayload::Text {
            value_type,
            text,
            include_terminator,
        } => {
            let mut bytes = match value_type {
                ValueType::String => text.as_bytes().to_vec(),
                ValueType::String16 => text
                    .encode_utf16()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect(),
                other => {
                    return Err(OperationError::new(
                        ErrorCode::InvalidArgument,
                        operation,
                        format!("{} is not a text type", other.as_str()),
                    ));
                }
            };
            if *include_terminator {
                match value_type {
                    ValueType::String => bytes.push(0),
                    _ => bytes.extend_from_slice(&[0, 0]),
                }
            }
            Ok(EncodedPayload {
                description: format!(
                    "{} encoded as {}{}",
                    text.len(),
                    value_type.as_str(),
                    if *include_terminator {
                        " with its terminator"
                    } else {
                        " without a terminator"
                    }
                ),
                value_type: *value_type,
                includes_terminator: *include_terminator,
                bytes,
            })
        }
        WritePayload::Typed { value_type, value } => {
            let bytes = match (value_type, value) {
                (ValueType::Int8, Needle::Int { value }) => {
                    vec![
                        i8::try_from(value.0)
                            .map_err(|_| out_of_range(operation, value.0, "int8"))?
                            as u8,
                    ]
                }
                (ValueType::Int16, Needle::Int { value }) => i16::try_from(value.0)
                    .map_err(|_| out_of_range(operation, value.0, "int16"))?
                    .to_le_bytes()
                    .to_vec(),
                (ValueType::Int32, Needle::Int { value }) => i32::try_from(value.0)
                    .map_err(|_| out_of_range(operation, value.0, "int32"))?
                    .to_le_bytes()
                    .to_vec(),
                (ValueType::Int64, Needle::Int { value }) => value.0.to_le_bytes().to_vec(),
                (ValueType::Uint8, Needle::Uint { value }) => {
                    vec![
                        u8::try_from(value.0)
                            .map_err(|_| out_of_range(operation, value.0, "uint8"))?,
                    ]
                }
                (ValueType::Uint16, Needle::Uint { value }) => u16::try_from(value.0)
                    .map_err(|_| out_of_range(operation, value.0, "uint16"))?
                    .to_le_bytes()
                    .to_vec(),
                (ValueType::Uint32, Needle::Uint { value }) => u32::try_from(value.0)
                    .map_err(|_| out_of_range(operation, value.0, "uint32"))?
                    .to_le_bytes()
                    .to_vec(),
                (ValueType::Uint64, Needle::Uint { value }) => value.0.to_le_bytes().to_vec(),
                (ValueType::Float, Needle::Float { value }) => {
                    (*value as f32).to_le_bytes().to_vec()
                }
                (ValueType::Double, Needle::Float { value }) => value.to_le_bytes().to_vec(),
                (ValueType::Pointer, Needle::Uint { value }) => match width {
                    PointerWidth::Four => u32::try_from(value.0)
                        .map_err(|_| out_of_range(operation, value.0, "a 4-byte pointer"))?
                        .to_le_bytes()
                        .to_vec(),
                    PointerWidth::Eight => value.0.to_le_bytes().to_vec(),
                },
                (vt, _) => {
                    return Err(OperationError::new(
                        ErrorCode::InvalidArgument,
                        operation,
                        format!(
                            "the supplied value does not match the declared type {}",
                            vt.as_str()
                        ),
                    )
                    .with_next_step(
                        "Signed types take an int value, unsigned types a uint value, and float \
                         types a float value.",
                    ));
                }
            };
            Ok(EncodedPayload {
                description: format!("one {} value", value_type.as_str()),
                value_type: *value_type,
                includes_terminator: false,
                bytes,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStatus {
    NotAttempted,
    Written,
    PartiallyWritten,
    WrittenButUnverified,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionCheck {
    pub base: String,
    pub size: WireU64,
    pub protection: u32,
    pub committed: bool,
    pub writable: bool,
    pub covers_whole_range: bool,
}

fn query_region(
    handle: HANDLE,
    address: Address,
    len: usize,
) -> Option<(MEMORY_BASIC_INFORMATION, bool)> {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    let written = unsafe {
        VirtualQueryEx(
            handle,
            Some(address.0 as *const core::ffi::c_void),
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return None;
    }
    let base = info.BaseAddress as u64;
    let end = base.saturating_add(info.RegionSize as u64);
    let covers = address.0 >= base && address.0.saturating_add(len as u64) <= end;
    Some((info, covers))
}

fn protection_allows_write(flags: u32) -> bool {
    if flags & PAGE_GUARD.0 != 0 {
        return false;
    }
    matches!(
        PAGE_PROTECTION_FLAGS(flags & 0xFF),
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedOperation {
    pub id: String,
    pub operation: String,
    pub session_id: String,
    pub address: String,
    pub requested_bytes: usize,
    pub bytes_written: usize,
    pub requested_raw: String,
    pub original_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback_raw: Option<String>,
    pub reason: String,
    pub memory_may_have_changed: bool,
    pub recovery_attempted: bool,
    pub recovery_bytes_written: usize,
    pub recovery_verified: bool,
    pub recovery_note: String,
    pub created_at_unix_us: WireU64,
}

#[derive(Debug, Default)]
pub struct FailureJournal {
    entries: Vec<FailedOperation>,
}

impl FailureJournal {
    pub fn record(&mut self, entry: FailedOperation) {
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[FailedOperation] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub id: String,
    pub session_id: String,
    pub pid: u32,
    pub creation_time: String,
    pub address: u64,
    pub original: Vec<u8>,
    pub written: Vec<u8>,
    pub created_at_unix_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoEntryView {
    pub id: String,
    pub session_id: String,
    pub pid: u32,
    pub address: String,
    pub bytes: usize,
    pub original_raw: String,
    pub written_raw: String,
    pub created_at_unix_us: WireU64,
}

#[derive(Debug)]
pub struct UndoHistory {
    entries: VecDeque<UndoEntry>,
    max_entries: usize,
    max_bytes: usize,
    bytes: usize,
    dropped: usize,
}

impl Default for UndoHistory {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_UNDO_ENTRIES, DEFAULT_MAX_UNDO_BYTES)
    }
}

impl UndoHistory {
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            bytes: 0,
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn push(&mut self, entry: UndoEntry) {
        self.bytes += entry.original.len() + entry.written.len();
        self.entries.push_back(entry);
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            match self.entries.pop_front() {
                Some(old) => {
                    self.bytes -= old.original.len() + old.written.len();
                    self.dropped += 1;
                }
                None => break,
            }
        }
    }

    pub fn views(&self, session_id: Option<&str>) -> Vec<UndoEntryView> {
        self.entries
            .iter()
            .filter(|e| session_id.is_none_or(|id| e.session_id == id))
            .map(|e| UndoEntryView {
                id: e.id.clone(),
                session_id: e.session_id.clone(),
                pid: e.pid,
                address: format!("0x{:x}", e.address),
                bytes: e.written.len(),
                original_raw: hex(&e.original),
                written_raw: hex(&e.written),
                created_at_unix_us: WireU64(e.created_at_unix_us),
            })
            .collect()
    }

    fn take(&mut self, id: &str) -> Option<UndoEntry> {
        let index = self.entries.iter().position(|e| e.id == id)?;
        let entry = self.entries.remove(index)?;
        self.bytes -= entry.original.len() + entry.written.len();
        Some(entry)
    }

    fn peek(&self, id: &str) -> Option<&UndoEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn clear_session(&mut self, session_id: &str) -> usize {
        let before = self.entries.len();
        let mut kept = VecDeque::new();
        let mut bytes = 0usize;
        while let Some(entry) = self.entries.pop_front() {
            if entry.session_id == session_id {
                continue;
            }
            bytes += entry.original.len() + entry.written.len();
            kept.push_back(entry);
        }
        self.entries = kept;
        self.bytes = bytes;
        before - self.entries.len()
    }
}

#[derive(Debug, Default)]
pub struct FrozenRanges {
    ranges: Vec<(String, u64, usize)>,
}

impl FrozenRanges {
    pub fn insert(&mut self, id: impl Into<String>, address: u64, len: usize) {
        self.ranges.push((id.into(), address, len));
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.ranges.len();
        self.ranges.retain(|(existing, _, _)| existing != id);
        before != self.ranges.len()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn overlapping(&self, address: u64, len: usize) -> Option<&(String, u64, usize)> {
        let end = address.saturating_add(len as u64);
        self.ranges.iter().find(|(_, start, size)| {
            let other_end = start.saturating_add(*size as u64);
            address < other_end && *start < end
        })
    }

    pub fn check_free(&self, address: u64, len: usize, operation: &str) -> Result<()> {
        match self.overlapping(address, len) {
            None => Ok(()),
            Some((id, start, size)) => Err(OperationError::new(
                ErrorCode::AddressFrozen,
                operation,
                format!(
                    "0x{address:x}..0x{:x} overlaps frozen range {id} at 0x{start:x}..0x{:x}",
                    address.saturating_add(len as u64),
                    start.saturating_add(*size as u64)
                ),
            )
            .with_address(format!("0x{address:x}"))
            .with_next_step("Unfreeze that range first; a frozen range is not written through.")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WriteRequest {
    pub address: String,
    pub payload: WritePayload,
    #[serde(default)]
    pub confirm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_original_raw: Option<String>,
    #[serde(default = "default_true")]
    pub attempt_recovery_on_failure: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOutcome {
    pub session_id: String,
    pub pid: u32,
    pub creation_time: String,
    pub address: String,
    pub address_raw: WireU64,
    pub payload_description: String,
    pub value_type: ValueType,
    pub requested_bytes: usize,
    pub bytes_written: usize,
    pub original_raw: String,
    pub requested_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback_raw: Option<String>,
    pub verified: bool,
    pub verified_at_unix_us: WireU64,
    pub mutation_status: MutationStatus,
    pub region: RegionCheck,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undo_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_operation_id: Option<String>,
    pub notes: Vec<String>,
}

static MUTATION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_id(prefix: &str) -> String {
    format!(
        "{prefix}{}",
        MUTATION_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn write_raw(handle: HANDLE, address: Address, bytes: &[u8]) -> (usize, Option<u32>) {
    let mut written: usize = 0;
    let result = unsafe {
        WriteProcessMemory(
            handle,
            address.0 as *const core::ffi::c_void,
            bytes.as_ptr().cast(),
            bytes.len(),
            Some(&mut written),
        )
    };
    let error = if result.is_err() {
        Some(win::last_error())
    } else {
        None
    };
    (written.min(bytes.len()), error)
}

#[allow(clippy::too_many_arguments)]
pub fn write_memory(
    session: &SessionRef,
    write_handle: HANDLE,
    request: &WriteRequest,
    history: &mut UndoHistory,
    journal: &mut FailureJournal,
    frozen: &FrozenRanges,
    operation: &str,
) -> Result<WriteOutcome> {
    require_write_authorisation(request.confirm, operation)?;

    let encoded = encode_payload(&request.payload, session.width, operation)?;
    if encoded.bytes.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "the encoded payload is empty",
        ));
    }
    if encoded.bytes.len() > MAX_WRITE_BYTES {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "the payload is {} bytes, over the {MAX_WRITE_BYTES}-byte limit",
                encoded.bytes.len()
            ),
        ));
    }

    let address =
        Address::parse_hex(&request.address, operation)?.check_width(session.width, operation)?;
    address.checked_add(encoded.bytes.len() as u64, operation)?;
    frozen.check_free(address.0, encoded.bytes.len(), operation)?;

    let (info, covers) =
        query_region(session.handle, address, encoded.bytes.len()).ok_or_else(|| {
            let code = win::last_error();
            win::win32_failure(
                ErrorCode::InvalidAddress,
                operation,
                format!(
                    "{} is not part of any mapping in this target",
                    address.to_canonical(session.width)
                ),
                code,
            )
            .with_session(&session.id)
            .with_address(address.to_canonical(session.width))
        })?;
    let region = RegionCheck {
        base: Address(info.BaseAddress as u64).to_canonical(session.width),
        size: WireU64(info.RegionSize as u64),
        protection: info.Protect.0,
        committed: info.State == MEM_COMMIT,
        writable: protection_allows_write(info.Protect.0),
        covers_whole_range: covers,
    };
    if !region.committed || !region.writable || !region.covers_whole_range {
        return Err(OperationError::new(
            ErrorCode::InvalidAddress,
            operation,
            format!(
                "the range at {} is not a committed writable mapping (committed={}, writable={}, \
                 covers_range={}, protection=0x{:x})",
                address.to_canonical(session.width),
                region.committed,
                region.writable,
                region.covers_whole_range,
                region.protection
            ),
        )
        .with_session(&session.id)
        .with_address(address.to_canonical(session.width))
        .with_next_step(
            "This server never changes page protection to force a write. Choose a range that is \
             already committed and writable.",
        ));
    }

    let before = mem::read_raw(session.handle, address, encoded.bytes.len());
    if before.bytes.len() != encoded.bytes.len() {
        return Err(OperationError::new(
            ErrorCode::PartialRead,
            operation,
            format!(
                "only {} of {} original bytes could be captured, so the write was not attempted",
                before.bytes.len(),
                encoded.bytes.len()
            ),
        )
        .with_session(&session.id)
        .with_address(address.to_canonical(session.width))
        .with_next_step("A write is never attempted without a complete original-byte capture."));
    }
    let original_raw = hex(&before.bytes);

    if let Some(expected) = &request.expect_original_raw {
        let expected_bytes = parse_hex_bytes(expected, operation)?;
        if expected_bytes != before.bytes {
            return Err(OperationError::new(
                ErrorCode::UndoConflict,
                operation,
                format!(
                    "the current bytes are {original_raw}, not the expected {}",
                    hex(&expected_bytes)
                ),
            )
            .with_session(&session.id)
            .with_address(address.to_canonical(session.width))
            .with_next_step(
                "Re-read the address and retry with the current bytes, or drop the guard.",
            ));
        }
    }

    let requested_raw = hex(&encoded.bytes);
    let (bytes_written, write_error) = write_raw(write_handle, address, &encoded.bytes);
    let after = mem::read_raw(session.handle, address, encoded.bytes.len());
    let readback_raw = (after.bytes.len() == encoded.bytes.len()).then(|| hex(&after.bytes));
    let verified = after.bytes == encoded.bytes;
    let verified_at = after.observed_at_unix_us;

    let complete = bytes_written == encoded.bytes.len() && write_error.is_none();
    let mut notes = Vec::new();

    if complete && verified {
        let undo_id = next_id("undo-");
        history.push(UndoEntry {
            id: undo_id.clone(),
            session_id: session.id.clone(),
            pid: session.pid,
            creation_time: session.creation_time.clone(),
            address: address.0,
            original: before.bytes.clone(),
            written: encoded.bytes.clone(),
            created_at_unix_us: verified_at,
        });
        notes.push(
            "verified=true means the read-back bytes equalled the requested bytes at the stated \
             verification time; the target may change them again at any moment."
                .to_owned(),
        );
        if encoded.value_type == ValueType::Float || encoded.value_type == ValueType::Double {
            notes.push(
                "A float is compared as bytes. A different decimal rendering after decoding is \
                 not a failed write."
                    .to_owned(),
            );
        }
        return Ok(WriteOutcome {
            session_id: session.id.clone(),
            pid: session.pid,
            creation_time: session.creation_time.clone(),
            address: address.to_canonical(session.width),
            address_raw: WireU64(address.0),
            payload_description: encoded.description,
            value_type: encoded.value_type,
            requested_bytes: encoded.bytes.len(),
            bytes_written,
            original_raw,
            requested_raw,
            readback_raw,
            verified: true,
            verified_at_unix_us: WireU64(verified_at),
            mutation_status: MutationStatus::Written,
            region,
            undo_id: Some(undo_id),
            failed_operation_id: None,
            notes,
        });
    }

    let reason = if !complete {
        format!(
            "WriteProcessMemory reported {bytes_written} of {} bytes written",
            encoded.bytes.len()
        )
    } else {
        format!(
            "the read-back bytes {} did not equal the requested {requested_raw}",
            readback_raw
                .clone()
                .unwrap_or_else(|| "<unreadable>".to_owned())
        )
    };

    let mut recovery_attempted = false;
    let mut recovery_bytes = 0usize;
    let mut recovery_verified = false;
    let mut recovery_note = "no recovery was attempted".to_owned();
    if request.attempt_recovery_on_failure && bytes_written > 0 {
        recovery_attempted = true;
        let (restored, _) = write_raw(write_handle, address, &before.bytes);
        recovery_bytes = restored;
        let check = mem::read_raw(session.handle, address, before.bytes.len());
        recovery_verified = check.bytes == before.bytes;
        recovery_note = if recovery_verified {
            format!(
                "the original {} bytes were restored and verified",
                before.bytes.len()
            )
        } else {
            format!(
                "restoration was attempted and wrote {restored} bytes but did NOT verify; memory \
                 is in an unknown state"
            )
        };
    } else if bytes_written > 0 {
        recovery_note =
            "recovery was not requested, and some bytes were already written".to_owned();
    }

    let failed_id = next_id("failed-");
    journal.record(FailedOperation {
        id: failed_id.clone(),
        operation: operation.to_owned(),
        session_id: session.id.clone(),
        address: address.to_canonical(session.width),
        requested_bytes: encoded.bytes.len(),
        bytes_written,
        requested_raw: requested_raw.clone(),
        original_raw: original_raw.clone(),
        readback_raw: readback_raw.clone(),
        reason: reason.clone(),
        memory_may_have_changed: bytes_written > 0,
        recovery_attempted,
        recovery_bytes_written: recovery_bytes,
        recovery_verified,
        recovery_note: recovery_note.clone(),
        created_at_unix_us: WireU64(verified_at),
    });

    notes.push(format!(
        "recorded in the failed-operation journal as {failed_id}"
    ));
    notes.push(
        "No undo entry was created. A short or unverified write is never recorded as a \
         successful mutation."
            .to_owned(),
    );
    if bytes_written > 0 {
        notes.push(
            "Memory may already have changed: some bytes were written before the failure."
                .to_owned(),
        );
    }
    notes.push(recovery_note);

    let status = if !complete && bytes_written > 0 {
        MutationStatus::PartiallyWritten
    } else if !complete {
        MutationStatus::Failed
    } else {
        MutationStatus::WrittenButUnverified
    };

    let mut err = OperationError::new(
        if matches!(
            status,
            MutationStatus::PartiallyWritten | MutationStatus::Failed
        ) {
            ErrorCode::PartialWrite
        } else {
            ErrorCode::VerifyFailed
        },
        operation,
        reason,
    )
    .with_session(&session.id)
    .with_pid(session.pid)
    .with_address(address.to_canonical(session.width))
    .with_next_step(format!(
        "See failed-operation {failed_id} for the recovery evidence. {}",
        if bytes_written > 0 {
            "Memory may already have changed."
        } else {
            "No bytes were written."
        }
    ));
    if let Some(code) = write_error {
        err = err.with_win32(code, win::error_message(code));
    }
    Err(err)
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UndoRequest {
    pub undo_id: String,
    #[serde(default)]
    pub confirm: bool,
    #[serde(default)]
    pub override_conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoOutcome {
    pub undo_id: String,
    pub session_id: String,
    pub address: String,
    pub requested_bytes: usize,
    pub bytes_written: usize,
    pub bytes_before_undo: String,
    pub original_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback_raw: Option<String>,
    pub verified: bool,
    pub verified_at_unix_us: WireU64,
    pub conflict_overridden: bool,
    pub notes: Vec<String>,
}

pub fn undo_write(
    session: &SessionRef,
    write_handle: HANDLE,
    request: &UndoRequest,
    history: &mut UndoHistory,
    journal: &mut FailureJournal,
    frozen: &FrozenRanges,
    operation: &str,
) -> Result<UndoOutcome> {
    require_write_authorisation(request.confirm, operation)?;

    let entry = history.peek(&request.undo_id).ok_or_else(|| {
        OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("no undo entry {} is retained", request.undo_id),
        )
        .with_next_step(
            "Undo history is bounded and session-bound; list it to see what is still available.",
        )
    })?;

    if entry.session_id != session.id
        || entry.pid != session.pid
        || entry.creation_time != session.creation_time
    {
        return Err(OperationError::new(
            ErrorCode::ProcessReplaced,
            operation,
            format!(
                "undo entry {} belongs to session {} (pid {}, created {}), not to session {} \
                 (pid {}, created {})",
                entry.id,
                entry.session_id,
                entry.pid,
                entry.creation_time,
                session.id,
                session.pid,
                session.creation_time
            ),
        )
        .with_session(&session.id)
        .with_next_step(
            "An undo entry is never applied to a different process or a restarted one.",
        ));
    }

    frozen.check_free(entry.address, entry.written.len(), operation)?;

    let address = Address(entry.address);
    let current = mem::read_raw(session.handle, address, entry.written.len());
    if current.bytes.len() != entry.written.len() {
        return Err(OperationError::new(
            ErrorCode::PartialRead,
            operation,
            format!(
                "only {} of {} bytes could be read before undoing, so nothing was restored",
                current.bytes.len(),
                entry.written.len()
            ),
        )
        .with_session(&session.id)
        .with_address(address.to_canonical(session.width)));
    }
    let bytes_before_undo = hex(&current.bytes);

    let conflict = current.bytes != entry.written;
    if conflict && !request.override_conflict {
        return Err(OperationError::new(
            ErrorCode::UndoConflict,
            operation,
            format!(
                "the bytes at {} are now {bytes_before_undo}, not the {} this entry wrote",
                address.to_canonical(session.width),
                hex(&entry.written)
            ),
        )
        .with_session(&session.id)
        .with_address(address.to_canonical(session.width))
        .with_next_step(
            "Something else changed this memory. Re-issue with override_conflict=true only if \
             overwriting the current bytes is intended.",
        ));
    }

    let original = entry.original.clone();
    let written = entry.written.clone();
    let entry_id = entry.id.clone();

    let (bytes_written, write_error) = write_raw(write_handle, address, &original);
    let after = mem::read_raw(session.handle, address, original.len());
    let readback_raw = (after.bytes.len() == original.len()).then(|| hex(&after.bytes));
    let verified = after.bytes == original;

    if bytes_written == original.len() && write_error.is_none() && verified {
        history.take(&entry_id);
        let mut notes =
            vec!["the original bytes were restored and verified byte for byte".to_owned()];
        if conflict {
            notes.push(
                "a conflict was explicitly overridden: the bytes present before this undo were \
                 not the ones the entry wrote"
                    .to_owned(),
            );
        }
        return Ok(UndoOutcome {
            undo_id: entry_id,
            session_id: session.id.clone(),
            address: address.to_canonical(session.width),
            requested_bytes: original.len(),
            bytes_written,
            bytes_before_undo,
            original_raw: hex(&original),
            readback_raw,
            verified: true,
            verified_at_unix_us: WireU64(after.observed_at_unix_us),
            conflict_overridden: conflict,
            notes,
        });
    }

    let reason = format!(
        "restoration wrote {bytes_written} of {} bytes and read back {}",
        original.len(),
        readback_raw
            .clone()
            .unwrap_or_else(|| "<unreadable>".to_owned())
    );
    let failed_id = next_id("failed-");
    journal.record(FailedOperation {
        id: failed_id.clone(),
        operation: operation.to_owned(),
        session_id: session.id.clone(),
        address: address.to_canonical(session.width),
        requested_bytes: original.len(),
        bytes_written,
        requested_raw: hex(&original),
        original_raw: hex(&written),
        readback_raw,
        reason: reason.clone(),
        memory_may_have_changed: bytes_written > 0,
        recovery_attempted: false,
        recovery_bytes_written: 0,
        recovery_verified: false,
        recovery_note: "a failed undo is not retried automatically; the entry is retained so the \
                        operator can decide"
            .to_owned(),
        created_at_unix_us: WireU64(after.observed_at_unix_us),
    });

    let mut err = OperationError::new(
        if bytes_written == original.len() {
            ErrorCode::VerifyFailed
        } else {
            ErrorCode::PartialWrite
        },
        operation,
        reason,
    )
    .with_session(&session.id)
    .with_address(address.to_canonical(session.width))
    .with_next_step(format!(
        "The undo entry is retained and no successful restoration is claimed. See \
         failed-operation {failed_id}."
    ));
    if let Some(code) = write_error {
        err = err.with_win32(code, win::error_message(code));
    }
    Err(err)
}

pub const MIN_FREEZE_INTERVAL_MS: u64 = 5;
pub const MAX_FREEZE_INTERVAL_MS: u64 = 10_000;
pub const MAX_FREEZE_LIFETIME_MS: u64 = 600_000;
pub const MAX_FREEZE_WORKERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeStopReason {
    LifetimeElapsed,
    Unfrozen,
    FatalWriteError,
    FatalVerifyFailed,
    TargetUnreadable,
    AuthorisationRevoked,
    ShutdownRequested,
}

impl FreezeStopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LifetimeElapsed => "lifetime_elapsed",
            Self::Unfrozen => "unfrozen",
            Self::FatalWriteError => "fatal_write_error",
            Self::FatalVerifyFailed => "fatal_verify_failed",
            Self::TargetUnreadable => "target_unreadable",
            Self::AuthorisationRevoked => "authorisation_revoked",
            Self::ShutdownRequested => "shutdown_requested",
        }
    }

    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::FatalWriteError | Self::FatalVerifyFailed | Self::TargetUnreadable
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FreezeStats {
    pub running: bool,
    pub ticks: WireU64,
    pub corrections: WireU64,
    pub writes_ok: WireU64,
    pub writes_failed: WireU64,
    pub last_tick_latency_us: WireU64,
    pub max_tick_latency_us: WireU64,
    pub mean_tick_latency_us: WireU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_correction_latency_us: Option<WireU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<FreezeStopReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
struct FreezeShared {
    stop: AtomicBool,
    requested_reason: Mutex<Option<FreezeStopReason>>,
    stats: Mutex<FreezeStats>,
}

impl FreezeShared {
    fn request_stop(&self, reason: FreezeStopReason) {
        if let Ok(mut slot) = self.requested_reason.lock()
            && slot.is_none()
        {
            *slot = Some(reason);
        }
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct SendOwnedHandle(crate::win::OwnedHandle);

unsafe impl Send for SendOwnedHandle {}

fn duplicate_for_worker(handle: HANDLE, operation: &str) -> Result<crate::win::OwnedHandle> {
    win::duplicate_for_worker(handle, operation, "the freeze worker")
}

pub struct FreezeWorker {
    pub id: String,
    pub session_id: String,
    pub pid: u32,
    pub creation_time: String,
    pub address: u64,
    pub frozen_bytes: Vec<u8>,
    pub original_bytes: Vec<u8>,
    pub value_type: ValueType,
    pub interval_ms: u64,
    pub lifetime_ms: u64,
    pub started_at_unix_us: u64,
    shared: Arc<FreezeShared>,
    thread: Option<JoinHandle<()>>,
    thread_id: ThreadId,
}

impl FreezeWorker {
    pub fn stats(&self) -> FreezeStats {
        self.shared
            .stats
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn is_running(&self) -> bool {
        self.stats().running
    }

    fn request_stop(&self, reason: FreezeStopReason) {
        self.shared.request_stop(reason);
    }

    fn join(&mut self, operation: &str) -> Result<()> {
        if std::thread::current().id() == self.thread_id {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("freeze worker {} cannot join itself", self.id),
            )
            .with_next_step(
                "Stop a freeze from the session thread, never from inside its own worker.",
            ));
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreezeRequest {
    pub address: String,
    pub payload: WritePayload,
    pub interval_ms: u64,
    pub lifetime_ms: u64,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeOutcome {
    pub freeze_id: String,
    pub session_id: String,
    pub address: String,
    pub address_raw: WireU64,
    pub value_type: ValueType,
    pub frozen_raw: String,
    pub original_raw: String,
    pub interval_ms: u64,
    pub lifetime_ms: u64,
    pub started_at_unix_us: WireU64,
    pub initial_write_verified: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenView {
    pub freeze_id: String,
    pub session_id: String,
    pub pid: u32,
    pub address: String,
    pub value_type: ValueType,
    pub frozen_raw: String,
    pub original_raw: String,
    pub interval_ms: u64,
    pub lifetime_ms: u64,
    pub started_at_unix_us: WireU64,
    pub stats: FreezeStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreOutcome {
    NotRequested,
    Restored,
    RestoreFailed,
    SkippedUnauthorised,
    SkippedAuthorisationRevoked,
    SkippedProcessGone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnfreezeOutcome {
    pub freeze_id: String,
    pub session_id: String,
    pub address: String,
    pub stopped: bool,
    pub joined: bool,
    pub stop_reason: FreezeStopReason,
    pub stats: FreezeStats,
    pub restore: RestoreOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restored_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback_raw: Option<String>,
    pub restore_verified: bool,
    pub notes: Vec<String>,
}

pub struct FreezeRegistry {
    workers: Vec<FreezeWorker>,
    ranges: FrozenRanges,
    stopped: Vec<FrozenView>,
    max_workers: usize,
}

impl Default for FreezeRegistry {
    fn default() -> Self {
        Self::new(MAX_FREEZE_WORKERS)
    }
}

impl FreezeRegistry {
    pub fn new(max_workers: usize) -> Self {
        Self {
            workers: Vec::new(),
            ranges: FrozenRanges::default(),
            stopped: Vec::new(),
            max_workers: max_workers.max(1),
        }
    }

    pub fn ranges(&self) -> &FrozenRanges {
        &self.ranges
    }

    pub fn active_count(&self) -> usize {
        self.workers.iter().filter(|w| w.is_running()).count()
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    pub fn views(&self) -> Vec<FrozenView> {
        let mut out: Vec<FrozenView> = self
            .workers
            .iter()
            .map(|w| FrozenView {
                freeze_id: w.id.clone(),
                session_id: w.session_id.clone(),
                pid: w.pid,
                address: format!("0x{:x}", w.address),
                value_type: w.value_type,
                frozen_raw: hex(&w.frozen_bytes),
                original_raw: hex(&w.original_bytes),
                interval_ms: w.interval_ms,
                lifetime_ms: w.lifetime_ms,
                started_at_unix_us: WireU64(w.started_at_unix_us),
                stats: w.stats(),
            })
            .collect();
        out.extend(self.stopped.iter().cloned());
        out
    }

    fn rebuild_ranges(&mut self) {
        self.ranges = FrozenRanges::default();
        for worker in &self.workers {
            self.ranges
                .insert(worker.id.clone(), worker.address, worker.frozen_bytes.len());
        }
    }

    pub fn stop_all(&mut self, reason: FreezeStopReason, operation: &str) -> Vec<String> {
        let mut stopped = Vec::new();
        for worker in &self.workers {
            worker.request_stop(reason);
        }
        let mut remaining = Vec::new();
        for mut worker in self.workers.drain(..) {
            match worker.join(operation) {
                Ok(()) => {
                    stopped.push(worker.id.clone());
                    self.stopped.push(FrozenView {
                        freeze_id: worker.id.clone(),
                        session_id: worker.session_id.clone(),
                        pid: worker.pid,
                        address: format!("0x{:x}", worker.address),
                        value_type: worker.value_type,
                        frozen_raw: hex(&worker.frozen_bytes),
                        original_raw: hex(&worker.original_bytes),
                        interval_ms: worker.interval_ms,
                        lifetime_ms: worker.lifetime_ms,
                        started_at_unix_us: WireU64(worker.started_at_unix_us),
                        stats: worker.stats(),
                    });
                }
                Err(_) => remaining.push(worker),
            }
        }
        self.workers = remaining;
        self.rebuild_ranges();
        stopped
    }

    pub fn reap_finished(&mut self) {
        let finished: Vec<usize> = self
            .workers
            .iter()
            .enumerate()
            .filter(|(_, w)| !w.is_running())
            .map(|(i, _)| i)
            .collect();
        for index in finished.into_iter().rev() {
            let mut worker = self.workers.remove(index);
            if worker.join("reap_finished").is_ok() {
                self.stopped.push(FrozenView {
                    freeze_id: worker.id.clone(),
                    session_id: worker.session_id.clone(),
                    pid: worker.pid,
                    address: format!("0x{:x}", worker.address),
                    value_type: worker.value_type,
                    frozen_raw: hex(&worker.frozen_bytes),
                    original_raw: hex(&worker.original_bytes),
                    interval_ms: worker.interval_ms,
                    lifetime_ms: worker.lifetime_ms,
                    started_at_unix_us: WireU64(worker.started_at_unix_us),
                    stats: worker.stats(),
                });
            } else {
                self.workers.insert(index, worker);
            }
        }
        self.rebuild_ranges();
    }
}

impl Drop for FreezeRegistry {
    fn drop(&mut self) {
        self.stop_all(FreezeStopReason::ShutdownRequested, "shutdown");
    }
}

pub fn freeze_value(
    session: &SessionRef,
    write_handle: HANDLE,
    request: &FreezeRequest,
    registry: &mut FreezeRegistry,
    policy_check: Box<dyn Fn() -> Result<()> + Send>,
    operation: &str,
) -> Result<FreezeOutcome> {
    require_write_authorisation(request.confirm, operation)?;

    if request.interval_ms < MIN_FREEZE_INTERVAL_MS || request.interval_ms > MAX_FREEZE_INTERVAL_MS
    {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "interval_ms {} must be between {MIN_FREEZE_INTERVAL_MS} and \
                 {MAX_FREEZE_INTERVAL_MS}",
                request.interval_ms
            ),
        ));
    }
    if request.lifetime_ms == 0 || request.lifetime_ms > MAX_FREEZE_LIFETIME_MS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "lifetime_ms {} must be between 1 and {MAX_FREEZE_LIFETIME_MS}; a freeze is \
                 always bounded",
                request.lifetime_ms
            ),
        ));
    }

    registry.reap_finished();
    if registry.active_count() >= registry.max_workers {
        return Err(OperationError::new(
            ErrorCode::BudgetExceeded,
            operation,
            format!(
                "{} freeze workers are already running, which is the limit",
                registry.max_workers
            ),
        )
        .with_next_step("Unfreeze something before freezing another range."));
    }

    let encoded = encode_payload(&request.payload, session.width, operation)?;
    if encoded.bytes.is_empty() || encoded.bytes.len() > MAX_WRITE_BYTES {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("the freeze payload is {} bytes", encoded.bytes.len()),
        ));
    }

    let address =
        Address::parse_hex(&request.address, operation)?.check_width(session.width, operation)?;
    address.checked_add(encoded.bytes.len() as u64, operation)?;
    registry
        .ranges
        .check_free(address.0, encoded.bytes.len(), operation)?;

    let (info, covers) =
        query_region(session.handle, address, encoded.bytes.len()).ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidAddress,
                operation,
                format!(
                    "{} is not part of any mapping in this target",
                    address.to_canonical(session.width)
                ),
            )
            .with_session(&session.id)
        })?;
    if info.State != MEM_COMMIT || !protection_allows_write(info.Protect.0) || !covers {
        return Err(OperationError::new(
            ErrorCode::InvalidAddress,
            operation,
            format!(
                "the range at {} is not a committed writable mapping",
                address.to_canonical(session.width)
            ),
        )
        .with_session(&session.id)
        .with_next_step("This server never changes page protection to force a write."));
    }

    let before = mem::read_raw(session.handle, address, encoded.bytes.len());
    if before.bytes.len() != encoded.bytes.len() {
        return Err(OperationError::new(
            ErrorCode::PartialRead,
            operation,
            format!(
                "only {} of {} pre-freeze bytes could be captured, so no freeze was started",
                before.bytes.len(),
                encoded.bytes.len()
            ),
        )
        .with_session(&session.id)
        .with_next_step("A freeze is never started without a complete pre-freeze capture."));
    }
    let original_bytes = before.bytes.clone();

    let (initial_written, initial_error) = write_raw(write_handle, address, &encoded.bytes);
    let initial_check = mem::read_raw(session.handle, address, encoded.bytes.len());
    let initial_verified = initial_written == encoded.bytes.len()
        && initial_error.is_none()
        && initial_check.bytes == encoded.bytes;
    if !initial_verified {
        let mut err = OperationError::new(
            if initial_written == encoded.bytes.len() {
                ErrorCode::VerifyFailed
            } else {
                ErrorCode::PartialWrite
            },
            operation,
            format!(
                "the initial freeze write put {initial_written} of {} bytes in place and did not \
                 verify, so no worker was started",
                encoded.bytes.len()
            ),
        )
        .with_session(&session.id)
        .with_address(address.to_canonical(session.width))
        .with_next_step(
            "No freeze worker exists and no undo entry was created. The original bytes are \
             reported so they can be restored deliberately.",
        );
        if let Some(code) = initial_error {
            err = err.with_win32(code, win::error_message(code));
        }
        return Err(err);
    }

    let freeze_id = next_id("freeze-");
    let shared = Arc::new(FreezeShared::default());
    {
        let mut stats = shared.stats.lock().expect("fresh mutex");
        stats.running = true;
    }

    let worker_handle = SendOwnedHandle(duplicate_for_worker(write_handle, operation)?);
    let read_handle = SendOwnedHandle(duplicate_for_worker(session.handle, operation)?);
    let worker_shared = Arc::clone(&shared);
    let frozen = encoded.bytes.clone();
    let interval = Duration::from_millis(request.interval_ms);
    let lifetime = Duration::from_millis(request.lifetime_ms);
    let worker_address = address;
    let worker_id = freeze_id.clone();

    let thread = std::thread::Builder::new()
        .name(format!("memscope-{worker_id}"))
        .spawn(move || {
            let write_owned = worker_handle;
            let read_owned = read_handle;
            let started = Instant::now();
            let reason;

            loop {
                if worker_shared.stop.load(Ordering::Relaxed) {
                    reason = worker_shared
                        .requested_reason
                        .lock()
                        .ok()
                        .and_then(|r| *r)
                        .unwrap_or(FreezeStopReason::Unfrozen);
                    break;
                }
                if started.elapsed() >= lifetime {
                    reason = FreezeStopReason::LifetimeElapsed;
                    break;
                }
                if let Err(e) = policy_check() {
                    reason = FreezeStopReason::AuthorisationRevoked;
                    if let Ok(mut stats) = worker_shared.stats.lock() {
                        stats.last_error = Some(e.message.clone());
                    }
                    break;
                }

                let tick_started = Instant::now();
                let current = mem::read_raw(read_owned.0.raw(), worker_address, frozen.len());
                if current.bytes.len() != frozen.len() {
                    reason = FreezeStopReason::TargetUnreadable;
                    if let Ok(mut stats) = worker_shared.stats.lock() {
                        stats.last_error = Some(format!(
                            "only {} of {} bytes were readable",
                            current.bytes.len(),
                            frozen.len()
                        ));
                    }
                    break;
                }

                let mut fatal = None;
                let drifted = current.bytes != frozen;
                if drifted {
                    let (written, error) = write_raw(write_owned.0.raw(), worker_address, &frozen);
                    let check = mem::read_raw(read_owned.0.raw(), worker_address, frozen.len());
                    if written != frozen.len() || error.is_some() {
                        fatal = Some((
                            FreezeStopReason::FatalWriteError,
                            format!("wrote {written} of {} bytes", frozen.len()),
                        ));
                    } else if check.bytes != frozen {
                        fatal = Some((
                            FreezeStopReason::FatalVerifyFailed,
                            "the correction did not verify".to_owned(),
                        ));
                    }
                }

                let latency = tick_started.elapsed().as_micros() as u64;
                if let Ok(mut stats) = worker_shared.stats.lock() {
                    stats.ticks = WireU64(stats.ticks.0 + 1);
                    stats.last_tick_latency_us = WireU64(latency);
                    if latency > stats.max_tick_latency_us.0 {
                        stats.max_tick_latency_us = WireU64(latency);
                    }
                    let total = stats.mean_tick_latency_us.0 * (stats.ticks.0 - 1) + latency;
                    stats.mean_tick_latency_us = WireU64(total / stats.ticks.0);
                    if drifted {
                        stats.corrections = WireU64(stats.corrections.0 + 1);
                        if stats.first_correction_latency_us.is_none() {
                            stats.first_correction_latency_us =
                                Some(WireU64(started.elapsed().as_micros() as u64));
                        }
                        match &fatal {
                            None => stats.writes_ok = WireU64(stats.writes_ok.0 + 1),
                            Some((_, note)) => {
                                stats.writes_failed = WireU64(stats.writes_failed.0 + 1);
                                stats.last_error = Some(note.clone());
                            }
                        }
                    }
                }

                if let Some((fatal_reason, _)) = fatal {
                    reason = fatal_reason;
                    break;
                }
                std::thread::sleep(interval);
            }

            if let Ok(mut stats) = worker_shared.stats.lock() {
                stats.running = false;
                stats.stop_reason = Some(reason);
            }
            drop(write_owned);
            drop(read_owned);
        })
        .map_err(|e| {
            OperationError::new(
                ErrorCode::BudgetExceeded,
                operation,
                format!("cannot start a freeze worker thread: {e}"),
            )
        })?;

    let thread_id = thread.thread().id();
    let started_at_unix_us = initial_check.observed_at_unix_us;
    registry.workers.push(FreezeWorker {
        id: freeze_id.clone(),
        session_id: session.id.clone(),
        pid: session.pid,
        creation_time: session.creation_time.clone(),
        address: address.0,
        frozen_bytes: encoded.bytes.clone(),
        original_bytes: original_bytes.clone(),
        value_type: encoded.value_type,
        interval_ms: request.interval_ms,
        lifetime_ms: request.lifetime_ms,
        started_at_unix_us,
        shared,
        thread: Some(thread),
        thread_id,
    });
    registry.rebuild_ranges();

    Ok(FreezeOutcome {
        freeze_id,
        session_id: session.id.clone(),
        address: address.to_canonical(session.width),
        address_raw: WireU64(address.0),
        value_type: encoded.value_type,
        frozen_raw: hex(&encoded.bytes),
        original_raw: hex(&original_bytes),
        interval_ms: request.interval_ms,
        lifetime_ms: request.lifetime_ms,
        started_at_unix_us: WireU64(started_at_unix_us),
        initial_write_verified: true,
        notes: vec![
            "A freeze is a worker, not an undo entry: its repeated writes are never recorded in \
             undo history."
                .to_owned(),
            "The pre-freeze bytes were captured once, before the first write, and are reported \
             here as original_raw."
                .to_owned(),
            "The worker rechecks authorisation before every tick and stops at the first fatal \
             error."
                .to_owned(),
            format!(
                "Writes and undo across 0x{:x}..0x{:x} are refused with ADDRESS_FROZEN while this \
                 freeze is active.",
                address.0,
                address.0 + encoded.bytes.len() as u64
            ),
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnfreezeRequest {
    pub freeze_id: String,
    #[serde(default)]
    pub restore_original: bool,
    #[serde(default)]
    pub confirm: bool,
}

pub fn unfreeze_value(
    session: &SessionRef,
    write_handle: HANDLE,
    request: &UnfreezeRequest,
    registry: &mut FreezeRegistry,
    authorisation_still_valid: impl Fn() -> Result<()>,
    operation: &str,
) -> Result<UnfreezeOutcome> {
    let index = registry
        .workers
        .iter()
        .position(|w| w.id == request.freeze_id)
        .ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("no active freeze {} is registered", request.freeze_id),
            )
            .with_next_step("Call list_frozen to see the active and recently stopped freezes.")
        })?;

    if registry.workers[index].session_id != session.id {
        return Err(OperationError::new(
            ErrorCode::ProcessReplaced,
            operation,
            format!(
                "freeze {} belongs to session {}, not {}",
                request.freeze_id, registry.workers[index].session_id, session.id
            ),
        )
        .with_session(&session.id));
    }

    registry.workers[index].request_stop(FreezeStopReason::Unfrozen);
    let mut worker = registry.workers.remove(index);
    let joined = worker.join(operation).is_ok();
    registry.rebuild_ranges();

    let stats = worker.stats();
    let stop_reason = stats.stop_reason.unwrap_or(FreezeStopReason::Unfrozen);
    let address = Address(worker.address);
    let mut notes = vec![format!(
        "the worker was stopped and {} before anything was restored",
        if joined {
            "joined"
        } else {
            "could not be joined"
        }
    )];

    let mut restore = RestoreOutcome::NotRequested;
    let mut restored_raw = None;
    let mut readback_raw = None;
    let mut restore_verified = false;

    if request.restore_original {
        if let Err(gate) = require_write_authorisation(request.confirm, operation) {
            restore = RestoreOutcome::SkippedUnauthorised;
            notes.push(format!(
                "restoration was requested but not authorised, so it was skipped: {}",
                gate.message
            ));
        } else if let Err(revoked) = authorisation_still_valid() {
            restore = RestoreOutcome::SkippedAuthorisationRevoked;
            notes.push(format!(
                "restoration was skipped because authorisation is no longer valid: {}. Memory was \
                 left exactly as the freeze had it; nothing was written after revocation.",
                revoked.message
            ));
        } else {
            let (written, error) = write_raw(write_handle, address, &worker.original_bytes);
            let check = mem::read_raw(session.handle, address, worker.original_bytes.len());
            readback_raw =
                (check.bytes.len() == worker.original_bytes.len()).then(|| hex(&check.bytes));
            restore_verified = written == worker.original_bytes.len()
                && error.is_none()
                && check.bytes == worker.original_bytes;
            restored_raw = Some(hex(&worker.original_bytes));
            if restore_verified {
                restore = RestoreOutcome::Restored;
                notes.push("the pre-freeze bytes were restored and verified".to_owned());
            } else {
                restore = RestoreOutcome::RestoreFailed;
                notes.push(format!(
                    "restoration wrote {written} of {} bytes and did NOT verify; memory is in an \
                     unknown state and no successful restore is claimed",
                    worker.original_bytes.len()
                ));
            }
        }
    } else {
        notes.push(
            "restore_original was not set, so the frozen value was left in place. Stopping a \
             freeze does not restore bytes."
                .to_owned(),
        );
    }

    let view = FrozenView {
        freeze_id: worker.id.clone(),
        session_id: worker.session_id.clone(),
        pid: worker.pid,
        address: format!("0x{:x}", worker.address),
        value_type: worker.value_type,
        frozen_raw: hex(&worker.frozen_bytes),
        original_raw: hex(&worker.original_bytes),
        interval_ms: worker.interval_ms,
        lifetime_ms: worker.lifetime_ms,
        started_at_unix_us: WireU64(worker.started_at_unix_us),
        stats: stats.clone(),
    };
    registry.stopped.push(view);

    Ok(UnfreezeOutcome {
        freeze_id: worker.id.clone(),
        session_id: session.id.clone(),
        address: address.to_canonical(session.width),
        stopped: true,
        joined,
        stop_reason,
        stats,
        restore,
        restored_raw,
        readback_raw,
        restore_verified,
        notes,
    })
}

pub fn list_frozen(registry: &mut FreezeRegistry) -> Vec<FrozenView> {
    registry.reap_finished();
    registry.views()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{WireI64, WireU64};

    fn typed(value_type: ValueType, value: Needle) -> WritePayload {
        WritePayload::Typed { value_type, value }
    }

    #[test]
    fn both_gates_are_required_and_the_environment_gate_is_checked_first() {
        let err = require_write_authorisation(true, "write_memory")
            .expect_err("this test process has no MEMSCOPE_ALLOW_WRITE");
        assert_eq!(err.code, ErrorCode::WriteDisabled);

        let err = require_write_authorisation(false, "write_memory").expect_err("no confirm");
        assert_eq!(
            err.code,
            ErrorCode::WriteDisabled,
            "the environment gate is reported first when both are missing"
        );
    }

    #[test]
    fn a_wildcard_pattern_is_refused_as_a_write_payload() {
        let err = encode_payload(
            &WritePayload::Bytes {
                hex: "cd ?? cc 3d".to_owned(),
            },
            PointerWidth::Eight,
            "write_memory",
        )
        .expect_err("a wildcard cannot be written");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("wildcard"), "got {}", err.message);
    }

    #[test]
    fn every_integer_width_encodes_little_endian_and_refuses_an_out_of_range_value() {
        let cases: &[(ValueType, i64, &[u8])] = &[
            (ValueType::Int8, -128, &[0x80]),
            (ValueType::Int16, -32768, &[0x00, 0x80]),
            (ValueType::Int32, 100, &[0x64, 0x00, 0x00, 0x00]),
            (
                ValueType::Int64,
                i64::MIN,
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
            ),
        ];
        for (value_type, value, expected) in cases {
            let encoded = encode_payload(
                &typed(
                    *value_type,
                    Needle::Int {
                        value: WireI64(*value),
                    },
                ),
                PointerWidth::Eight,
                "write_memory",
            )
            .expect("encode");
            assert_eq!(encoded.bytes, *expected, "{}", value_type.as_str());
        }

        for (value_type, value) in [
            (ValueType::Int8, 128i64),
            (ValueType::Int8, -129),
            (ValueType::Int16, 40000),
            (ValueType::Int32, i64::from(i32::MAX) + 1),
        ] {
            let err = encode_payload(
                &typed(
                    value_type,
                    Needle::Int {
                        value: WireI64(value),
                    },
                ),
                PointerWidth::Eight,
                "write_memory",
            )
            .expect_err("out of range");
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            assert!(err.message.contains("does not fit"), "got {}", err.message);
        }
    }

    #[test]
    fn unsigned_and_pointer_payloads_respect_the_target_width() {
        let encoded = encode_payload(
            &typed(
                ValueType::Uint32,
                Needle::Uint {
                    value: WireU64(u64::from(u32::MAX)),
                },
            ),
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(encoded.bytes, vec![0xff, 0xff, 0xff, 0xff]);

        let narrow = encode_payload(
            &typed(
                ValueType::Pointer,
                Needle::Uint {
                    value: WireU64(0x1122_3344),
                },
            ),
            PointerWidth::Four,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(narrow.bytes, vec![0x44, 0x33, 0x22, 0x11]);

        let too_wide = encode_payload(
            &typed(
                ValueType::Pointer,
                Needle::Uint {
                    value: WireU64(0x1_0000_0000),
                },
            ),
            PointerWidth::Four,
            "write_memory",
        )
        .expect_err("a 33-bit value is not a 4-byte pointer");
        assert_eq!(too_wide.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn binary32_one_tenth_encodes_to_the_bytes_the_brief_names() {
        let encoded = encode_payload(
            &typed(ValueType::Float, Needle::Float { value: 0.1 }),
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(hex(&encoded.bytes), "cdcccc3d");

        let double = encode_payload(
            &typed(ValueType::Double, Needle::Float { value: 0.1 }),
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(hex(&double.bytes), "9a9999999999b93f");
    }

    #[test]
    fn a_mismatched_value_shape_is_refused_rather_than_coerced() {
        let err = encode_payload(
            &typed(ValueType::Int32, Needle::Float { value: 1.5 }),
            PointerWidth::Eight,
            "write_memory",
        )
        .expect_err("a float is not an int32 payload");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_string_write_defaults_to_no_terminator_and_adds_one_only_on_request() {
        let bare = encode_payload(
            &WritePayload::Text {
                value_type: ValueType::String,
                text: "ab".to_owned(),
                include_terminator: false,
            },
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(bare.bytes, b"ab".to_vec());
        assert!(!bare.includes_terminator);

        let terminated = encode_payload(
            &WritePayload::Text {
                value_type: ValueType::String,
                text: "ab".to_owned(),
                include_terminator: true,
            },
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(terminated.bytes, vec![b'a', b'b', 0]);

        let utf16 = encode_payload(
            &WritePayload::Text {
                value_type: ValueType::String16,
                text: "ab".to_owned(),
                include_terminator: true,
            },
            PointerWidth::Eight,
            "write_memory",
        )
        .expect("encode");
        assert_eq!(utf16.bytes, vec![b'a', 0, b'b', 0, 0, 0]);
    }

    #[test]
    fn a_default_write_request_has_confirm_false() {
        let request: WriteRequest =
            serde_json::from_str(r#"{"address":"0x1000","payload":{"kind":"bytes","hex":"00"}}"#)
                .expect("deserialise");
        assert!(!request.confirm, "confirm must never default to true");
        assert!(request.attempt_recovery_on_failure);
    }

    #[test]
    fn undo_history_is_bounded_by_entries_and_by_bytes() {
        let mut history = UndoHistory::new(3, 1024);
        for n in 0..5u8 {
            history.push(UndoEntry {
                id: format!("undo-{n}"),
                session_id: "s1".to_owned(),
                pid: 1,
                creation_time: "1".to_owned(),
                address: 0x1000 + u64::from(n),
                original: vec![0; 4],
                written: vec![1; 4],
                created_at_unix_us: 0,
            });
        }
        assert_eq!(history.len(), 3);
        assert_eq!(history.dropped(), 2);
        assert!(history.peek("undo-0").is_none(), "the oldest was evicted");
        assert!(history.peek("undo-4").is_some());

        let mut tight = UndoHistory::new(100, 16);
        for n in 0..5u8 {
            tight.push(UndoEntry {
                id: format!("u{n}"),
                session_id: "s1".to_owned(),
                pid: 1,
                creation_time: "1".to_owned(),
                address: 0x2000,
                original: vec![0; 4],
                written: vec![1; 4],
                created_at_unix_us: 0,
            });
        }
        assert!(tight.bytes() <= 16);
        assert!(tight.dropped() > 0);
    }

    #[test]
    fn undo_history_can_be_cleared_per_session() {
        let mut history = UndoHistory::default();
        for (id, session) in [("a", "s1"), ("b", "s2"), ("c", "s1")] {
            history.push(UndoEntry {
                id: id.to_owned(),
                session_id: session.to_owned(),
                pid: 1,
                creation_time: "1".to_owned(),
                address: 0x1000,
                original: vec![0],
                written: vec![1],
                created_at_unix_us: 0,
            });
        }
        assert_eq!(history.views(Some("s1")).len(), 2);
        assert_eq!(history.clear_session("s1"), 2);
        assert_eq!(history.len(), 1);
        assert_eq!(history.views(None)[0].id, "b");
    }

    #[test]
    fn a_frozen_range_refuses_an_overlapping_write() {
        let mut frozen = FrozenRanges::default();
        frozen.insert("freeze-1", 0x1000, 4);

        assert!(frozen.check_free(0x2000, 4, "write_memory").is_ok());
        for (address, len) in [(0x1000u64, 4usize), (0x1002, 4), (0xffe, 4), (0x1000, 1)] {
            let err = frozen
                .check_free(address, len, "write_memory")
                .expect_err("overlap");
            assert_eq!(err.code, ErrorCode::AddressFrozen);
        }
        assert!(frozen.check_free(0x1004, 4, "write_memory").is_ok());
        assert!(frozen.check_free(0xffc, 4, "write_memory").is_ok());

        assert!(frozen.remove("freeze-1"));
        assert!(frozen.check_free(0x1000, 4, "write_memory").is_ok());
    }

    #[test]
    fn protection_must_already_allow_writing() {
        assert!(protection_allows_write(PAGE_READWRITE.0));
        assert!(protection_allows_write(PAGE_WRITECOPY.0));
        assert!(protection_allows_write(PAGE_EXECUTE_READWRITE.0));
        assert!(!protection_allows_write(
            windows::Win32::System::Memory::PAGE_READONLY.0
        ));
        assert!(!protection_allows_write(
            windows::Win32::System::Memory::PAGE_NOACCESS.0
        ));
        assert!(
            !protection_allows_write(PAGE_READWRITE.0 | PAGE_GUARD.0),
            "a guard page is never written through"
        );
    }

    #[test]
    fn the_failure_journal_is_separate_from_undo_history() {
        let mut journal = FailureJournal::default();
        assert!(journal.is_empty());
        journal.record(FailedOperation {
            id: "failed-1".to_owned(),
            operation: "write_memory".to_owned(),
            session_id: "s1".to_owned(),
            address: "0x1000".to_owned(),
            requested_bytes: 4,
            bytes_written: 2,
            requested_raw: "01020304".to_owned(),
            original_raw: "00000000".to_owned(),
            readback_raw: Some("01020000".to_owned()),
            reason: "short write".to_owned(),
            memory_may_have_changed: true,
            recovery_attempted: true,
            recovery_bytes_written: 4,
            recovery_verified: true,
            recovery_note: "restored".to_owned(),
            created_at_unix_us: WireU64(1),
        });
        assert_eq!(journal.len(), 1);
        assert!(journal.entries()[0].memory_may_have_changed);

        let history = UndoHistory::default();
        assert!(
            history.is_empty(),
            "a failed operation must never appear as an undo entry"
        );
    }

    #[test]
    fn every_mutation_status_has_a_wire_name() {
        for status in [
            MutationStatus::NotAttempted,
            MutationStatus::Written,
            MutationStatus::PartiallyWritten,
            MutationStatus::WrittenButUnverified,
            MutationStatus::Failed,
        ] {
            let json = serde_json::to_string(&status).expect("serialise");
            assert!(json.len() > 2, "{status:?}");
        }
    }
}
