use std::time::{Instant, SystemTime};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::error::{ErrorCode, OperationError, Result};
use crate::win;
use crate::wire::{Address, FloatClass, FloatValue, PointerWidth, WireI64, WireU64, hex};

pub const PAGE_SIZE: usize = 4096;
pub const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const MAX_BATCH_ITEMS: usize = 1024;
pub const MAX_STRUCT_FIELDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float,
    Double,
    String,
    String16,
    Bytes,
    Pointer,
}

impl ValueType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Int8 => "int8",
            Self::Int16 => "int16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Uint8 => "uint8",
            Self::Uint16 => "uint16",
            Self::Uint32 => "uint32",
            Self::Uint64 => "uint64",
            Self::Float => "float",
            Self::Double => "double",
            Self::String => "string",
            Self::String16 => "string16",
            Self::Bytes => "bytes",
            Self::Pointer => "pointer",
        }
    }

    pub const fn fixed_size(self) -> Option<usize> {
        match self {
            Self::Int8 | Self::Uint8 => Some(1),
            Self::Int16 | Self::Uint16 => Some(2),
            Self::Int32 | Self::Uint32 | Self::Float => Some(4),
            Self::Int64 | Self::Uint64 | Self::Double => Some(8),
            Self::String | Self::String16 | Self::Bytes | Self::Pointer => None,
        }
    }

    pub const fn is_scalar(self) -> bool {
        self.fixed_size().is_some()
    }

    pub const fn size_for(self, width: PointerWidth) -> Option<usize> {
        match self {
            Self::Pointer => Some(width.bytes()),
            other => other.fixed_size(),
        }
    }

    pub const fn alignment(self, width: PointerWidth) -> usize {
        match self.size_for(width) {
            Some(n) => n,
            None => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyMode {
    Live,
    Paused,
}

impl ConsistencyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Paused => "paused",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub session_id: String,
    pub pid: u32,
    pub creation_time: String,
    pub address: String,
    pub requested_bytes: usize,
    pub actual_bytes: usize,
    pub complete: bool,
    pub raw: String,
    pub observed_at_unix_us: WireU64,
    pub elapsed_us: WireU64,
    pub consistency: ConsistencyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub bytes_consumed: usize,
    pub terminator_found: bool,
    pub output_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decoded {
    Int { value: WireI64 },
    Uint { value: WireU64 },
    Float { value: FloatValue },
    Text { value: TextValue },
    Bytes,
    Pointer { value: String, raw_value: WireU64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResult {
    pub value_type: ValueType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Decoded>,
    #[serde(flatten)]
    pub provenance: Provenance,
}

#[derive(Debug, Clone)]
pub struct SessionRef {
    pub id: String,
    pub pid: u32,
    pub creation_time: String,
    pub width: PointerWidth,
    pub handle: HANDLE,
}

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct RawRead {
    pub bytes: Vec<u8>,
    pub requested: usize,
    pub win32_error: Option<u32>,
    pub elapsed_us: u64,
    pub observed_at_unix_us: u64,
}

impl RawRead {
    pub fn complete(&self) -> bool {
        self.bytes.len() == self.requested && self.win32_error.is_none()
    }
}

fn read_once(handle: HANDLE, address: Address, len: usize) -> (Vec<u8>, Option<u32>) {
    if len == 0 {
        return (Vec::new(), None);
    }
    let mut buffer = vec![0u8; len];
    let mut transferred: usize = 0;
    let result = unsafe {
        ReadProcessMemory(
            handle,
            address.0 as *const core::ffi::c_void,
            buffer.as_mut_ptr().cast(),
            len,
            Some(&mut transferred),
        )
    };
    let error = if result.is_err() {
        Some(win::last_error())
    } else {
        None
    };
    buffer.truncate(transferred.min(len));
    (buffer, error)
}

pub fn read_raw(handle: HANDLE, address: Address, len: usize) -> RawRead {
    let started = Instant::now();
    let observed_at_unix_us = unix_micros();

    let (bytes, error) = read_once(handle, address, len);
    if bytes.len() == len && error.is_none() {
        return RawRead {
            bytes,
            requested: len,
            win32_error: None,
            elapsed_us: started.elapsed().as_micros() as u64,
            observed_at_unix_us,
        };
    }

    let mut collected = bytes;
    let mut first_error = error;
    if collected.len() < len {
        let mut offset = collected.len();
        while offset < len {
            let page_end = (address.0 as usize + offset + PAGE_SIZE) & !(PAGE_SIZE - 1);
            let chunk = (page_end - (address.0 as usize + offset)).min(len - offset);
            let (page_bytes, page_error) =
                read_once(handle, Address(address.0 + offset as u64), chunk);
            let got = page_bytes.len();
            collected.extend_from_slice(&page_bytes);
            if got < chunk {
                if first_error.is_none() {
                    first_error = page_error;
                }
                break;
            }
            offset += chunk;
        }
    }
    if collected.len() == len {
        first_error = None;
    }

    RawRead {
        bytes: collected,
        requested: len,
        win32_error: first_error,
        elapsed_us: started.elapsed().as_micros() as u64,
        observed_at_unix_us,
    }
}

fn provenance(session: &SessionRef, address: Address, raw: &RawRead) -> Provenance {
    Provenance {
        session_id: session.id.clone(),
        pid: session.pid,
        creation_time: session.creation_time.clone(),
        address: address.to_canonical(session.width),
        requested_bytes: raw.requested,
        actual_bytes: raw.bytes.len(),
        complete: raw.complete(),
        raw: hex(&raw.bytes),
        observed_at_unix_us: WireU64(raw.observed_at_unix_us),
        elapsed_us: WireU64(raw.elapsed_us),
        consistency: ConsistencyMode::Live,
        win32_error: raw.win32_error,
        win32_message: raw.win32_error.and_then(win::error_message),
    }
}

fn partial_read_error(
    session: &SessionRef,
    address: Address,
    raw: &RawRead,
    operation: &str,
    what: &str,
) -> OperationError {
    let mut err = OperationError::new(
        ErrorCode::PartialRead,
        operation,
        format!(
            "{what} needs {} bytes at {} but only {} were readable",
            raw.requested,
            address.to_canonical(session.width),
            raw.bytes.len()
        ),
    )
    .with_session(&session.id)
    .with_pid(session.pid)
    .with_address(address.to_canonical(session.width))
    .with_next_step(
        "The unread bytes are not zero-filled. Narrow the range, or list regions to \
         find where the mapping ends.",
    );
    if let Some(code) = raw.win32_error {
        err = err.with_win32(code, win::error_message(code));
    }
    err
}

fn check_length(len: usize, limit: usize, operation: &str, what: &str) -> Result<()> {
    if len == 0 {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("{what} length must be at least 1"),
        )
        .with_next_step("Request at least one byte."));
    }
    if len > limit {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("{what} length {len} exceeds the {limit}-byte limit"),
        )
        .with_next_step("Split the request into smaller reads."));
    }
    Ok(())
}

pub fn read_bytes(
    session: &SessionRef,
    address: Address,
    len: usize,
    operation: &str,
) -> Result<ReadResult> {
    check_length(len, MAX_READ_BYTES, operation, "read_bytes")?;
    address.check_width(session.width, operation)?;
    address.checked_add(len as u64, operation)?;

    let raw = read_raw(session.handle, address, len);
    if raw.bytes.is_empty() {
        let mut err = OperationError::new(
            ErrorCode::InvalidAddress,
            operation,
            format!(
                "no bytes were readable at {}",
                address.to_canonical(session.width)
            ),
        )
        .with_session(&session.id)
        .with_pid(session.pid)
        .with_address(address.to_canonical(session.width))
        .with_next_step("List regions to find a committed, readable address.");
        if let Some(code) = raw.win32_error {
            err = err.with_win32(code, win::error_message(code));
        }
        return Err(err);
    }
    Ok(ReadResult {
        value_type: ValueType::Bytes,
        decoded: Some(Decoded::Bytes),
        provenance: provenance(session, address, &raw),
    })
}

pub fn decode_scalar(
    value_type: ValueType,
    bytes: &[u8],
    width: PointerWidth,
    operation: &str,
) -> Result<Decoded> {
    let needed = value_type.size_for(width).ok_or_else(|| {
        OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("{} is not a fixed-size type", value_type.as_str()),
        )
    })?;
    if bytes.len() < needed {
        return Err(OperationError::new(
            ErrorCode::PartialRead,
            operation,
            format!(
                "{} needs {needed} bytes but {} were supplied",
                value_type.as_str(),
                bytes.len()
            ),
        ));
    }
    let b = &bytes[..needed];
    Ok(match value_type {
        ValueType::Int8 => Decoded::Int {
            value: WireI64(i8::from_le_bytes([b[0]]) as i64),
        },
        ValueType::Int16 => Decoded::Int {
            value: WireI64(i16::from_le_bytes([b[0], b[1]]) as i64),
        },
        ValueType::Int32 => Decoded::Int {
            value: WireI64(i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64),
        },
        ValueType::Int64 => Decoded::Int {
            value: WireI64(i64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])),
        },
        ValueType::Uint8 => Decoded::Uint {
            value: WireU64(u64::from(b[0])),
        },
        ValueType::Uint16 => Decoded::Uint {
            value: WireU64(u64::from(u16::from_le_bytes([b[0], b[1]]))),
        },
        ValueType::Uint32 => Decoded::Uint {
            value: WireU64(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))),
        },
        ValueType::Uint64 => Decoded::Uint {
            value: WireU64(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])),
        },
        ValueType::Float => Decoded::Float {
            value: FloatValue::from_f32(f32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        },
        ValueType::Double => Decoded::Float {
            value: FloatValue::from_f64(f64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])),
        },
        ValueType::Pointer => {
            let raw_value = match width {
                PointerWidth::Four => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
                PointerWidth::Eight => {
                    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                }
            };
            Decoded::Pointer {
                value: Address(raw_value).to_canonical(width),
                raw_value: WireU64(raw_value),
            }
        }
        ValueType::String | ValueType::String16 | ValueType::Bytes => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("{} is not a scalar", value_type.as_str()),
            ));
        }
    })
}

pub fn decode_utf8(bytes: &[u8], max_chars: Option<usize>) -> TextValue {
    let terminator = bytes.iter().position(|&b| b == 0);
    let terminator_found = terminator.is_some();
    let body_end = terminator.unwrap_or(bytes.len());
    let body = &bytes[..body_end];
    let bytes_consumed = if terminator_found {
        body_end + 1
    } else {
        body_end
    };

    let (text, decode_error) = match std::str::from_utf8(body) {
        Ok(s) => (Some(s.to_owned()), None),
        Err(e) => (
            None,
            Some(format!("invalid UTF-8 at byte {}: {e}", e.valid_up_to())),
        ),
    };

    let mut output_truncated = false;
    let text = match (text, max_chars) {
        (Some(s), Some(limit)) if s.chars().count() > limit => {
            output_truncated = true;
            Some(s.chars().take(limit).collect())
        }
        (other, _) => other,
    };

    TextValue {
        text,
        bytes_consumed,
        terminator_found,
        output_truncated,
        decode_error,
    }
}

pub fn decode_utf16le(bytes: &[u8], max_chars: Option<usize>) -> TextValue {
    let usable = bytes.len() - (if bytes.len().is_multiple_of(2) { 0 } else { 1 });
    let mut units: Vec<u16> = Vec::with_capacity(usable / 2);
    let mut terminator_found = false;
    let mut code_units = 0usize;
    for pair in bytes[..usable].chunks(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            terminator_found = true;
            break;
        }
        units.push(unit);
        code_units += 1;
    }
    let bytes_consumed = if terminator_found {
        code_units * 2 + 2
    } else {
        code_units * 2
    };

    let (text, decode_error) = match String::from_utf16(&units) {
        Ok(s) => (Some(s), None),
        Err(e) => (None, Some(format!("invalid UTF-16LE: {e}"))),
    };

    let mut output_truncated = false;
    let text = match (text, max_chars) {
        (Some(s), Some(limit)) if s.chars().count() > limit => {
            output_truncated = true;
            Some(s.chars().take(limit).collect())
        }
        (other, _) => other,
    };

    let mut value = TextValue {
        text,
        bytes_consumed,
        terminator_found,
        output_truncated,
        decode_error,
    };
    if !bytes.len().is_multiple_of(2) && !value.terminator_found {
        let note = format!(
            "{} trailing byte is not a whole UTF-16 code unit",
            bytes.len() - usable
        );
        value.decode_error = Some(match value.decode_error {
            Some(existing) => format!("{existing}; {note}"),
            None => note,
        });
    }
    value
}

pub fn read_memory(
    session: &SessionRef,
    address: Address,
    value_type: ValueType,
    max_bytes: Option<usize>,
    max_chars: Option<usize>,
    operation: &str,
) -> Result<ReadResult> {
    address.check_width(session.width, operation)?;

    match value_type {
        ValueType::Bytes => {
            let len = max_bytes.ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    "reading bytes requires max_bytes",
                )
                .with_next_step("Supply max_bytes, or use read_bytes with an explicit length.")
            })?;
            read_bytes(session, address, len, operation)
        }
        ValueType::String | ValueType::String16 => {
            let len = max_bytes.ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("{} requires max_bytes", value_type.as_str()),
                )
                .with_next_step(
                    "A string read is always bounded; supply max_bytes, for example 256.",
                )
            })?;
            check_length(len, MAX_STRING_BYTES, operation, value_type.as_str())?;
            address.checked_add(len as u64, operation)?;

            let raw = read_raw(session.handle, address, len);
            if raw.bytes.is_empty() {
                return Err(partial_read_error(
                    session,
                    address,
                    &raw,
                    operation,
                    value_type.as_str(),
                ));
            }
            let text = if value_type == ValueType::String {
                decode_utf8(&raw.bytes, max_chars)
            } else {
                decode_utf16le(&raw.bytes, max_chars)
            };
            Ok(ReadResult {
                value_type,
                decoded: Some(Decoded::Text { value: text }),
                provenance: provenance(session, address, &raw),
            })
        }
        scalar => {
            let needed = scalar
                .size_for(session.width)
                .expect("every remaining type is fixed size");
            address.checked_add(needed as u64, operation)?;
            let raw = read_raw(session.handle, address, needed);
            if raw.bytes.len() < needed {
                return Err(partial_read_error(
                    session,
                    address,
                    &raw,
                    operation,
                    scalar.as_str(),
                ));
            }
            let decoded = decode_scalar(scalar, &raw.bytes, session.width, operation)?;
            Ok(ReadResult {
                value_type: scalar,
                decoded: Some(decoded),
                provenance: provenance(session, address, &raw),
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BatchItemRequest {
    pub address: String,
    pub value_type: ValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemOutcome {
    pub index: usize,
    pub requested_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ReadResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    pub requested: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub atomic_snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub items: Vec<BatchItemOutcome>,
    pub summary: BatchSummary,
}

pub fn read_batch(
    session: &SessionRef,
    items: &[BatchItemRequest],
    operation: &str,
) -> Result<BatchResult> {
    if items.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "read_batch needs at least one item",
        ));
    }
    if items.len() > MAX_BATCH_ITEMS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "read_batch received {} items, over the {MAX_BATCH_ITEMS} limit",
                items.len()
            ),
        ));
    }

    let mut outcomes = Vec::with_capacity(items.len());
    let mut succeeded = 0usize;
    for (index, item) in items.iter().enumerate() {
        let parsed = Address::parse_hex(&item.address, operation)
            .and_then(|a| a.check_width(session.width, operation));
        let outcome = match parsed {
            Err(error) => BatchItemOutcome {
                index,
                requested_address: item.address.clone(),
                result: None,
                error: Some(error),
            },
            Ok(address) => match read_memory(
                session,
                address,
                item.value_type,
                item.max_bytes,
                item.max_chars,
                operation,
            ) {
                Ok(result) => {
                    succeeded += 1;
                    BatchItemOutcome {
                        index,
                        requested_address: item.address.clone(),
                        result: Some(result),
                        error: None,
                    }
                }
                Err(error) => BatchItemOutcome {
                    index,
                    requested_address: item.address.clone(),
                    result: None,
                    error: Some(error),
                },
            },
        };
        outcomes.push(outcome);
    }

    Ok(BatchResult {
        summary: BatchSummary {
            requested: items.len(),
            succeeded,
            failed: items.len() - succeeded,
            atomic_snapshot: false,
        },
        items: outcomes,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructFieldSpec {
    pub name: String,
    pub value_type: ValueType,
    pub offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldOutcome {
    pub name: String,
    pub value_type: ValueType,
    pub offset: u64,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Decoded>,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructResult {
    pub base_address: String,
    pub declared_size: usize,
    pub layout_source: String,
    pub fields: Vec<StructFieldOutcome>,
    #[serde(flatten)]
    pub provenance: Provenance,
}

pub fn read_struct(
    session: &SessionRef,
    base: Address,
    fields: &[StructFieldSpec],
    declared_size: Option<usize>,
    operation: &str,
) -> Result<StructResult> {
    if fields.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "read_struct needs at least one field",
        )
        .with_next_step("Declare the fields explicitly; layout is never inferred."));
    }
    if fields.len() > MAX_STRUCT_FIELDS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "read_struct received {} fields, over the {MAX_STRUCT_FIELDS} limit",
                fields.len()
            ),
        ));
    }
    base.check_width(session.width, operation)?;

    let mut span = 0usize;
    for field in fields {
        let size = match field.value_type {
            ValueType::String | ValueType::String16 | ValueType::Bytes => {
                field.max_bytes.ok_or_else(|| {
                    OperationError::new(
                        ErrorCode::InvalidArgument,
                        operation,
                        format!(
                            "field {:?} is a {} and needs max_bytes",
                            field.name,
                            field.value_type.as_str()
                        ),
                    )
                })?
            }
            other => other
                .size_for(session.width)
                .expect("every remaining type is fixed size"),
        };
        let end = usize::try_from(field.offset)
            .ok()
            .and_then(|o| o.checked_add(size))
            .ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("field {:?} ends outside the addressable range", field.name),
                )
            })?;
        span = span.max(end);
    }
    let total = declared_size.unwrap_or(span);
    if total < span {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("declared size {total} is smaller than the {span} bytes the fields span"),
        )
        .with_next_step("Raise total_size, or move the field that overflows it."));
    }
    check_length(total, MAX_READ_BYTES, operation, "read_struct")?;
    base.checked_add(total as u64, operation)?;

    let raw = read_raw(session.handle, base, total);
    let mut outcomes = Vec::with_capacity(fields.len());
    for field in fields {
        let offset = field.offset as usize;
        let address = Address(base.0 + field.offset);
        let size = match field.value_type {
            ValueType::String | ValueType::String16 | ValueType::Bytes => {
                field.max_bytes.unwrap_or(0)
            }
            other => other.size_for(session.width).unwrap_or(0),
        };
        let available = raw.bytes.len().saturating_sub(offset).min(size);
        let slice = if offset < raw.bytes.len() {
            &raw.bytes[offset..offset + available]
        } else {
            &[][..]
        };

        if available < size {
            outcomes.push(StructFieldOutcome {
                name: field.name.clone(),
                value_type: field.value_type,
                offset: field.offset,
                address: address.to_canonical(session.width),
                decoded: None,
                raw: hex(slice),
                error: Some(
                    OperationError::new(
                        ErrorCode::PartialRead,
                        operation,
                        format!(
                            "field {:?} needs {size} bytes at offset {} but only {available} were readable",
                            field.name, field.offset
                        ),
                    )
                    .with_session(&session.id)
                    .with_address(address.to_canonical(session.width)),
                ),
            });
            continue;
        }

        let decoded = match field.value_type {
            ValueType::String => Ok(Decoded::Text {
                value: decode_utf8(slice, field.max_chars),
            }),
            ValueType::String16 => Ok(Decoded::Text {
                value: decode_utf16le(slice, field.max_chars),
            }),
            ValueType::Bytes => Ok(Decoded::Bytes),
            other => decode_scalar(other, slice, session.width, operation),
        };
        match decoded {
            Ok(value) => outcomes.push(StructFieldOutcome {
                name: field.name.clone(),
                value_type: field.value_type,
                offset: field.offset,
                address: address.to_canonical(session.width),
                decoded: Some(value),
                raw: hex(slice),
                error: None,
            }),
            Err(error) => outcomes.push(StructFieldOutcome {
                name: field.name.clone(),
                value_type: field.value_type,
                offset: field.offset,
                address: address.to_canonical(session.width),
                decoded: None,
                raw: hex(slice),
                error: Some(error),
            }),
        }
    }

    Ok(StructResult {
        base_address: base.to_canonical(session.width),
        declared_size: total,
        layout_source: "caller-declared field offsets; no compiler packing was inferred".to_owned(),
        fields: outcomes,
        provenance: provenance(session, base, &raw),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FloatCompare {
    Exact,
    Tolerance { relative: f64, absolute: f64 },
}

pub const DEFAULT_FLOAT_REL_TOL: f64 = 1e-6;
pub const DEFAULT_FLOAT_ABS_TOL: f64 = 1e-9;

pub fn float_matches(observed: f64, target: f64, compare: FloatCompare) -> bool {
    match compare {
        FloatCompare::Exact => observed.to_bits() == target.to_bits(),
        FloatCompare::Tolerance { relative, absolute } => {
            if target.is_nan() || observed.is_nan() {
                return false;
            }
            if target.is_infinite() || observed.is_infinite() {
                return observed == target;
            }
            let diff = (observed - target).abs();
            diff <= absolute + relative * target.abs()
        }
    }
}

pub fn float32_matches(observed: f32, target: f32, compare: FloatCompare) -> bool {
    match compare {
        FloatCompare::Exact => observed.to_bits() == target.to_bits(),
        FloatCompare::Tolerance { .. } => {
            float_matches(f64::from(observed), f64::from(target), compare)
        }
    }
}

pub fn float_class(value: f64) -> FloatClass {
    if value.is_nan() {
        FloatClass::Nan
    } else if value.is_infinite() && value.is_sign_negative() {
        FloatClass::NegativeInfinity
    } else if value.is_infinite() {
        FloatClass::Infinity
    } else {
        FloatClass::Finite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH64: PointerWidth = PointerWidth::Eight;
    const WIDTH32: PointerWidth = PointerWidth::Four;

    fn int_of(decoded: &Decoded) -> i64 {
        match decoded {
            Decoded::Int { value } => value.0,
            other => panic!("expected an int, got {other:?}"),
        }
    }

    fn uint_of(decoded: &Decoded) -> u64 {
        match decoded {
            Decoded::Uint { value } => value.0,
            other => panic!("expected a uint, got {other:?}"),
        }
    }

    fn float_of(decoded: &Decoded) -> FloatValue {
        match decoded {
            Decoded::Float { value } => value.clone(),
            other => panic!("expected a float, got {other:?}"),
        }
    }

    #[test]
    fn every_signed_limit_decodes_from_its_little_endian_bytes() {
        let cases: &[(ValueType, &[u8], i64)] = &[
            (ValueType::Int8, &[0x80], i64::from(i8::MIN)),
            (ValueType::Int8, &[0x7f], i64::from(i8::MAX)),
            (ValueType::Int16, &[0x00, 0x80], i64::from(i16::MIN)),
            (ValueType::Int16, &[0xff, 0x7f], i64::from(i16::MAX)),
            (
                ValueType::Int32,
                &[0x00, 0x00, 0x00, 0x80],
                i64::from(i32::MIN),
            ),
            (
                ValueType::Int32,
                &[0xff, 0xff, 0xff, 0x7f],
                i64::from(i32::MAX),
            ),
            (
                ValueType::Int64,
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
                i64::MIN,
            ),
            (
                ValueType::Int64,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
                i64::MAX,
            ),
        ];
        for (value_type, bytes, expected) in cases {
            let decoded = decode_scalar(*value_type, bytes, WIDTH64, "test").expect("decode");
            assert_eq!(int_of(&decoded), *expected, "{}", value_type.as_str());
        }
    }

    #[test]
    fn every_unsigned_limit_decodes_from_its_little_endian_bytes() {
        let cases: &[(ValueType, &[u8], u64)] = &[
            (ValueType::Uint8, &[0x00], 0),
            (ValueType::Uint8, &[0xff], u64::from(u8::MAX)),
            (ValueType::Uint16, &[0xff, 0xff], u64::from(u16::MAX)),
            (
                ValueType::Uint32,
                &[0xff, 0xff, 0xff, 0xff],
                u64::from(u32::MAX),
            ),
            (
                ValueType::Uint64,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                u64::MAX,
            ),
        ];
        for (value_type, bytes, expected) in cases {
            let decoded = decode_scalar(*value_type, bytes, WIDTH64, "test").expect("decode");
            assert_eq!(uint_of(&decoded), *expected, "{}", value_type.as_str());
        }
    }

    #[test]
    fn a_sixty_four_bit_value_survives_serialisation_as_a_decimal_string() {
        let decoded = decode_scalar(
            ValueType::Uint64,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            WIDTH64,
            "test",
        )
        .expect("decode");
        let json = serde_json::to_value(&decoded).expect("serialise");
        assert_eq!(json["value"], "18446744073709551615");
    }

    #[test]
    fn decoding_is_little_endian_not_native_guesswork() {
        let decoded = decode_scalar(
            ValueType::Uint32,
            &[0x01, 0x02, 0x03, 0x04],
            WIDTH64,
            "test",
        )
        .unwrap();
        assert_eq!(uint_of(&decoded), 0x0403_0201);
    }

    #[test]
    fn a_scalar_short_of_its_bytes_is_a_partial_read_not_a_zero_fill() {
        let err = decode_scalar(ValueType::Int32, &[0x01, 0x02], WIDTH64, "read_memory")
            .expect_err("three bytes cannot make an int32");
        assert_eq!(err.code, ErrorCode::PartialRead);
    }

    #[test]
    fn a_pointer_decodes_at_the_targets_width_and_ignores_neighbouring_bytes() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0xde, 0xad, 0xbe, 0xef];
        let wide = decode_scalar(ValueType::Pointer, &bytes, WIDTH64, "test").unwrap();
        let narrow = decode_scalar(ValueType::Pointer, &bytes, WIDTH32, "test").unwrap();
        match (&wide, &narrow) {
            (
                Decoded::Pointer {
                    raw_value: w,
                    value: wv,
                },
                Decoded::Pointer {
                    raw_value: n,
                    value: nv,
                },
            ) => {
                assert_eq!(w.0, 0xefbe_adde_4433_2211);
                assert_eq!(n.0, 0x4433_2211);
                assert_eq!(wv, "0xefbeadde44332211");
                assert_eq!(nv, "0x44332211");
            }
            other => panic!("expected two pointers, got {other:?}"),
        }
    }

    #[test]
    fn binary32_one_tenth_decodes_to_its_exact_wire_bytes() {
        let decoded =
            decode_scalar(ValueType::Float, &[0xcd, 0xcc, 0xcc, 0x3d], WIDTH64, "test").unwrap();
        let value = float_of(&decoded);
        assert_eq!(value.class, FloatClass::Finite);
        assert_eq!(value.repr, "0.1");
        assert_eq!(value.repr.parse::<f32>().unwrap(), 0.1f32);
    }

    #[test]
    fn non_finite_floats_decode_to_tagged_classes_with_no_json_number() {
        let nan = float_of(
            &decode_scalar(ValueType::Float, &f32::NAN.to_le_bytes(), WIDTH64, "t").unwrap(),
        );
        assert_eq!(nan.class, FloatClass::Nan);
        assert!(nan.value.is_none());

        let inf = float_of(
            &decode_scalar(
                ValueType::Double,
                &f64::INFINITY.to_le_bytes(),
                WIDTH64,
                "t",
            )
            .unwrap(),
        );
        assert_eq!(inf.class, FloatClass::Infinity);
        assert!(inf.value.is_none());

        let neg = float_of(
            &decode_scalar(
                ValueType::Double,
                &f64::NEG_INFINITY.to_le_bytes(),
                WIDTH64,
                "t",
            )
            .unwrap(),
        );
        assert_eq!(neg.class, FloatClass::NegativeInfinity);
    }

    #[test]
    fn negative_zero_decodes_distinguishably_from_positive_zero() {
        let neg = float_of(
            &decode_scalar(ValueType::Float, &(-0.0f32).to_le_bytes(), WIDTH64, "t").unwrap(),
        );
        let pos = float_of(
            &decode_scalar(ValueType::Float, &0.0f32.to_le_bytes(), WIDTH64, "t").unwrap(),
        );
        assert!(neg.negative_zero);
        assert!(!pos.negative_zero);
    }

    #[test]
    fn exact_float_comparison_is_bitwise_so_signed_zero_and_nan_behave() {
        assert!(float_matches(0.0, 0.0, FloatCompare::Exact));
        assert!(!float_matches(-0.0, 0.0, FloatCompare::Exact));
        assert!(float_matches(f64::NAN, f64::NAN, FloatCompare::Exact));
        assert!(!float_matches(1.0, 1.0 + f64::EPSILON, FloatCompare::Exact));
    }

    #[test]
    fn infinity_does_not_match_every_value_under_tolerance() {
        let tol = FloatCompare::Tolerance {
            relative: DEFAULT_FLOAT_REL_TOL,
            absolute: DEFAULT_FLOAT_ABS_TOL,
        };
        assert!(!float_matches(1.0, f64::INFINITY, tol));
        assert!(!float_matches(1e300, f64::INFINITY, tol));
        assert!(float_matches(f64::INFINITY, f64::INFINITY, tol));
        assert!(!float_matches(f64::NEG_INFINITY, f64::INFINITY, tol));
        assert!(!float_matches(f64::INFINITY, 1.0, tol));
    }

    #[test]
    fn nan_never_matches_under_tolerance() {
        let tol = FloatCompare::Tolerance {
            relative: DEFAULT_FLOAT_REL_TOL,
            absolute: DEFAULT_FLOAT_ABS_TOL,
        };
        assert!(!float_matches(f64::NAN, f64::NAN, tol));
        assert!(!float_matches(f64::NAN, 1.0, tol));
        assert!(!float_matches(1.0, f64::NAN, tol));
    }

    #[test]
    fn tolerance_comparison_accepts_a_representable_neighbour() {
        let tol = FloatCompare::Tolerance {
            relative: DEFAULT_FLOAT_REL_TOL,
            absolute: DEFAULT_FLOAT_ABS_TOL,
        };
        assert!(float32_matches(0.1f32, 0.1f32, tol));
        assert!(float_matches(f64::from(0.1f32), 0.1f64, tol));
        assert!(!float_matches(0.2, 0.1, tol));
    }

    #[test]
    fn a_terminated_utf8_string_reports_its_terminator_and_consumed_bytes() {
        let bytes = b"memscope-utf8\0\xff\xff";
        let value = decode_utf8(bytes, None);
        assert_eq!(value.text.as_deref(), Some("memscope-utf8"));
        assert!(value.terminator_found);
        assert_eq!(value.bytes_consumed, 14);
        assert!(!value.output_truncated);
        assert!(value.decode_error.is_none());
    }

    #[test]
    fn a_missing_terminator_is_distinguished_from_output_truncation() {
        let unterminated = decode_utf8(b"no-terminator", None);
        assert!(!unterminated.terminator_found);
        assert!(!unterminated.output_truncated);
        assert_eq!(unterminated.bytes_consumed, 13);

        let truncated = decode_utf8(b"no-terminator\0", Some(4));
        assert!(truncated.terminator_found);
        assert!(truncated.output_truncated);
        assert_eq!(truncated.text.as_deref(), Some("no-t"));
    }

    #[test]
    fn invalid_utf8_reports_a_decode_error_and_keeps_the_raw_bytes_available() {
        let value = decode_utf8(&[0x48, 0x69, 0xff, 0xfe, 0x00], None);
        assert!(value.text.is_none());
        let error = value.decode_error.expect("a decode error");
        assert!(error.contains("invalid UTF-8"), "got {error}");
        assert!(value.terminator_found);
        assert_eq!(value.bytes_consumed, 5);
    }

    #[test]
    fn a_utf16_terminator_is_only_recognised_on_a_code_unit_boundary() {
        let mut bytes = Vec::new();
        for unit in "memscope-utf16".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x00, 0x00]);
        let value = decode_utf16le(&bytes, None);
        assert_eq!(value.text.as_deref(), Some("memscope-utf16"));
        assert!(value.terminator_found);
        assert_eq!(value.bytes_consumed, 30);
    }

    #[test]
    fn a_lone_utf16_surrogate_is_a_decode_error_not_a_silent_replacement() {
        let value = decode_utf16le(&[0x00, 0xd8, 0x41, 0x00, 0x00, 0x00], None);
        assert!(value.text.is_none());
        assert!(value.decode_error.is_some());
        assert!(value.terminator_found);
        assert_eq!(value.bytes_consumed, 6);
    }

    #[test]
    fn an_odd_trailing_byte_in_a_utf16_read_is_reported() {
        let value = decode_utf16le(&[0x41, 0x00, 0x42], None);
        assert_eq!(value.text.as_deref(), Some("A"));
        assert!(!value.terminator_found);
        let error = value.decode_error.expect("the odd byte must be reported");
        assert!(error.contains("whole UTF-16 code unit"), "got {error}");
    }

    #[test]
    fn an_unterminated_utf16_string_consumes_only_whole_code_units() {
        let mut bytes = Vec::new();
        for unit in "no-term".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let value = decode_utf16le(&bytes, None);
        assert_eq!(value.text.as_deref(), Some("no-term\u{ffff}\u{ffff}"));
        assert!(!value.terminator_found);
    }

    #[test]
    fn type_sizes_follow_the_targets_pointer_width() {
        assert_eq!(ValueType::Pointer.size_for(WIDTH64), Some(8));
        assert_eq!(ValueType::Pointer.size_for(WIDTH32), Some(4));
        assert_eq!(ValueType::Int32.size_for(WIDTH32), Some(4));
        assert_eq!(ValueType::String.size_for(WIDTH64), None);
    }

    #[test]
    fn a_zero_or_oversized_length_is_an_argument_error() {
        assert_eq!(
            check_length(0, 100, "read_bytes", "read_bytes")
                .expect_err("zero")
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            check_length(101, 100, "read_bytes", "read_bytes")
                .expect_err("over")
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(check_length(100, 100, "read_bytes", "read_bytes").is_ok());
    }
}
