use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};

use crate::error::{ErrorCode, OperationError, Result};
use crate::kernel;
use crate::mem::{self, FloatCompare, PAGE_SIZE, SessionRef, ValueType};
use crate::ptr::{self, ModuleInfo};
use crate::win;
use crate::wire::{Address, WireI64, WireU64, hex, parse_hex_bytes};

pub const DEFAULT_DISPLAY_LIMIT: usize = 100;
pub const MAX_DISPLAY_LIMIT: usize = 10_000;
pub const DEFAULT_MAX_RESULTS: usize = 1_000_000;
pub const MAX_MAX_RESULTS: usize = 50_000_000;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_MAX_BYTES_SCANNED: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const MAX_TIMEOUT_MS: u64 = 600_000;
pub const CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_PATTERN_BYTES: usize = 4096;
const CHECKPOINT_CHUNKS: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionState {
    Commit,
    Reserve,
    Free,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    Image,
    Mapped,
    Private,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    NotCommitted,
    NoAccess,
    GuardPage,
    NotReadable,
    ZeroSize,
    OutsideAddressRange,
    ExcludedRegionKind,
    ExcludedProtection,
    BeyondPointerWidth,
}

impl ExclusionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCommitted => "not_committed",
            Self::NoAccess => "no_access",
            Self::GuardPage => "guard_page",
            Self::NotReadable => "not_readable",
            Self::ZeroSize => "zero_size",
            Self::OutsideAddressRange => "outside_address_range",
            Self::ExcludedRegionKind => "excluded_region_kind",
            Self::ExcludedProtection => "excluded_protection",
            Self::BeyondPointerWidth => "beyond_pointer_width",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub base: String,
    pub base_raw: WireU64,
    pub size: WireU64,
    pub end_raw: WireU64,
    pub state: RegionState,
    pub kind: RegionKind,
    pub protection: String,
    pub protection_raw: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub eligible: bool,
    pub exclusions: Vec<ExclusionReason>,
}

fn protection_name(flags: u32) -> String {
    let base = flags & 0xFF;
    let mut name = match PAGE_PROTECTION_FLAGS(base) {
        PAGE_NOACCESS => "PAGE_NOACCESS",
        PAGE_READONLY => "PAGE_READONLY",
        PAGE_READWRITE => "PAGE_READWRITE",
        PAGE_WRITECOPY => "PAGE_WRITECOPY",
        PAGE_EXECUTE => "PAGE_EXECUTE",
        PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
        PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
        _ => "PAGE_UNKNOWN",
    }
    .to_owned();
    if flags & PAGE_GUARD.0 != 0 {
        name.push_str("|PAGE_GUARD");
    }
    if flags & 0x200 != 0 {
        name.push_str("|PAGE_NOCACHE");
    }
    if flags & 0x400 != 0 {
        name.push_str("|PAGE_WRITECOMBINE");
    }
    name
}

fn protection_is_readable(flags: u32) -> bool {
    if flags & PAGE_GUARD.0 != 0 {
        return false;
    }
    matches!(
        PAGE_PROTECTION_FLAGS(flags & 0xFF),
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegionFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_address: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<RegionKind>,
    #[serde(default)]
    pub writable_only: bool,
    #[serde(default)]
    pub include_images: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedFilter {
    min: u64,
    max: u64,
    kinds: Option<[bool; 3]>,
    writable_only: bool,
    include_images: bool,
}

impl RegionFilter {
    fn resolve(&self, session: &SessionRef, operation: &str) -> Result<ResolvedFilter> {
        let min = match &self.min_address {
            Some(text) => Address::parse_hex(text, operation)?.0,
            None => 0,
        };
        let max = match &self.max_address {
            Some(text) => Address::parse_hex(text, operation)?.0,
            None => session.width.max_address(),
        };
        if min > max {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("min_address 0x{min:x} is above max_address 0x{max:x}"),
            )
            .with_next_step("Swap the bounds so the range is non-empty."));
        }
        let kinds = if self.kinds.is_empty() {
            None
        } else {
            let mut flags = [false; 3];
            for kind in &self.kinds {
                match kind {
                    RegionKind::Image => flags[0] = true,
                    RegionKind::Mapped => flags[1] = true,
                    RegionKind::Private => flags[2] = true,
                    RegionKind::Unknown => {}
                }
            }
            Some(flags)
        };
        Ok(ResolvedFilter {
            min,
            max: max.min(session.width.max_address()),
            kinds,
            writable_only: self.writable_only,
            include_images: self.include_images,
        })
    }

    fn allows_kind(filter: &ResolvedFilter, kind: RegionKind) -> bool {
        match filter.kinds {
            Some(flags) => match kind {
                RegionKind::Image => flags[0],
                RegionKind::Mapped => flags[1],
                RegionKind::Private => flags[2],
                RegionKind::Unknown => false,
            },
            None => kind != RegionKind::Image || filter.include_images,
        }
    }
}

pub fn list_regions(
    session: &SessionRef,
    filter: &RegionFilter,
    operation: &str,
) -> Result<Vec<RegionInfo>> {
    let resolved = filter.resolve(session, operation)?;
    let modules = ptr::list_modules(session, operation).unwrap_or_default();
    enumerate_regions(session, &resolved, &modules, operation)
}

fn enumerate_regions(
    session: &SessionRef,
    filter: &ResolvedFilter,
    modules: &[ModuleInfo],
    operation: &str,
) -> Result<Vec<RegionInfo>> {
    let limit = session.width.max_address();
    let mut address: u64 = 0;
    let mut regions = Vec::new();
    let mut queries_failed = 0u32;

    loop {
        if address > limit {
            break;
        }
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                session.handle,
                Some(address as *const core::ffi::c_void),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            queries_failed += 1;
            if queries_failed > 4 {
                break;
            }
            let next = address.saturating_add(PAGE_SIZE as u64);
            if next <= address {
                break;
            }
            address = next;
            continue;
        }
        queries_failed = 0;

        let base_raw = info.BaseAddress as u64;
        let size = info.RegionSize as u64;
        let state = if info.State == MEM_COMMIT {
            RegionState::Commit
        } else if info.State == MEM_RESERVE {
            RegionState::Reserve
        } else if info.State == MEM_FREE {
            RegionState::Free
        } else {
            RegionState::Unknown
        };
        let kind = if info.Type == MEM_IMAGE {
            RegionKind::Image
        } else if info.Type == MEM_MAPPED {
            RegionKind::Mapped
        } else if info.Type == MEM_PRIVATE {
            RegionKind::Private
        } else {
            RegionKind::Unknown
        };
        let protection_raw = info.Protect.0;

        let mut exclusions = Vec::new();
        if size == 0 {
            exclusions.push(ExclusionReason::ZeroSize);
        }
        if state != RegionState::Commit {
            exclusions.push(ExclusionReason::NotCommitted);
        }
        if protection_raw & PAGE_GUARD.0 != 0 {
            exclusions.push(ExclusionReason::GuardPage);
        }
        if PAGE_PROTECTION_FLAGS(protection_raw & 0xFF) == PAGE_NOACCESS {
            exclusions.push(ExclusionReason::NoAccess);
        } else if state == RegionState::Commit && !protection_is_readable(protection_raw) {
            exclusions.push(ExclusionReason::NotReadable);
        }
        let end_raw = base_raw.saturating_add(size);
        if end_raw <= filter.min || base_raw > filter.max {
            exclusions.push(ExclusionReason::OutsideAddressRange);
        }
        if base_raw > session.width.max_address() {
            exclusions.push(ExclusionReason::BeyondPointerWidth);
        }
        if !RegionFilter::allows_kind(filter, kind) {
            exclusions.push(ExclusionReason::ExcludedRegionKind);
        }
        if filter.writable_only
            && !matches!(
                PAGE_PROTECTION_FLAGS(protection_raw & 0xFF),
                PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
        {
            exclusions.push(ExclusionReason::ExcludedProtection);
        }

        regions.push(RegionInfo {
            base: Address(base_raw).to_canonical(session.width),
            base_raw: WireU64(base_raw),
            size: WireU64(size),
            end_raw: WireU64(end_raw),
            state,
            kind,
            protection: protection_name(protection_raw),
            protection_raw,
            module: ptr::module_for(modules, base_raw).map(|m| m.name.clone()),
            eligible: exclusions.is_empty(),
            exclusions,
        });

        let next = base_raw.saturating_add(size.max(PAGE_SIZE as u64));
        if next <= address {
            break;
        }
        address = next;
    }

    if regions.is_empty() {
        let code = win::last_error();
        return Err(win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!(
                "no memory regions could be enumerated for pid {}",
                session.pid
            ),
            code,
        )
        .with_session(&session.id)
        .with_pid(session.pid));
    }
    Ok(regions)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Needle {
    Int { value: WireI64 },
    Uint { value: WireU64 },
    Float { value: f64 },
    Bytes { hex: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<bool>,
}

impl BytePattern {
    pub fn parse(text: &str, operation: &str) -> Result<Self> {
        let cleaned: String = text
            .trim()
            .chars()
            .filter(|c| !matches!(c, ' ' | '_' | '-'))
            .collect();
        if cleaned.is_empty() {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "the byte pattern is empty",
            )
            .with_next_step("Supply a pattern such as \"cd ?? cc 3d\"."));
        }
        if !cleaned.len().is_multiple_of(2) {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "the byte pattern has {} characters, which is not whole bytes",
                    cleaned.len()
                ),
            )
            .with_next_step("Each byte is two characters: a hex pair, or \"??\" for any byte."));
        }
        let chars: Vec<char> = cleaned.chars().collect();
        let mut bytes = Vec::with_capacity(chars.len() / 2);
        let mut mask = Vec::with_capacity(chars.len() / 2);
        for pair in chars.chunks(2) {
            if pair[0] == '?' && pair[1] == '?' {
                bytes.push(0);
                mask.push(false);
                continue;
            }
            if pair[0] == '?' || pair[1] == '?' {
                return Err(OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!(
                        "half-wildcard byte {:?} is not supported",
                        pair.iter().collect::<String>()
                    ),
                )
                .with_next_step(
                    "Use \"??\" for a whole wildcard byte; nibble wildcards are not supported.",
                ));
            }
            let text: String = pair.iter().collect();
            let value = u8::from_str_radix(&text, 16).map_err(|_| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("{text:?} is not a hex byte or a wildcard"),
                )
            })?;
            bytes.push(value);
            mask.push(true);
        }
        if bytes.len() > MAX_PATTERN_BYTES {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "the byte pattern is {} bytes, over the {MAX_PATTERN_BYTES}-byte limit",
                    bytes.len()
                ),
            ));
        }
        if !mask.iter().any(|m| *m) {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "the byte pattern is all wildcards and would match every address",
            )
            .with_next_step("Include at least one concrete byte."));
        }
        Ok(Self { bytes, mask })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > haystack.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(&self.mask)
            .enumerate()
            .all(|(i, (byte, must))| !*must || haystack[offset + i] == *byte)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Exact,
    NotEqual,
    GreaterThan,
    LessThan,
    Between,
    Unknown,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,
    DecreasedBy,
    Pattern,
}

impl Operator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::NotEqual => "not_equal",
            Self::GreaterThan => "greater_than",
            Self::LessThan => "less_than",
            Self::Between => "between",
            Self::Unknown => "unknown",
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::Increased => "increased",
            Self::Decreased => "decreased",
            Self::IncreasedBy => "increased_by",
            Self::DecreasedBy => "decreased_by",
            Self::Pattern => "pattern",
        }
    }

    pub const fn needs_previous(self) -> bool {
        matches!(
            self,
            Self::Changed
                | Self::Unchanged
                | Self::Increased
                | Self::Decreased
                | Self::IncreasedBy
                | Self::DecreasedBy
        )
    }

    pub const fn is_first_scan_operator(self) -> bool {
        matches!(
            self,
            Self::Exact
                | Self::NotEqual
                | Self::GreaterThan
                | Self::LessThan
                | Self::Between
                | Self::Unknown
                | Self::Pattern
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericClass {
    SignedInteger,
    UnsignedInteger,
    Float,
    Opaque,
}

pub fn numeric_class(value_type: ValueType) -> NumericClass {
    match value_type {
        ValueType::Int8 | ValueType::Int16 | ValueType::Int32 | ValueType::Int64 => {
            NumericClass::SignedInteger
        }
        ValueType::Uint8
        | ValueType::Uint16
        | ValueType::Uint32
        | ValueType::Uint64
        | ValueType::Pointer => NumericClass::UnsignedInteger,
        ValueType::Float | ValueType::Double => NumericClass::Float,
        ValueType::String | ValueType::String16 | ValueType::Bytes => NumericClass::Opaque,
    }
}

pub fn validate_pair(value_type: ValueType, operator: Operator, operation: &str) -> Result<()> {
    let class = numeric_class(value_type);
    let ok = match operator {
        Operator::Pattern => class == NumericClass::Opaque,
        Operator::Exact | Operator::NotEqual | Operator::Changed | Operator::Unchanged => {
            class != NumericClass::Opaque
        }
        Operator::Unknown => class != NumericClass::Opaque,
        Operator::GreaterThan
        | Operator::LessThan
        | Operator::Between
        | Operator::Increased
        | Operator::Decreased
        | Operator::IncreasedBy
        | Operator::DecreasedBy => matches!(
            class,
            NumericClass::SignedInteger | NumericClass::UnsignedInteger | NumericClass::Float
        ),
    };
    if ok {
        return Ok(());
    }
    Err(OperationError::new(
        ErrorCode::InvalidArgument,
        operation,
        format!(
            "operator {} is not defined for type {}",
            operator.as_str(),
            value_type.as_str()
        ),
    )
    .with_next_step(match operator {
        Operator::Pattern => "Use the pattern operator with the bytes type.",
        _ => "Use a numeric type for ordering and delta comparisons.",
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegerOverflow {
    Saturate,
    Reject,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSource {
    #[default]
    PreviousScan,
    InitialBaseline,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScanBudget {
    pub display_limit: usize,
    pub max_results: usize,
    pub max_snapshot_bytes: usize,
    pub max_bytes_scanned: u64,
    pub timeout_ms: u64,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            display_limit: DEFAULT_DISPLAY_LIMIT,
            max_results: DEFAULT_MAX_RESULTS,
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
            max_bytes_scanned: DEFAULT_MAX_BYTES_SCANNED,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl ScanBudget {
    pub fn validate(&self, operation: &str) -> Result<()> {
        if self.display_limit == 0 || self.display_limit > MAX_DISPLAY_LIMIT {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "display_limit {} must be between 1 and {MAX_DISPLAY_LIMIT}",
                    self.display_limit
                ),
            ));
        }
        if self.max_results == 0 || self.max_results > MAX_MAX_RESULTS {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "max_results {} must be between 1 and {MAX_MAX_RESULTS}",
                    self.max_results
                ),
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "timeout_ms {} must be between 1 and {MAX_TIMEOUT_MS}",
                    self.timeout_ms
                ),
            ));
        }
        if self.max_bytes_scanned == 0 {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "max_bytes_scanned must be at least 1",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    MaxResults,
    MaxBytesScanned,
    MaxSnapshotBytes,
    Timeout,
    Cancelled,
}

impl StopReason {
    pub const fn truncates(self) -> bool {
        !matches!(self, Self::Completed)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub regions_eligible: usize,
    pub regions_visited: usize,
    pub bytes_eligible: WireU64,
    pub bytes_visited: WireU64,
    pub bytes_unreadable: WireU64,
    pub slots_examined: WireU64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanTiming {
    pub total_us: WireU64,
    pub region_enum_us: WireU64,
    pub capture_us: WireU64,
    pub compare_us: WireU64,
    pub materialise_us: WireU64,
    pub policy_us: WireU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateView {
    pub address: String,
    pub address_raw: WireU64,
    pub captured_raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_decoded: Option<mem::Decoded>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub scan_id: String,
    pub generation: WireU64,
    pub session_id: String,
    pub value_type: ValueType,
    pub operator: Operator,
    pub baseline_source: BaselineSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compared_against_scan_id: Option<String>,
    pub retained: usize,
    pub displayed: Vec<CandidateView>,
    pub display_offset: usize,
    pub total_matches_known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_matches: Option<WireU64>,
    pub truncated: bool,
    pub stop_reason: StopReason,
    pub coverage: Coverage,
    pub timing: ScanTiming,
    pub consistency: mem::ConsistencyMode,
    pub values_are_from_capture: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_slot_count: Option<WireU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_valid_slots: Option<WireU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_bytes: Option<WireU64>,
}

#[derive(Debug, Clone)]
pub struct CandidateStore {
    pub value_type: ValueType,
    pub item_size: usize,
    pub addresses: Vec<u64>,
    pub values: Vec<u8>,
}

impl CandidateStore {
    fn new(value_type: ValueType, item_size: usize) -> Self {
        Self {
            value_type,
            item_size,
            addresses: Vec::new(),
            values: Vec::new(),
        }
    }

    fn push(&mut self, address: u64, bytes: &[u8]) {
        self.addresses.push(address);
        self.values.extend_from_slice(bytes);
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn value_at(&self, index: usize) -> &[u8] {
        let start = index * self.item_size;
        &self.values[start..start + self.item_size]
    }

    pub fn memory_bytes(&self) -> usize {
        self.addresses.len() * size_of::<u64>() + self.values.len()
    }
}

#[derive(Debug, Clone)]
pub struct BaselineChunk {
    pub base: u64,
    pub bytes: Vec<u8>,
    pub valid_pages: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct Baseline {
    pub id: String,
    pub value_type: ValueType,
    pub item_size: usize,
    pub chunks: Vec<BaselineChunk>,
    pub total_bytes: usize,
    pub slot_count: u64,
    pub valid_slots: u64,
}

impl Baseline {
    fn value_at(&self, address: u64) -> Option<&[u8]> {
        for chunk in &self.chunks {
            let end = chunk.base + chunk.bytes.len() as u64;
            if address >= chunk.base && address + self.item_size as u64 <= end {
                let offset = (address - chunk.base) as usize;
                let first_page = offset / PAGE_SIZE;
                let last_page = (offset + self.item_size - 1) / PAGE_SIZE;
                for page in first_page..=last_page {
                    if !chunk.valid_pages.get(page).copied().unwrap_or(false) {
                        return None;
                    }
                }
                return Some(&chunk.bytes[offset..offset + self.item_size]);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct ScanState {
    pub scan_id: String,
    pub generation: u64,
    pub session_id: String,
    pub value_type: ValueType,
    pub item_size: usize,
    pub candidates: CandidateStore,
    pub initial_baseline: Option<Arc<Baseline>>,
    pub previous_values: Option<CandidateStore>,
    pub last_outcome: Option<ScanOutcome>,
    pub truncated: bool,
}

static SCAN_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_id(prefix: &str) -> String {
    let n = SCAN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{n}")
}

#[derive(Debug, Clone)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FirstScanRequest {
    pub value_type: ValueType,
    pub operator: Operator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needle: Option<Needle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needle_high: Option<Needle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default)]
    pub filter: RegionFilter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    #[serde(default)]
    pub budget: ScanBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_compare: Option<FloatCompare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NextScanRequest {
    pub operator: Operator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needle: Option<Needle>,
    #[serde(default)]
    pub baseline_source: BaselineSource,
    #[serde(default)]
    pub budget: ScanBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_compare: Option<FloatCompare>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integer_overflow: Option<IntegerOverflow>,
}

#[derive(Debug, Clone, Copy)]
enum Target {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

fn needle_to_target(needle: &Needle, value_type: ValueType, operation: &str) -> Result<Target> {
    let class = numeric_class(value_type);
    match (needle, class) {
        (Needle::Int { value }, NumericClass::SignedInteger) => Ok(Target::Signed(value.0)),
        (Needle::Int { value }, NumericClass::UnsignedInteger) => {
            u64::try_from(value.0).map(Target::Unsigned).map_err(|_| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("{} is negative and cannot be an unsigned target", value.0),
                )
            })
        }
        (Needle::Uint { value }, NumericClass::UnsignedInteger) => Ok(Target::Unsigned(value.0)),
        (Needle::Uint { value }, NumericClass::SignedInteger) => {
            i64::try_from(value.0).map(Target::Signed).map_err(|_| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("{} does not fit in a signed 64-bit target", value.0),
                )
            })
        }
        (Needle::Float { value }, NumericClass::Float) => Ok(Target::Float(*value)),
        (Needle::Int { value }, NumericClass::Float) => Ok(Target::Float(value.0 as f64)),
        (Needle::Uint { value }, NumericClass::Float) => Ok(Target::Float(value.0 as f64)),
        _ => Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "the supplied value does not match type {}",
                value_type.as_str()
            ),
        )),
    }
}

fn read_slot(value_type: ValueType, bytes: &[u8]) -> Option<Target> {
    Some(match value_type {
        ValueType::Int8 => Target::Signed(i64::from(i8::from_le_bytes([bytes[0]]))),
        ValueType::Int16 => Target::Signed(i64::from(i16::from_le_bytes([bytes[0], bytes[1]]))),
        ValueType::Int32 => Target::Signed(i64::from(i32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        ValueType::Int64 => Target::Signed(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        ValueType::Uint8 => Target::Unsigned(u64::from(bytes[0])),
        ValueType::Uint16 => Target::Unsigned(u64::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
        ValueType::Uint32 => Target::Unsigned(u64::from(u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        ValueType::Uint64 | ValueType::Pointer => {
            if bytes.len() == 4 {
                Target::Unsigned(u64::from(u32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            } else {
                Target::Unsigned(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
        }
        ValueType::Float => Target::Float(f64::from(f32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        ValueType::Double => Target::Float(f64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        ValueType::String | ValueType::String16 | ValueType::Bytes => return None,
    })
}

fn compare_first(
    observed: Target,
    operator: Operator,
    low: Target,
    high: Option<Target>,
    float_compare: FloatCompare,
) -> bool {
    match (observed, low) {
        (Target::Signed(o), Target::Signed(t)) => match operator {
            Operator::Exact => o == t,
            Operator::NotEqual => o != t,
            Operator::GreaterThan => o > t,
            Operator::LessThan => o < t,
            Operator::Between => match high {
                Some(Target::Signed(h)) => o >= t && o <= h,
                _ => false,
            },
            _ => false,
        },
        (Target::Unsigned(o), Target::Unsigned(t)) => match operator {
            Operator::Exact => o == t,
            Operator::NotEqual => o != t,
            Operator::GreaterThan => o > t,
            Operator::LessThan => o < t,
            Operator::Between => match high {
                Some(Target::Unsigned(h)) => o >= t && o <= h,
                _ => false,
            },
            _ => false,
        },
        (Target::Float(o), Target::Float(t)) => match operator {
            Operator::Exact => mem::float_matches(o, t, float_compare),
            Operator::NotEqual => !mem::float_matches(o, t, float_compare),
            Operator::GreaterThan => o.is_finite() && t.is_finite() && o > t,
            Operator::LessThan => o.is_finite() && t.is_finite() && o < t,
            Operator::Between => match high {
                Some(Target::Float(h)) => o.is_finite() && o >= t && o <= h,
                _ => false,
            },
            _ => false,
        },
        _ => false,
    }
}

fn compare_delta(
    now: Target,
    before: Target,
    operator: Operator,
    delta: Option<Target>,
    float_compare: FloatCompare,
    overflow: IntegerOverflow,
) -> Option<bool> {
    match (now, before) {
        (Target::Signed(n), Target::Signed(b)) => Some(match operator {
            Operator::Changed => n != b,
            Operator::Unchanged => n == b,
            Operator::Increased => n > b,
            Operator::Decreased => n < b,
            Operator::IncreasedBy | Operator::DecreasedBy => {
                let Some(Target::Signed(d)) = delta else {
                    return Some(false);
                };
                let wanted = if operator == Operator::IncreasedBy {
                    b.checked_add(d)
                } else {
                    b.checked_sub(d)
                };
                match (wanted, overflow) {
                    (Some(w), _) => n == w,
                    (None, IntegerOverflow::Saturate) => {
                        let w = if operator == Operator::IncreasedBy {
                            b.saturating_add(d)
                        } else {
                            b.saturating_sub(d)
                        };
                        n == w
                    }
                    (None, IntegerOverflow::Reject) => return None,
                }
            }
            _ => false,
        }),
        (Target::Unsigned(n), Target::Unsigned(b)) => Some(match operator {
            Operator::Changed => n != b,
            Operator::Unchanged => n == b,
            Operator::Increased => n > b,
            Operator::Decreased => n < b,
            Operator::IncreasedBy | Operator::DecreasedBy => {
                let d = match delta {
                    Some(Target::Unsigned(d)) => d,
                    Some(Target::Signed(d)) if d >= 0 => d as u64,
                    _ => return Some(false),
                };
                let wanted = if operator == Operator::IncreasedBy {
                    b.checked_add(d)
                } else {
                    b.checked_sub(d)
                };
                match (wanted, overflow) {
                    (Some(w), _) => n == w,
                    (None, IntegerOverflow::Saturate) => {
                        let w = if operator == Operator::IncreasedBy {
                            b.saturating_add(d)
                        } else {
                            b.saturating_sub(d)
                        };
                        n == w
                    }
                    (None, IntegerOverflow::Reject) => return None,
                }
            }
            _ => false,
        }),
        (Target::Float(n), Target::Float(b)) => Some(match operator {
            Operator::Changed => !mem::float_matches(n, b, float_compare),
            Operator::Unchanged => mem::float_matches(n, b, float_compare),
            Operator::Increased => n.is_finite() && b.is_finite() && n > b,
            Operator::Decreased => n.is_finite() && b.is_finite() && n < b,
            Operator::IncreasedBy | Operator::DecreasedBy => {
                let Some(Target::Float(d)) = delta else {
                    return Some(false);
                };
                let wanted = if operator == Operator::IncreasedBy {
                    b + d
                } else {
                    b - d
                };
                mem::float_matches(n, wanted, float_compare)
            }
            _ => false,
        }),
        _ => Some(false),
    }
}

enum FastPath {
    Exact4([u8; 4]),
    Exact8([u8; 8]),
    Bytes(Vec<u8>),
    Pattern { bytes: Vec<u8>, mask: Vec<bool> },
}

fn encode_target(target: Target, item_size: usize) -> Option<Vec<u8>> {
    match (target, item_size) {
        (Target::Signed(v), 4) => i32::try_from(v).ok().map(|n| n.to_le_bytes().to_vec()),
        (Target::Signed(v), 8) => Some(v.to_le_bytes().to_vec()),
        (Target::Unsigned(v), 4) => u32::try_from(v).ok().map(|n| n.to_le_bytes().to_vec()),
        (Target::Unsigned(v), 8) => Some(v.to_le_bytes().to_vec()),
        (Target::Float(v), 4) => Some((v as f32).to_le_bytes().to_vec()),
        (Target::Float(v), 8) => Some(v.to_le_bytes().to_vec()),
        _ => None,
    }
}

struct Sweep {
    budget: ScanBudget,
    started: Instant,
    deadline: Duration,
    bytes_visited: u64,
    cancel: Cancel,
    chunks_done: u32,
    capture_us: u64,
    compare_us: u64,
}

impl Sweep {
    fn new(budget: &ScanBudget, cancel: Cancel) -> Self {
        Self {
            deadline: Duration::from_millis(budget.timeout_ms),
            budget: budget.clone(),
            started: Instant::now(),
            bytes_visited: 0,
            cancel,
            chunks_done: 0,
            capture_us: 0,
            compare_us: 0,
        }
    }

    fn stop_now(&self) -> Option<StopReason> {
        if self.cancel.is_cancelled() {
            return Some(StopReason::Cancelled);
        }
        if self.started.elapsed() >= self.deadline {
            return Some(StopReason::Timeout);
        }
        if self.bytes_visited >= self.budget.max_bytes_scanned {
            return Some(StopReason::MaxBytesScanned);
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn sweep_regions(
    session: &SessionRef,
    regions: &[RegionInfo],
    item_size: usize,
    alignment: usize,
    sweep: &mut Sweep,
    mut on_chunk: impl FnMut(u64, &[u8], &[bool]) -> Option<StopReason>,
    coverage: &mut Coverage,
    policy_check: &mut impl FnMut() -> Result<()>,
    policy_us: &mut u64,
) -> Result<StopReason> {
    let overlap = item_size.saturating_sub(1);
    for region in regions.iter().filter(|r| r.eligible) {
        if let Some(reason) = sweep.stop_now() {
            return Ok(reason);
        }
        coverage.regions_visited += 1;
        let base = region.base_raw.0;
        let size = region.size.0 as usize;
        let mut offset = 0usize;

        while offset < size {
            if let Some(reason) = sweep.stop_now() {
                return Ok(reason);
            }
            sweep.chunks_done += 1;
            if sweep.chunks_done.is_multiple_of(CHECKPOINT_CHUNKS) {
                let started = Instant::now();
                policy_check()?;
                *policy_us += started.elapsed().as_micros() as u64;
            }

            let core = CHUNK_BYTES.min(size - offset);
            let with_tail = (core + overlap).min(size - offset);
            let address = base + offset as u64;

            let capture_started = Instant::now();
            let raw = mem::read_raw(session.handle, Address(address), with_tail);
            sweep.capture_us += capture_started.elapsed().as_micros() as u64;

            let got = raw.bytes.len();
            sweep.bytes_visited += got as u64;
            coverage.bytes_visited = WireU64(coverage.bytes_visited.0 + got as u64);
            if got < with_tail {
                coverage.bytes_unreadable =
                    WireU64(coverage.bytes_unreadable.0 + (with_tail - got) as u64);
            }

            if got >= item_size {
                let usable_core = got.min(core);
                let mut valid = vec![true; got];
                if got < with_tail {
                    for slot in valid.iter_mut().skip(got) {
                        *slot = false;
                    }
                }
                let compare_started = Instant::now();
                let stop = on_chunk(address, &raw.bytes[..got], &valid[..got]);
                sweep.compare_us += compare_started.elapsed().as_micros() as u64;
                let slots = if usable_core >= item_size {
                    ((usable_core - item_size) / alignment + 1) as u64
                } else {
                    0
                };
                coverage.slots_examined = WireU64(coverage.slots_examined.0 + slots);
                if let Some(reason) = stop {
                    return Ok(reason);
                }
            }

            if got < with_tail {
                let skipped =
                    ((address as usize + got + PAGE_SIZE) & !(PAGE_SIZE - 1)) - (address as usize);
                offset += skipped.max(core).min(size - offset);
                continue;
            }
            offset += core;
        }
    }
    Ok(StopReason::Completed)
}

#[allow(clippy::too_many_arguments)]
pub fn first_scan(
    session: &SessionRef,
    request: &FirstScanRequest,
    cancel: Cancel,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<(ScanState, ScanOutcome)> {
    let total_started = Instant::now();
    request.budget.validate(operation)?;
    if !request.operator.is_first_scan_operator() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "operator {} compares against a previous scan and is only valid in next_scan",
                request.operator.as_str()
            ),
        )
        .with_next_step("Run first_scan with exact, not_equal, greater_than, less_than, between, unknown, or pattern."));
    }
    validate_pair(request.value_type, request.operator, operation)?;

    let float_compare = request.float_compare.unwrap_or(FloatCompare::Tolerance {
        relative: mem::DEFAULT_FLOAT_REL_TOL,
        absolute: mem::DEFAULT_FLOAT_ABS_TOL,
    });

    let pattern = if request.operator == Operator::Pattern {
        let text = request.pattern.as_deref().ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "the pattern operator needs a pattern",
            )
        })?;
        Some(BytePattern::parse(text, operation)?)
    } else {
        None
    };

    let item_size = match (&pattern, request.value_type) {
        (Some(p), _) => p.len(),
        (None, ValueType::Bytes) => {
            let hex_text = match &request.needle {
                Some(Needle::Bytes { hex }) => hex.clone(),
                _ => {
                    return Err(OperationError::new(
                        ErrorCode::InvalidArgument,
                        operation,
                        "a bytes scan needs a hex needle or a pattern",
                    ));
                }
            };
            parse_hex_bytes(&hex_text, operation)?.len()
        }
        (None, t) => t.size_for(session.width).ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("{} cannot be scanned as a fixed-size value", t.as_str()),
            )
            .with_next_step("Use the bytes type with a pattern to search text.")
        })?,
    };

    let alignment = match request.alignment {
        Some(0) => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "alignment must be at least 1",
            ));
        }
        Some(a) if a > 4096 => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("alignment {a} is above the 4096-byte limit"),
            ));
        }
        Some(a) => a,
        None => {
            if request.operator == Operator::Pattern || request.value_type == ValueType::Bytes {
                1
            } else {
                request.value_type.alignment(session.width)
            }
        }
    };

    let exact_bytes = match (&request.needle, request.value_type) {
        (Some(Needle::Bytes { hex }), ValueType::Bytes) => Some(parse_hex_bytes(hex, operation)?),
        _ => None,
    };

    let (low, high) = if request.operator == Operator::Unknown
        || request.operator == Operator::Pattern
        || request.value_type == ValueType::Bytes
    {
        (None, None)
    } else {
        let needle = request.needle.as_ref().ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("operator {} needs a value", request.operator.as_str()),
            )
        })?;
        let low = needle_to_target(needle, request.value_type, operation)?;
        let high = if request.operator == Operator::Between {
            let hi = request.needle_high.as_ref().ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    "the between operator needs needle_high",
                )
            })?;
            Some(needle_to_target(hi, request.value_type, operation)?)
        } else {
            None
        };
        (Some(low), high)
    };

    let region_started = Instant::now();
    let resolved = request.filter.resolve(session, operation)?;
    let modules = ptr::list_modules(session, operation).unwrap_or_default();
    let regions = enumerate_regions(session, &resolved, &modules, operation)?;
    let region_enum_us = region_started.elapsed().as_micros() as u64;

    let mut coverage = Coverage::default();
    for region in regions.iter().filter(|r| r.eligible) {
        coverage.regions_eligible += 1;
        coverage.bytes_eligible = WireU64(coverage.bytes_eligible.0 + region.size.0);
    }

    let mut sweep = Sweep::new(&request.budget, cancel);
    let mut policy_us = 0u64;
    let mut candidates = CandidateStore::new(request.value_type, item_size);
    let mut total_matches: u64 = 0;
    let mut hit_result_cap = false;

    let bitwise_exact = request.operator == Operator::Exact
        && match numeric_class(request.value_type) {
            NumericClass::Float => float_compare == FloatCompare::Exact,
            NumericClass::SignedInteger | NumericClass::UnsignedInteger => true,
            NumericClass::Opaque => false,
        };
    let fast_path: Option<FastPath> = if let Some(p) = &pattern {
        Some(FastPath::Pattern {
            bytes: p.bytes.clone(),
            mask: p.mask.clone(),
        })
    } else if let Some(needle) = &exact_bytes {
        Some(FastPath::Bytes(needle.clone()))
    } else if bitwise_exact
        && let Some(target) = low
        && let Some(encoded) = encode_target(target, item_size)
    {
        match item_size {
            4 => Some(FastPath::Exact4(
                encoded[..4].try_into().expect("four bytes"),
            )),
            8 => Some(FastPath::Exact8(
                encoded[..8].try_into().expect("eight bytes"),
            )),
            _ => None,
        }
    } else {
        None
    };

    let mut baseline_chunks: Vec<BaselineChunk> = Vec::new();
    let mut baseline_bytes = 0usize;
    let mut baseline_slots = 0u64;
    let mut baseline_valid = 0u64;
    let unknown = request.operator == Operator::Unknown;
    let snapshot_cap = request.budget.max_snapshot_bytes;
    let mut hit_snapshot_cap = false;

    let stop = sweep_regions(
        session,
        &regions,
        item_size,
        alignment,
        &mut sweep,
        |address, bytes, valid| {
            if unknown {
                if baseline_bytes + bytes.len() > snapshot_cap {
                    hit_snapshot_cap = true;
                    return Some(StopReason::MaxSnapshotBytes);
                }
                let pages = bytes.len().div_ceil(PAGE_SIZE);
                let mut valid_pages = vec![false; pages];
                for (page, slot) in valid_pages.iter_mut().enumerate() {
                    let start = page * PAGE_SIZE;
                    let end = ((page + 1) * PAGE_SIZE).min(valid.len());
                    *slot = start < end && valid[start..end].iter().all(|v| *v);
                }
                let slots = if bytes.len() >= item_size {
                    ((bytes.len() - item_size) / alignment + 1) as u64
                } else {
                    0
                };
                baseline_slots += slots;
                for index in 0..slots {
                    let offset = index as usize * alignment;
                    let page = offset / PAGE_SIZE;
                    if valid_pages.get(page).copied().unwrap_or(false) {
                        baseline_valid += 1;
                    }
                }
                baseline_bytes += bytes.len();
                baseline_chunks.push(BaselineChunk {
                    base: address,
                    bytes: bytes.to_vec(),
                    valid_pages,
                });
                return None;
            }

            let core_end = bytes
                .len()
                .saturating_sub(item_size.saturating_sub(1))
                .max(1);

            if let Some(fast) = &fast_path {
                let mut hits = Vec::new();
                match fast {
                    FastPath::Exact4(needle) => {
                        kernel::find_exact_4(bytes, *needle, alignment, &mut hits)
                    }
                    FastPath::Exact8(needle) => {
                        kernel::find_exact_8(bytes, *needle, alignment, &mut hits)
                    }
                    FastPath::Bytes(needle) => {
                        kernel::find_bytes(bytes, needle, alignment, &mut hits)
                    }
                    FastPath::Pattern { bytes: p, mask } => {
                        kernel::find_pattern(bytes, p, mask, alignment, &mut hits)
                    }
                }
                for offset in hits {
                    if offset > 0 && offset >= core_end {
                        continue;
                    }
                    if offset + item_size > bytes.len() {
                        continue;
                    }
                    total_matches += 1;
                    if candidates.len() < request.budget.max_results {
                        candidates
                            .push(address + offset as u64, &bytes[offset..offset + item_size]);
                    } else {
                        hit_result_cap = true;
                        return Some(StopReason::MaxResults);
                    }
                }
                return None;
            }

            let mut offset = 0usize;
            while offset + item_size <= bytes.len() {
                if offset >= core_end && offset > 0 {
                    break;
                }
                let slot = &bytes[offset..offset + item_size];
                let is_match = match (read_slot(request.value_type, slot), low) {
                    (Some(observed), Some(target)) => {
                        compare_first(observed, request.operator, target, high, float_compare)
                    }
                    _ => false,
                };
                if is_match {
                    total_matches += 1;
                    if candidates.len() < request.budget.max_results {
                        candidates.push(address + offset as u64, slot);
                    } else {
                        hit_result_cap = true;
                        return Some(StopReason::MaxResults);
                    }
                }
                offset += alignment;
            }
            None
        },
        &mut coverage,
        &mut policy_check,
        &mut policy_us,
    )?;

    let materialise_started = Instant::now();
    let scan_id = next_id("scan-");
    let baseline = if unknown {
        Some(Arc::new(Baseline {
            id: next_id("baseline-"),
            value_type: request.value_type,
            item_size,
            chunks: baseline_chunks,
            total_bytes: baseline_bytes,
            slot_count: baseline_slots,
            valid_slots: baseline_valid,
        }))
    } else {
        None
    };

    let effective_stop = if hit_snapshot_cap {
        StopReason::MaxSnapshotBytes
    } else if hit_result_cap {
        StopReason::MaxResults
    } else {
        stop
    };
    let truncated = effective_stop.truncates();

    let displayed = view_candidates(
        session,
        &candidates,
        0,
        request.budget.display_limit,
        request.value_type,
    );
    let materialise_us = materialise_started.elapsed().as_micros() as u64;

    let outcome = ScanOutcome {
        scan_id: scan_id.clone(),
        generation: WireU64(1),
        session_id: session.id.clone(),
        value_type: request.value_type,
        operator: request.operator,
        baseline_source: BaselineSource::InitialBaseline,
        baseline_id: baseline.as_ref().map(|b| b.id.clone()),
        compared_against_scan_id: None,
        retained: candidates.len(),
        displayed,
        display_offset: 0,
        total_matches_known: !truncated,
        total_matches: (!truncated).then_some(WireU64(total_matches)),
        truncated,
        stop_reason: effective_stop,
        coverage,
        timing: ScanTiming {
            total_us: WireU64(total_started.elapsed().as_micros() as u64),
            region_enum_us: WireU64(region_enum_us),
            capture_us: WireU64(sweep.capture_us),
            compare_us: WireU64(sweep.compare_us),
            materialise_us: WireU64(materialise_us),
            policy_us: WireU64(policy_us),
        },
        consistency: mem::ConsistencyMode::Live,
        values_are_from_capture: true,
        baseline_slot_count: baseline.as_ref().map(|b| WireU64(b.slot_count)),
        baseline_valid_slots: baseline.as_ref().map(|b| WireU64(b.valid_slots)),
        baseline_bytes: baseline.as_ref().map(|b| WireU64(b.total_bytes as u64)),
    };

    let state = ScanState {
        scan_id,
        generation: 1,
        session_id: session.id.clone(),
        value_type: request.value_type,
        item_size,
        candidates,
        initial_baseline: baseline,
        previous_values: None,
        last_outcome: Some(outcome.clone()),
        truncated,
    };
    Ok((state, outcome))
}

fn view_candidates(
    session: &SessionRef,
    store: &CandidateStore,
    offset: usize,
    limit: usize,
    value_type: ValueType,
) -> Vec<CandidateView> {
    let mut out = Vec::new();
    for index in offset..store.len().min(offset + limit) {
        let bytes = store.value_at(index);
        let address = store.addresses[index];
        out.push(CandidateView {
            address: Address(address).to_canonical(session.width),
            address_raw: WireU64(address),
            captured_raw: hex(bytes),
            captured_decoded: if value_type.is_scalar() || value_type == ValueType::Pointer {
                mem::decode_scalar(value_type, bytes, session.width, "list_results").ok()
            } else {
                None
            },
        });
    }
    out
}

pub fn next_scan(
    session: &SessionRef,
    state: &mut ScanState,
    request: &NextScanRequest,
    cancel: Cancel,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<ScanOutcome> {
    let total_started = Instant::now();
    request.budget.validate(operation)?;
    if !request.operator.needs_previous() && !request.operator.is_first_scan_operator() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("operator {} is not valid here", request.operator.as_str()),
        ));
    }
    if request.operator == Operator::Unknown {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "the unknown operator starts a baseline and belongs to first_scan",
        )
        .with_next_step(
            "Narrow an unknown baseline with changed, unchanged, increased or decreased.",
        ));
    }
    validate_pair(state.value_type, request.operator, operation)?;

    let float_compare = request.float_compare.unwrap_or(FloatCompare::Tolerance {
        relative: mem::DEFAULT_FLOAT_REL_TOL,
        absolute: mem::DEFAULT_FLOAT_ABS_TOL,
    });
    let overflow = request
        .integer_overflow
        .unwrap_or(IntegerOverflow::Saturate);

    let delta = match (&request.needle, request.operator) {
        (Some(n), Operator::IncreasedBy | Operator::DecreasedBy) => {
            Some(needle_to_target(n, state.value_type, operation)?)
        }
        (None, Operator::IncreasedBy | Operator::DecreasedBy) => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("operator {} needs a delta value", request.operator.as_str()),
            ));
        }
        _ => None,
    };

    let from_baseline = request.baseline_source == BaselineSource::InitialBaseline;
    if from_baseline && state.initial_baseline.is_none() {
        return Err(OperationError::new(
            ErrorCode::ScanStateInvalid,
            operation,
            "this scan has no initial baseline to compare against",
        )
        .with_next_step(
            "An initial baseline exists only after an unknown first_scan. Use previous_scan.",
        ));
    }

    let item_size = state.item_size;
    let mut kept = CandidateStore::new(state.value_type, item_size);
    let mut previous_kept = CandidateStore::new(state.value_type, item_size);
    let mut coverage = Coverage::default();
    let mut sweep = Sweep::new(&request.budget, cancel);
    let mut policy_us = 0u64;
    let mut unreadable = 0u64;
    let mut rejected_overflow = 0u64;

    let compared_against = if from_baseline {
        state
            .initial_baseline
            .as_ref()
            .map(|b| b.id.clone())
            .unwrap_or_default()
    } else {
        state.scan_id.clone()
    };

    let baseline = state.initial_baseline.clone();
    let source_is_baseline_only = state.candidates.is_empty() && baseline.is_some();

    let addresses: Vec<u64> = if source_is_baseline_only {
        let b = baseline.as_ref().expect("checked");
        let mut out = Vec::new();
        for chunk in &b.chunks {
            let mut offset = 0usize;
            while offset + item_size <= chunk.bytes.len() {
                let page = offset / PAGE_SIZE;
                if chunk.valid_pages.get(page).copied().unwrap_or(false) {
                    out.push(chunk.base + offset as u64);
                }
                offset += item_size;
            }
        }
        out
    } else {
        state.candidates.addresses.clone()
    };

    coverage.regions_eligible = 1;
    coverage.bytes_eligible = WireU64((addresses.len() * item_size) as u64);

    let mut stop = StopReason::Completed;
    for (index, &address) in addresses.iter().enumerate() {
        if let Some(reason) = sweep.stop_now() {
            stop = reason;
            break;
        }
        if index.is_multiple_of(4096) {
            let started = Instant::now();
            policy_check()?;
            policy_us += started.elapsed().as_micros() as u64;
        }

        let capture_started = Instant::now();
        let raw = mem::read_raw(session.handle, Address(address), item_size);
        sweep.capture_us += capture_started.elapsed().as_micros() as u64;
        sweep.bytes_visited += raw.bytes.len() as u64;
        coverage.bytes_visited = WireU64(coverage.bytes_visited.0 + raw.bytes.len() as u64);

        if raw.bytes.len() < item_size {
            unreadable += 1;
            coverage.bytes_unreadable =
                WireU64(coverage.bytes_unreadable.0 + (item_size - raw.bytes.len()) as u64);
            continue;
        }
        coverage.slots_examined = WireU64(coverage.slots_examined.0 + 1);

        let before_bytes: Option<Vec<u8>> = if from_baseline {
            baseline
                .as_ref()
                .and_then(|b| b.value_at(address))
                .map(<[u8]>::to_vec)
        } else if source_is_baseline_only {
            baseline
                .as_ref()
                .and_then(|b| b.value_at(address))
                .map(<[u8]>::to_vec)
        } else {
            Some(state.candidates.value_at(index).to_vec())
        };
        let Some(before_bytes) = before_bytes else {
            unreadable += 1;
            continue;
        };

        let compare_started = Instant::now();
        let decision = match (
            read_slot(state.value_type, &raw.bytes),
            read_slot(state.value_type, &before_bytes),
        ) {
            (Some(now), Some(before)) => {
                if request.operator.needs_previous() {
                    compare_delta(
                        now,
                        before,
                        request.operator,
                        delta,
                        float_compare,
                        overflow,
                    )
                } else {
                    let target = request
                        .needle
                        .as_ref()
                        .map(|n| needle_to_target(n, state.value_type, operation))
                        .transpose()?;
                    Some(match target {
                        Some(t) => compare_first(now, request.operator, t, None, float_compare),
                        None => false,
                    })
                }
            }
            _ => Some(false),
        };
        sweep.compare_us += compare_started.elapsed().as_micros() as u64;

        match decision {
            None => rejected_overflow += 1,
            Some(true) => {
                if kept.len() >= request.budget.max_results {
                    stop = StopReason::MaxResults;
                    break;
                }
                kept.push(address, &raw.bytes);
                previous_kept.push(address, &before_bytes);
            }
            Some(false) => {}
        }
    }

    let materialise_started = Instant::now();
    state.generation += 1;
    let new_scan_id = next_id("scan-");
    let truncated = stop.truncates() || state.truncated;
    let retained = kept.len();
    let displayed = view_candidates(
        session,
        &kept,
        0,
        request.budget.display_limit,
        state.value_type,
    );
    let materialise_us = materialise_started.elapsed().as_micros() as u64;

    if unreadable > 0 || rejected_overflow > 0 {
        crate::diag::info(&format!(
            "next_scan: {unreadable} slots became unreadable, {rejected_overflow} rejected for integer overflow"
        ));
    }

    let outcome = ScanOutcome {
        scan_id: new_scan_id.clone(),
        generation: WireU64(state.generation),
        session_id: session.id.clone(),
        value_type: state.value_type,
        operator: request.operator,
        baseline_source: request.baseline_source,
        baseline_id: baseline.as_ref().map(|b| b.id.clone()),
        compared_against_scan_id: Some(compared_against),
        retained,
        displayed,
        display_offset: 0,
        total_matches_known: !truncated,
        total_matches: (!truncated).then_some(WireU64(retained as u64)),
        truncated,
        stop_reason: stop,
        coverage,
        timing: ScanTiming {
            total_us: WireU64(total_started.elapsed().as_micros() as u64),
            region_enum_us: WireU64(0),
            capture_us: WireU64(sweep.capture_us),
            compare_us: WireU64(sweep.compare_us),
            materialise_us: WireU64(materialise_us),
            policy_us: WireU64(policy_us),
        },
        consistency: mem::ConsistencyMode::Live,
        values_are_from_capture: true,
        baseline_slot_count: baseline.as_ref().map(|b| WireU64(b.slot_count)),
        baseline_valid_slots: baseline.as_ref().map(|b| WireU64(b.valid_slots)),
        baseline_bytes: baseline.as_ref().map(|b| WireU64(b.total_bytes as u64)),
    };

    state.scan_id = new_scan_id;
    state.candidates = kept;
    state.previous_values = Some(previous_kept);
    state.truncated = truncated;
    state.last_outcome = Some(outcome.clone());
    Ok(outcome)
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListResultsRequest {
    #[serde(default)]
    pub offset: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default)]
    pub reread_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RereadValue {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_decoded: Option<mem::Decoded>,
    pub observed_at_unix_us: WireU64,
    pub readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResultsOutcome {
    pub scan_id: String,
    pub generation: WireU64,
    pub retained: usize,
    pub display_offset: usize,
    pub displayed: Vec<CandidateView>,
    pub values_are_from_capture: bool,
    pub truncated: bool,
    pub display_pagination_only: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub current_values: Vec<RereadValue>,
}

pub fn list_results(
    session: &SessionRef,
    state: &ScanState,
    request: &ListResultsRequest,
    operation: &str,
) -> Result<ListResultsOutcome> {
    let limit = request.limit.unwrap_or(DEFAULT_DISPLAY_LIMIT);
    if limit == 0 || limit > MAX_DISPLAY_LIMIT {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("limit {limit} must be between 1 and {MAX_DISPLAY_LIMIT}"),
        ));
    }
    if request.offset > state.candidates.len() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "offset {} is past the {} retained candidates",
                request.offset,
                state.candidates.len()
            ),
        ));
    }

    let displayed = view_candidates(
        session,
        &state.candidates,
        request.offset,
        limit,
        state.value_type,
    );

    let mut current_values = Vec::new();
    if request.reread_current {
        for view in &displayed {
            let raw = mem::read_raw(session.handle, Address(view.address_raw.0), state.item_size);
            let readable = raw.bytes.len() == state.item_size;
            current_values.push(RereadValue {
                address: view.address.clone(),
                current_raw: readable.then(|| hex(&raw.bytes)),
                current_decoded: if readable {
                    mem::decode_scalar(state.value_type, &raw.bytes, session.width, operation).ok()
                } else {
                    None
                },
                observed_at_unix_us: WireU64(raw.observed_at_unix_us),
                readable,
            });
        }
    }

    Ok(ListResultsOutcome {
        scan_id: state.scan_id.clone(),
        generation: WireU64(state.generation),
        retained: state.candidates.len(),
        display_offset: request.offset,
        displayed,
        values_are_from_capture: true,
        truncated: state.truncated,
        display_pagination_only: true,
        current_values,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetOutcome {
    pub cleared_scan_id: String,
    pub cleared_candidates: usize,
    pub cleared_baseline: bool,
    pub generation: WireU64,
}

pub fn reset_scan(state: ScanState) -> ResetOutcome {
    ResetOutcome {
        cleared_scan_id: state.scan_id,
        cleared_candidates: state.candidates.len(),
        cleared_baseline: state.initial_baseline.is_some(),
        generation: WireU64(state.generation),
    }
}

pub const MAX_GROUP_FIELDS: usize = 64;
pub const MAX_GROUP_SPAN: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GroupFieldSpec {
    pub name: String,
    pub value_type: ValueType,
    pub offset: i64,
    pub operator: Operator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needle: Option<Needle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needle_high: Option<Needle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GroupScanRequest {
    pub fields: Vec<GroupFieldSpec>,
    #[serde(default)]
    pub filter: RegionFilter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    #[serde(default)]
    pub budget: ScanBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_compare: Option<FloatCompare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFieldEvidence {
    pub name: String,
    pub value_type: ValueType,
    pub offset: i64,
    pub address: String,
    pub address_raw: WireU64,
    pub operator: Operator,
    pub captured_raw: String,
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_decoded: Option<mem::Decoded>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMatch {
    pub base_address: String,
    pub base_address_raw: WireU64,
    pub span_start_raw: WireU64,
    pub span_end_raw: WireU64,
    pub fields: Vec<GroupFieldEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupScanOutcome {
    pub scan_id: String,
    pub session_id: String,
    pub field_count: usize,
    pub span_bytes: usize,
    pub min_offset: i64,
    pub max_offset: i64,
    pub retained: usize,
    pub matches: Vec<GroupMatch>,
    pub display_offset: usize,
    pub total_matches_known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_matches: Option<WireU64>,
    pub truncated: bool,
    pub stop_reason: StopReason,
    pub coverage: Coverage,
    pub timing: ScanTiming,
    pub consistency: mem::ConsistencyMode,
    pub values_are_from_capture: bool,
}

struct ResolvedGroupField {
    spec_name: String,
    value_type: ValueType,
    offset: i64,
    operator: Operator,
    size: usize,
    low: Option<Target>,
    high: Option<Target>,
}

pub fn group_scan(
    session: &SessionRef,
    request: &GroupScanRequest,
    cancel: Cancel,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<GroupScanOutcome> {
    let total_started = Instant::now();
    request.budget.validate(operation)?;

    if request.fields.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "group_scan needs at least one field",
        )
        .with_next_step("Declare the fields and their offsets explicitly."));
    }
    if request.fields.len() > MAX_GROUP_FIELDS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "group_scan received {} fields, over the {MAX_GROUP_FIELDS} limit",
                request.fields.len()
            ),
        ));
    }

    let float_compare = request.float_compare.unwrap_or(FloatCompare::Tolerance {
        relative: mem::DEFAULT_FLOAT_REL_TOL,
        absolute: mem::DEFAULT_FLOAT_ABS_TOL,
    });

    let mut resolved = Vec::with_capacity(request.fields.len());
    for field in &request.fields {
        if !field.operator.is_first_scan_operator() || field.operator == Operator::Unknown {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "field {:?} uses operator {}, which compares against a previous scan",
                    field.name,
                    field.operator.as_str()
                ),
            )
            .with_next_step("A group field takes a value comparison, not a delta comparison."));
        }
        validate_pair(field.value_type, field.operator, operation)?;
        let size = field.value_type.size_for(session.width).ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "field {:?} has type {}, which has no fixed size",
                    field.name,
                    field.value_type.as_str()
                ),
            )
            .with_next_step("Group fields must be fixed-size typed values.")
        })?;
        let needle = field.needle.as_ref().ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("field {:?} needs a value to compare against", field.name),
            )
        })?;
        let low = needle_to_target(needle, field.value_type, operation)?;
        let high = if field.operator == Operator::Between {
            let hi = field.needle_high.as_ref().ok_or_else(|| {
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    operation,
                    format!("field {:?} uses between and needs needle_high", field.name),
                )
            })?;
            Some(needle_to_target(hi, field.value_type, operation)?)
        } else {
            None
        };
        resolved.push(ResolvedGroupField {
            spec_name: field.name.clone(),
            value_type: field.value_type,
            offset: field.offset,
            operator: field.operator,
            size,
            low: Some(low),
            high,
        });
    }

    let min_offset = resolved.iter().map(|f| f.offset).min().expect("non-empty");
    let max_end = resolved
        .iter()
        .map(|f| f.offset + f.size as i64)
        .max()
        .expect("non-empty");
    let span = (max_end - min_offset) as usize;
    if span == 0 || span > MAX_GROUP_SPAN {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("the field group spans {span} bytes, outside 1..={MAX_GROUP_SPAN}"),
        ));
    }

    let alignment = match request.alignment {
        Some(0) => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                "alignment must be at least 1",
            ));
        }
        Some(a) if a > 4096 => {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("alignment {a} is above the 4096-byte limit"),
            ));
        }
        Some(a) => a,
        None => resolved[0].value_type.alignment(session.width),
    };

    let region_started = Instant::now();
    let filter = request.filter.resolve(session, operation)?;
    let modules = ptr::list_modules(session, operation).unwrap_or_default();
    let regions = enumerate_regions(session, &filter, &modules, operation)?;
    let region_enum_us = region_started.elapsed().as_micros() as u64;

    let mut coverage = Coverage::default();
    for region in regions.iter().filter(|r| r.eligible) {
        coverage.regions_eligible += 1;
        coverage.bytes_eligible = WireU64(coverage.bytes_eligible.0 + region.size.0);
    }

    let mut sweep = Sweep::new(&request.budget, cancel);
    let mut policy_us = 0u64;
    let mut matches: Vec<GroupMatch> = Vec::new();
    let mut total_matches = 0u64;
    let mut hit_cap = false;

    let stop = sweep_regions(
        session,
        &regions,
        span,
        alignment,
        &mut sweep,
        |chunk_address, bytes, _valid| {
            let core_end = bytes.len().saturating_sub(span.saturating_sub(1)).max(1);
            let mut offset = 0usize;
            while offset + span <= bytes.len() {
                if offset >= core_end && offset > 0 {
                    break;
                }
                let span_start = chunk_address + offset as u64;
                let base = span_start.wrapping_sub(min_offset as u64);
                let mut all_matched = true;
                let mut evidence = Vec::with_capacity(resolved.len());
                for field in &resolved {
                    let field_offset = (field.offset - min_offset) as usize;
                    let slot = &bytes[offset + field_offset..offset + field_offset + field.size];
                    let matched = match (read_slot(field.value_type, slot), field.low) {
                        (Some(observed), Some(target)) => compare_first(
                            observed,
                            field.operator,
                            target,
                            field.high,
                            float_compare,
                        ),
                        _ => false,
                    };
                    if !matched {
                        all_matched = false;
                        break;
                    }
                    let field_address = span_start + field_offset as u64;
                    evidence.push(GroupFieldEvidence {
                        name: field.spec_name.clone(),
                        value_type: field.value_type,
                        offset: field.offset,
                        address: Address(field_address).to_canonical(session.width),
                        address_raw: WireU64(field_address),
                        operator: field.operator,
                        captured_raw: hex(slot),
                        matched: true,
                        captured_decoded: mem::decode_scalar(
                            field.value_type,
                            slot,
                            session.width,
                            "group_scan",
                        )
                        .ok(),
                    });
                }
                if all_matched {
                    total_matches += 1;
                    if matches.len() < request.budget.max_results {
                        matches.push(GroupMatch {
                            base_address: Address(base).to_canonical(session.width),
                            base_address_raw: WireU64(base),
                            span_start_raw: WireU64(span_start),
                            span_end_raw: WireU64(span_start + span as u64),
                            fields: evidence,
                        });
                    } else {
                        hit_cap = true;
                        return Some(StopReason::MaxResults);
                    }
                }
                offset += alignment;
            }
            None
        },
        &mut coverage,
        &mut policy_check,
        &mut policy_us,
    )?;

    let materialise_started = Instant::now();
    let effective_stop = if hit_cap {
        StopReason::MaxResults
    } else {
        stop
    };
    let truncated = effective_stop.truncates();
    let retained = matches.len();
    matches.truncate(request.budget.display_limit);
    let materialise_us = materialise_started.elapsed().as_micros() as u64;

    Ok(GroupScanOutcome {
        scan_id: next_id("group-"),
        session_id: session.id.clone(),
        field_count: resolved.len(),
        span_bytes: span,
        min_offset,
        max_offset: max_end,
        retained,
        matches,
        display_offset: 0,
        total_matches_known: !truncated,
        total_matches: (!truncated).then_some(WireU64(total_matches)),
        truncated,
        stop_reason: effective_stop,
        coverage,
        timing: ScanTiming {
            total_us: WireU64(total_started.elapsed().as_micros() as u64),
            region_enum_us: WireU64(region_enum_us),
            capture_us: WireU64(sweep.capture_us),
            compare_us: WireU64(sweep.compare_us),
            materialise_us: WireU64(materialise_us),
            policy_us: WireU64(policy_us),
        },
        consistency: mem::ConsistencyMode::Live,
        values_are_from_capture: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_parses_wildcards_and_rejects_nonsense() {
        let p = BytePattern::parse("cd ?? cc 3d", "first_scan").expect("valid");
        assert_eq!(p.bytes, vec![0xcd, 0x00, 0xcc, 0x3d]);
        assert_eq!(p.mask, vec![true, false, true, true]);
        assert_eq!(p.len(), 4);

        assert!(BytePattern::parse("", "first_scan").is_err());
        assert!(BytePattern::parse("cdc", "first_scan").is_err());
        assert!(BytePattern::parse("?? ?? ??", "first_scan").is_err());
        assert!(BytePattern::parse("c?", "first_scan").is_err());
        assert!(BytePattern::parse("zz", "first_scan").is_err());
    }

    #[test]
    fn a_pattern_matches_only_where_its_concrete_bytes_agree() {
        let p = BytePattern::parse("cd??3d", "first_scan").unwrap();
        let haystack = [0x00, 0xcd, 0xff, 0x3d, 0xcd, 0x11, 0x3e];
        assert!(p.matches_at(&haystack, 1));
        assert!(!p.matches_at(&haystack, 4));
        assert!(!p.matches_at(&haystack, 5));
    }

    #[test]
    fn unsupported_type_and_operator_pairs_are_rejected_by_name() {
        assert!(validate_pair(ValueType::Bytes, Operator::GreaterThan, "first_scan").is_err());
        assert!(validate_pair(ValueType::Int32, Operator::Pattern, "first_scan").is_err());
        assert!(validate_pair(ValueType::String, Operator::Exact, "first_scan").is_err());
        assert!(validate_pair(ValueType::Bytes, Operator::Pattern, "first_scan").is_ok());
        assert!(validate_pair(ValueType::Float, Operator::Between, "first_scan").is_ok());
        assert!(validate_pair(ValueType::Uint64, Operator::IncreasedBy, "next_scan").is_ok());
    }

    #[test]
    fn delta_operators_are_refused_in_a_first_scan() {
        for op in [
            Operator::Changed,
            Operator::Unchanged,
            Operator::Increased,
            Operator::Decreased,
            Operator::IncreasedBy,
            Operator::DecreasedBy,
        ] {
            assert!(op.needs_previous(), "{}", op.as_str());
            assert!(!op.is_first_scan_operator(), "{}", op.as_str());
        }
        for op in [
            Operator::Exact,
            Operator::NotEqual,
            Operator::GreaterThan,
            Operator::LessThan,
            Operator::Between,
            Operator::Unknown,
            Operator::Pattern,
        ] {
            assert!(op.is_first_scan_operator(), "{}", op.as_str());
        }
    }

    #[test]
    fn signed_and_unsigned_comparisons_do_not_bleed_into_each_other() {
        let f = FloatCompare::Exact;
        assert!(compare_first(
            Target::Signed(-1),
            Operator::LessThan,
            Target::Signed(0),
            None,
            f
        ));
        assert!(compare_first(
            Target::Unsigned(u64::MAX),
            Operator::GreaterThan,
            Target::Unsigned(0),
            None,
            f
        ));
        assert!(!compare_first(
            Target::Signed(-1),
            Operator::Exact,
            Target::Unsigned(1),
            None,
            f
        ));
    }

    #[test]
    fn between_is_inclusive_at_both_ends() {
        let f = FloatCompare::Exact;
        for value in [10i64, 15, 20] {
            assert!(
                compare_first(
                    Target::Signed(value),
                    Operator::Between,
                    Target::Signed(10),
                    Some(Target::Signed(20)),
                    f
                ),
                "{value}"
            );
        }
        assert!(!compare_first(
            Target::Signed(9),
            Operator::Between,
            Target::Signed(10),
            Some(Target::Signed(20)),
            f
        ));
        assert!(!compare_first(
            Target::Signed(21),
            Operator::Between,
            Target::Signed(10),
            Some(Target::Signed(20)),
            f
        ));
    }

    #[test]
    fn ordering_comparisons_never_match_a_non_finite_float() {
        let f = FloatCompare::Exact;
        assert!(!compare_first(
            Target::Float(f64::NAN),
            Operator::GreaterThan,
            Target::Float(0.0),
            None,
            f
        ));
        assert!(!compare_first(
            Target::Float(f64::INFINITY),
            Operator::GreaterThan,
            Target::Float(0.0),
            None,
            f
        ));
    }

    #[test]
    fn delta_comparisons_cover_changed_unchanged_increased_and_decreased() {
        let f = FloatCompare::Exact;
        let o = IntegerOverflow::Saturate;
        let s = |n: i64| Target::Signed(n);
        assert_eq!(
            compare_delta(s(5), s(4), Operator::Changed, None, f, o),
            Some(true)
        );
        assert_eq!(
            compare_delta(s(4), s(4), Operator::Unchanged, None, f, o),
            Some(true)
        );
        assert_eq!(
            compare_delta(s(5), s(4), Operator::Increased, None, f, o),
            Some(true)
        );
        assert_eq!(
            compare_delta(s(3), s(4), Operator::Decreased, None, f, o),
            Some(true)
        );
        assert_eq!(
            compare_delta(s(3), s(4), Operator::Increased, None, f, o),
            Some(false)
        );
    }

    #[test]
    fn an_exact_delta_matches_only_the_stated_difference() {
        let f = FloatCompare::Exact;
        let o = IntegerOverflow::Saturate;
        let s = |n: i64| Target::Signed(n);
        assert_eq!(
            compare_delta(s(30), s(25), Operator::IncreasedBy, Some(s(5)), f, o),
            Some(true)
        );
        assert_eq!(
            compare_delta(s(31), s(25), Operator::IncreasedBy, Some(s(5)), f, o),
            Some(false)
        );
        assert_eq!(
            compare_delta(s(20), s(25), Operator::DecreasedBy, Some(s(5)), f, o),
            Some(true)
        );
    }

    #[test]
    fn integer_overflow_in_a_delta_is_either_saturated_or_rejected_but_never_wrapped() {
        let f = FloatCompare::Exact;
        let before = Target::Unsigned(u64::MAX - 1);
        let delta = Some(Target::Unsigned(10));

        let saturated = compare_delta(
            Target::Unsigned(u64::MAX),
            before,
            Operator::IncreasedBy,
            delta,
            f,
            IntegerOverflow::Saturate,
        );
        assert_eq!(saturated, Some(true));

        let wrapped_value = Target::Unsigned(8);
        assert_eq!(
            compare_delta(
                wrapped_value,
                before,
                Operator::IncreasedBy,
                delta,
                f,
                IntegerOverflow::Saturate
            ),
            Some(false),
            "a wrapped value must not be accepted as the delta result"
        );

        assert_eq!(
            compare_delta(
                Target::Unsigned(u64::MAX),
                before,
                Operator::IncreasedBy,
                delta,
                f,
                IntegerOverflow::Reject
            ),
            None,
            "reject mode reports the slot as undecidable rather than matching"
        );
    }

    #[test]
    fn a_float_delta_uses_the_configured_tolerance() {
        let tol = FloatCompare::Tolerance {
            relative: mem::DEFAULT_FLOAT_REL_TOL,
            absolute: mem::DEFAULT_FLOAT_ABS_TOL,
        };
        let o = IntegerOverflow::Saturate;
        assert_eq!(
            compare_delta(
                Target::Float(1.5),
                Target::Float(1.0),
                Operator::IncreasedBy,
                Some(Target::Float(0.5)),
                tol,
                o
            ),
            Some(true)
        );
    }

    #[test]
    fn a_budget_rejects_zero_and_oversized_limits() {
        let mut budget = ScanBudget::default();
        assert!(budget.validate("first_scan").is_ok());
        budget.display_limit = 0;
        assert!(budget.validate("first_scan").is_err());
        budget.display_limit = MAX_DISPLAY_LIMIT + 1;
        assert!(budget.validate("first_scan").is_err());
        budget = ScanBudget::default();
        budget.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(budget.validate("first_scan").is_err());
        budget = ScanBudget::default();
        budget.max_results = 0;
        assert!(budget.validate("first_scan").is_err());
        budget = ScanBudget::default();
        budget.max_bytes_scanned = 0;
        assert!(budget.validate("first_scan").is_err());
    }

    #[test]
    fn only_completion_leaves_a_scan_untruncated() {
        assert!(!StopReason::Completed.truncates());
        for reason in [
            StopReason::MaxResults,
            StopReason::MaxBytesScanned,
            StopReason::MaxSnapshotBytes,
            StopReason::Timeout,
            StopReason::Cancelled,
        ] {
            assert!(reason.truncates(), "{reason:?}");
        }
    }

    #[test]
    fn protection_names_and_readability_follow_the_page_flags() {
        assert_eq!(protection_name(PAGE_READWRITE.0), "PAGE_READWRITE");
        assert_eq!(protection_name(PAGE_NOACCESS.0), "PAGE_NOACCESS");
        assert_eq!(
            protection_name(PAGE_READWRITE.0 | PAGE_GUARD.0),
            "PAGE_READWRITE|PAGE_GUARD"
        );
        assert!(protection_is_readable(PAGE_READWRITE.0));
        assert!(protection_is_readable(PAGE_READONLY.0));
        assert!(protection_is_readable(PAGE_EXECUTE_READ.0));
        assert!(!protection_is_readable(PAGE_NOACCESS.0));
        assert!(!protection_is_readable(PAGE_EXECUTE.0));
        assert!(
            !protection_is_readable(PAGE_READWRITE.0 | PAGE_GUARD.0),
            "a guard page is never eligible even though its base protection is readable"
        );
    }

    #[test]
    fn every_exclusion_reason_has_a_wire_name() {
        let all = [
            ExclusionReason::NotCommitted,
            ExclusionReason::NoAccess,
            ExclusionReason::GuardPage,
            ExclusionReason::NotReadable,
            ExclusionReason::ZeroSize,
            ExclusionReason::OutsideAddressRange,
            ExclusionReason::ExcludedRegionKind,
            ExclusionReason::ExcludedProtection,
            ExclusionReason::BeyondPointerWidth,
        ];
        for reason in all {
            assert!(!reason.as_str().is_empty());
            let json = serde_json::to_string(&reason).expect("serialise");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
        }
    }

    #[test]
    fn a_cancel_flag_is_observable_from_a_clone() {
        let cancel = Cancel::new();
        let clone = cancel.clone();
        assert!(!clone.is_cancelled());
        cancel.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn the_default_baseline_source_is_the_previous_scan() {
        assert_eq!(BaselineSource::default(), BaselineSource::PreviousScan);
    }

    #[test]
    fn candidate_storage_is_flat_and_reports_its_own_size() {
        let mut store = CandidateStore::new(ValueType::Int32, 4);
        store.push(0x1000, &[1, 0, 0, 0]);
        store.push(0x2000, &[2, 0, 0, 0]);
        assert_eq!(store.len(), 2);
        assert_eq!(store.value_at(1), &[2, 0, 0, 0]);
        assert_eq!(store.memory_bytes(), 2 * 8 + 2 * 4);
    }

    #[test]
    fn a_baseline_refuses_a_slot_whose_page_was_unreadable() {
        let baseline = Baseline {
            id: "b1".to_owned(),
            value_type: ValueType::Int32,
            item_size: 4,
            chunks: vec![BaselineChunk {
                base: 0x1000,
                bytes: vec![0u8; PAGE_SIZE * 2],
                valid_pages: vec![true, false],
            }],
            total_bytes: PAGE_SIZE * 2,
            slot_count: 2,
            valid_slots: 1,
        };
        assert!(baseline.value_at(0x1000).is_some());
        assert!(
            baseline.value_at(0x1000 + PAGE_SIZE as u64).is_none(),
            "a slot on an invalid page must not be treated as zeroes"
        );
        assert!(baseline.value_at(0x9999).is_none());
    }

    #[test]
    fn a_region_filter_rejects_an_inverted_range() {
        let session = SessionRef {
            id: "s1".to_owned(),
            pid: 1,
            creation_time: "1".to_owned(),
            width: crate::wire::PointerWidth::Eight,
            handle: windows::Win32::Foundation::HANDLE(std::ptr::null_mut()),
        };
        let filter = RegionFilter {
            min_address: Some("0x2000".to_owned()),
            max_address: Some("0x1000".to_owned()),
            ..Default::default()
        };
        let err = filter
            .resolve(&session, "list_regions")
            .expect_err("inverted");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wow64_filter_is_clamped_to_the_thirty_two_bit_address_space() {
        let session = SessionRef {
            id: "s1".to_owned(),
            pid: 1,
            creation_time: "1".to_owned(),
            width: crate::wire::PointerWidth::Four,
            handle: windows::Win32::Foundation::HANDLE(std::ptr::null_mut()),
        };
        let resolved = RegionFilter::default()
            .resolve(&session, "list_regions")
            .expect("default filter");
        assert_eq!(resolved.max, u64::from(u32::MAX));
    }

    #[test]
    fn images_are_excluded_by_default_and_included_on_request() {
        let session = SessionRef {
            id: "s1".to_owned(),
            pid: 1,
            creation_time: "1".to_owned(),
            width: crate::wire::PointerWidth::Eight,
            handle: windows::Win32::Foundation::HANDLE(std::ptr::null_mut()),
        };
        let default = RegionFilter::default().resolve(&session, "t").unwrap();
        assert!(!RegionFilter::allows_kind(&default, RegionKind::Image));
        assert!(RegionFilter::allows_kind(&default, RegionKind::Private));

        let with_images = RegionFilter {
            include_images: true,
            ..Default::default()
        }
        .resolve(&session, "t")
        .unwrap();
        assert!(RegionFilter::allows_kind(&with_images, RegionKind::Image));

        let only_mapped = RegionFilter {
            kinds: vec![RegionKind::Mapped],
            ..Default::default()
        }
        .resolve(&session, "t")
        .unwrap();
        assert!(RegionFilter::allows_kind(&only_mapped, RegionKind::Mapped));
        assert!(!RegionFilter::allows_kind(
            &only_mapped,
            RegionKind::Private
        ));
    }

    #[test]
    fn a_needle_of_the_wrong_shape_for_the_type_is_refused() {
        assert!(
            needle_to_target(
                &Needle::Bytes {
                    hex: "ff".to_owned()
                },
                ValueType::Int32,
                "first_scan"
            )
            .is_err()
        );
        assert!(
            needle_to_target(
                &Needle::Int { value: WireI64(-5) },
                ValueType::Uint32,
                "first_scan"
            )
            .is_err(),
            "a negative value cannot be an unsigned target"
        );
        assert!(
            needle_to_target(
                &Needle::Uint {
                    value: WireU64(u64::MAX)
                },
                ValueType::Int64,
                "first_scan"
            )
            .is_err()
        );
        assert!(
            needle_to_target(
                &Needle::Int { value: WireI64(5) },
                ValueType::Double,
                "first_scan"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_slot_decodes_at_the_width_its_bytes_imply() {
        match read_slot(ValueType::Pointer, &[0x11, 0x22, 0x33, 0x44]) {
            Some(Target::Unsigned(v)) => assert_eq!(v, 0x4433_2211),
            other => panic!("expected an unsigned target, got {other:?}"),
        }
        match read_slot(
            ValueType::Pointer,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ) {
            Some(Target::Unsigned(v)) => assert_eq!(v, 0x8877_6655_4433_2211),
            other => panic!("expected an unsigned target, got {other:?}"),
        }
        assert!(read_slot(ValueType::String, &[0x41]).is_none());
    }
}
