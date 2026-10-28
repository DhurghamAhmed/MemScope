use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};

use crate::error::{ErrorCode, OperationError, Result};
use crate::mem::{self, SessionRef};
use crate::scan::{Cancel, RegionFilter, StopReason};
use crate::win;
use crate::wire::{Address, PointerWidth, WireU64, hex};

pub const MAX_MODULES: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base: String,
    pub base_raw: WireU64,
    pub size: WireU64,
    pub end_raw: WireU64,
}

impl ModuleInfo {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base_raw.0 && address < self.end_raw.0
    }
}

pub fn list_modules(session: &SessionRef, operation: &str) -> Result<Vec<ModuleInfo>> {
    let mut handles: Vec<HMODULE> = vec![HMODULE::default(); MAX_MODULES];
    let mut needed: u32 = 0;
    let byte_capacity = (handles.len() * size_of::<HMODULE>()) as u32;

    unsafe {
        EnumProcessModulesEx(
            session.handle,
            handles.as_mut_ptr(),
            byte_capacity,
            &mut needed,
            LIST_MODULES_ALL,
        )
    }
    .map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot enumerate the modules of pid {}", session.pid),
            code,
        )
        .with_session(&session.id)
        .with_pid(session.pid)
        .with_next_step(
            "Module enumeration needs query access; a target that refuses it has no module map.",
        )
    })?;

    let count = (needed as usize / size_of::<HMODULE>()).min(handles.len());
    let mut modules = Vec::with_capacity(count);
    for handle in handles.into_iter().take(count) {
        if handle.is_invalid() {
            continue;
        }
        let mut info = MODULEINFO::default();
        if unsafe {
            GetModuleInformation(
                session.handle,
                handle,
                &mut info,
                size_of::<MODULEINFO>() as u32,
            )
        }
        .is_err()
        {
            continue;
        }
        let mut buffer = [0u16; 1024];
        let len = unsafe { GetModuleFileNameExW(Some(session.handle), Some(handle), &mut buffer) };
        let path = if len == 0 {
            String::new()
        } else {
            win::from_wide(&buffer[..len as usize])
        };
        let name = path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_owned();
        let base_raw = info.lpBaseOfDll as u64;
        let size = u64::from(info.SizeOfImage);
        modules.push(ModuleInfo {
            name,
            path,
            base: Address(base_raw).to_canonical(session.width),
            base_raw: WireU64(base_raw),
            size: WireU64(size),
            end_raw: WireU64(base_raw.saturating_add(size)),
        });
    }
    modules.sort_by_key(|m| m.base_raw.0);
    Ok(modules)
}

pub fn module_for(modules: &[ModuleInfo], address: u64) -> Option<&ModuleInfo> {
    modules.iter().find(|m| m.contains(address))
}

pub fn find_module<'a>(
    modules: &'a [ModuleInfo],
    name: &str,
    operation: &str,
) -> Result<&'a ModuleInfo> {
    let wanted = name.trim();
    if wanted.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "a module name is required",
        ));
    }
    let looks_like_path = wanted.contains('\\') || wanted.contains('/');
    let matches: Vec<&ModuleInfo> = if looks_like_path {
        modules
            .iter()
            .filter(|m| m.path.eq_ignore_ascii_case(wanted))
            .collect()
    } else {
        modules
            .iter()
            .filter(|m| m.name.eq_ignore_ascii_case(wanted))
            .collect()
    };

    match matches.len() {
        0 => Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("no module named {wanted:?} is loaded in this target"),
        )
        .with_next_step("Call list_modules to see the loaded module names.")),
        1 => Ok(matches[0]),
        n => Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("{wanted:?} is ambiguous: {n} loaded modules share that name"),
        )
        .with_next_step(
            "Supply the full path instead of the base name to identify the module exactly.",
        )),
    }
}

pub const MAX_PATH_HOPS: usize = 16;
pub const MAX_POINTER_SCAN_DEPTH: usize = 8;
pub const MAX_POINTER_SCAN_OFFSET: u64 = 8192;
pub const DEFAULT_POINTER_INDEX_BYTES: usize = 512 * 1024 * 1024;
pub const POINTER_CHUNK_BYTES: usize = 1024 * 1024;

pub const INDEX_BUCKET_BYTES: usize = size_of::<u64>() + size_of::<Vec<u64>>() + 1;
pub const HOLDER_SLOT_BYTES: usize = size_of::<u64>();
const MIN_TABLE_BUCKETS: usize = 4;
const MIN_GROWN_CAPACITY: usize = 4;

pub const INDEX_BUDGET_NOTE: &str = "max_index_bytes caps the whole working set of this scan. \
index_bytes counts the hash table's allocated buckets, each holding one u64 key, one vector \
header and one control byte, sized at the 7/8 load factor the table grows on, plus the allocated \
capacity of every holder vector. search_bytes counts the breadth-first frontier: its ring buffer \
and the trail and visited vectors of every queued path. Both are charged against the one budget, \
and an allocation that would pass it is refused rather than made. Allocator bookkeeping outside \
those allocations is not counted.";

const fn usable_capacity(buckets: usize) -> usize {
    if buckets < 8 {
        buckets - 1
    } else {
        buckets / 8 * 7
    }
}

fn table_bytes_for(entries: usize) -> usize {
    if entries == 0 {
        return 0;
    }
    let mut buckets = MIN_TABLE_BUCKETS;
    while usable_capacity(buckets) < entries {
        match buckets.checked_mul(2) {
            Some(doubled) => buckets = doubled,
            None => break,
        }
    }
    buckets.saturating_mul(INDEX_BUCKET_BYTES)
}

fn grown_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        MIN_GROWN_CAPACITY
    } else {
        capacity.saturating_mul(2).max(MIN_GROWN_CAPACITY)
    }
}

struct PointerIndex {
    holders: HashMap<u64, Vec<u64>>,
    table_capacity: usize,
    table_bytes: usize,
    holder_bytes: usize,
    pairs: u64,
}

impl PointerIndex {
    fn new() -> Self {
        Self {
            holders: HashMap::new(),
            table_capacity: 0,
            table_bytes: 0,
            holder_bytes: 0,
            pairs: 0,
        }
    }

    fn bytes(&self) -> usize {
        self.table_bytes + self.holder_bytes
    }

    fn values(&self) -> usize {
        self.holders.len()
    }

    fn pairs(&self) -> u64 {
        self.pairs
    }

    fn holders_of(&self, value: u64) -> Option<&[u64]> {
        self.holders.get(&value).map(Vec::as_slice)
    }

    fn insert_within(&mut self, value: u64, holder: u64, limit: usize) -> bool {
        let table_full = self.holders.len() == self.table_capacity;
        if (table_full || self.bytes() + HOLDER_SLOT_BYTES > limit)
            && !self.holders.contains_key(&value)
        {
            let projected = if table_full {
                table_bytes_for(self.holders.len() + 1) + self.holder_bytes + HOLDER_SLOT_BYTES
            } else {
                self.bytes() + HOLDER_SLOT_BYTES
            };
            if projected > limit {
                return false;
            }
        }

        match self.holders.entry(value) {
            Entry::Occupied(mut slot) => {
                let list = slot.get_mut();
                let capacity = list.capacity();
                if list.len() == capacity {
                    let growth =
                        grown_capacity(capacity).saturating_sub(capacity) * HOLDER_SLOT_BYTES;
                    if self.table_bytes + self.holder_bytes + growth > limit {
                        return false;
                    }
                }
                list.push(holder);
                self.holder_bytes += (list.capacity() - capacity) * HOLDER_SLOT_BYTES;
            }
            Entry::Vacant(slot) => {
                let list = vec![holder];
                self.holder_bytes += list.capacity() * HOLDER_SLOT_BYTES;
                slot.insert(list);
            }
        }

        self.pairs += 1;
        let capacity = self.holders.capacity();
        if capacity != self.table_capacity {
            self.table_capacity = capacity;
            self.table_bytes = table_bytes_for(capacity);
        }
        true
    }
}

struct Work {
    value: u64,
    trail: Vec<i64>,
    visited: Vec<u64>,
}

impl Work {
    fn heap_bytes(&self) -> usize {
        self.trail.capacity() * size_of::<i64>() + self.visited.capacity() * size_of::<u64>()
    }
}

struct Frontier {
    items: VecDeque<Work>,
    ring_bytes: usize,
    heap_bytes: usize,
}

impl Frontier {
    fn new() -> Self {
        Self {
            items: VecDeque::new(),
            ring_bytes: 0,
            heap_bytes: 0,
        }
    }

    fn bytes(&self) -> usize {
        self.ring_bytes + self.heap_bytes
    }

    fn push_within(&mut self, work: Work, limit: usize) -> bool {
        let added = work.heap_bytes();
        let capacity = self.items.capacity();
        let ring = if self.items.len() == capacity {
            grown_capacity(capacity).saturating_mul(size_of::<Work>())
        } else {
            self.ring_bytes
        };
        if ring + self.heap_bytes + added > limit {
            return false;
        }

        self.items.push_back(work);
        self.heap_bytes += added;
        if self.items.capacity() != capacity {
            self.ring_bytes = self.items.capacity() * size_of::<Work>();
        }
        true
    }

    fn pop(&mut self) -> Option<Work> {
        let work = self.items.pop_front()?;
        self.heap_bytes = self.heap_bytes.saturating_sub(work.heap_bytes());
        Some(work)
    }
}

pub const DEREFERENCE_ORDER: &str = "A pointer path starts at its base address. For each entry in \
deref_offsets, in order, the offset is added to the current address and the result is \
dereferenced as one target-width pointer, which becomes the new current address. After the last \
dereference, final_offset is added without dereferencing; that sum is the value address.";

pub const STABILITY_CAVEAT: &str = "A module offset or a pointer path is a candidate for \
stability, not a guarantee. It can break across a restart, a binary update, or a different \
allocation order, and a readable path proves neither identity nor stability.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRef {
    pub name: String,
    pub path: String,
    pub base: String,
    pub offset: WireU64,
    pub spec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAddress {
    pub input: String,
    pub form: String,
    pub address: String,
    pub address_raw: WireU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleRef>,
    pub stability: String,
}

fn module_ref(module: &ModuleInfo, address: u64, width: PointerWidth) -> ModuleRef {
    let offset = address - module.base_raw.0;
    ModuleRef {
        name: module.name.clone(),
        path: module.path.clone(),
        base: Address(module.base_raw.0).to_canonical(width),
        offset: WireU64(offset),
        spec: format!("{}+0x{offset:x}", module.name),
    }
}

fn apply_offset(address: u64, offset: i64, width: PointerWidth, operation: &str) -> Result<u64> {
    let result = if offset >= 0 {
        address.checked_add(offset as u64)
    } else {
        address.checked_sub(offset.unsigned_abs())
    };
    let value = result.ok_or_else(|| {
        OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("0x{address:x} {offset:+} leaves the address space"),
        )
        .with_next_step("Use an offset that keeps the address inside the target.")
    })?;
    if value > width.max_address() {
        return Err(OperationError::new(
            ErrorCode::UnsupportedPointerWidth,
            operation,
            format!(
                "0x{address:x} {offset:+} gives 0x{value:x}, past the {}-byte pointer width",
                width.bytes()
            ),
        )
        .with_next_step("A WOW64 target cannot address memory above 0xffffffff."));
    }
    Ok(value)
}

pub fn resolve_address(
    session: &SessionRef,
    modules: &[ModuleInfo],
    spec: &str,
    operation: &str,
) -> Result<ResolvedAddress> {
    let text = spec.trim();
    if text.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "an address specification is required",
        )
        .with_next_step("Supply 0x..., module.dll, or module.dll+0x1234."));
    }

    let split = text
        .rfind('+')
        .map(|i| (i, 1i64))
        .or_else(|| text.rfind('-').filter(|i| *i > 0).map(|i| (i, -1i64)));

    if let Some((index, sign)) = split
        && !text.starts_with("0x")
        && !text.starts_with("0X")
    {
        let (name, rest) = text.split_at(index);
        let offset_text = rest[1..].trim();
        let module = find_module(modules, name.trim(), operation)?;
        let magnitude = Address::parse_hex(offset_text, operation)?.0;
        let offset = i64::try_from(magnitude).map(|v| v * sign).map_err(|_| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("offset {offset_text:?} does not fit in a signed 64-bit offset"),
            )
        })?;
        let address = apply_offset(module.base_raw.0, offset, session.width, operation)?;
        return Ok(ResolvedAddress {
            input: text.to_owned(),
            form: "module_relative".to_owned(),
            address: Address(address).to_canonical(session.width),
            address_raw: WireU64(address),
            module: Some(module_ref(module, address, session.width)),
            stability: STABILITY_CAVEAT.to_owned(),
        });
    }

    if text.starts_with("0x") || text.starts_with("0X") {
        let address = Address::parse_hex(text, operation)?.check_width(session.width, operation)?;
        let module = module_for(modules, address.0);
        return Ok(ResolvedAddress {
            input: text.to_owned(),
            form: "absolute".to_owned(),
            address: address.to_canonical(session.width),
            address_raw: WireU64(address.0),
            module: module.map(|m| module_ref(m, address.0, session.width)),
            stability: if module.is_some() {
                STABILITY_CAVEAT.to_owned()
            } else {
                "An absolute address is specific to this run of this process and is not valid \
                 after a restart."
                    .to_owned()
            },
        });
    }

    let module = find_module(modules, text, operation)?;
    Ok(ResolvedAddress {
        input: text.to_owned(),
        form: "module_base".to_owned(),
        address: Address(module.base_raw.0).to_canonical(session.width),
        address_raw: module.base_raw,
        module: Some(module_ref(module, module.base_raw.0, session.width)),
        stability: STABILITY_CAVEAT.to_owned(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PointerPathSpec {
    pub base: String,
    pub deref_offsets: Vec<i64>,
    #[serde(default)]
    pub final_offset: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerHop {
    pub index: usize,
    pub offset: i64,
    pub read_at: String,
    pub readable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_value_raw: Option<WireU64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerPathResolution {
    pub base_input: String,
    pub base_address: String,
    pub pointer_width: usize,
    pub hops: Vec<PointerHop>,
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_address_raw: Option<WireU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_at_hop: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub dereference_order: String,
    pub stability: String,
}

pub fn resolve_pointer_path(
    session: &SessionRef,
    modules: &[ModuleInfo],
    spec: &PointerPathSpec,
    operation: &str,
) -> Result<PointerPathResolution> {
    if spec.deref_offsets.len() > MAX_PATH_HOPS {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "a pointer path may have at most {MAX_PATH_HOPS} dereferences, got {}",
                spec.deref_offsets.len()
            ),
        ));
    }
    let base = resolve_address(session, modules, &spec.base, operation)?;
    let width = session.width.bytes();
    let mut cursor = base.address_raw.0;
    let mut hops = Vec::with_capacity(spec.deref_offsets.len());

    for (index, &offset) in spec.deref_offsets.iter().enumerate() {
        let read_at = apply_offset(cursor, offset, session.width, operation)?;
        let raw = mem::read_raw(session.handle, Address(read_at), width);
        if raw.bytes.len() < width {
            hops.push(PointerHop {
                index,
                offset,
                read_at: Address(read_at).to_canonical(session.width),
                readable: false,
                raw: None,
                pointer_value: None,
                pointer_value_raw: None,
            });
            return Ok(PointerPathResolution {
                base_input: spec.base.clone(),
                base_address: base.address,
                pointer_width: width,
                hops,
                resolved: false,
                value_address: None,
                value_address_raw: None,
                failed_at_hop: Some(index),
                failure: Some(format!(
                    "hop {index} could not read {width} bytes at {}",
                    Address(read_at).to_canonical(session.width)
                )),
                dereference_order: DEREFERENCE_ORDER.to_owned(),
                stability: STABILITY_CAVEAT.to_owned(),
            });
        }
        let value = match session.width {
            PointerWidth::Four => u64::from(u32::from_le_bytes([
                raw.bytes[0],
                raw.bytes[1],
                raw.bytes[2],
                raw.bytes[3],
            ])),
            PointerWidth::Eight => u64::from_le_bytes([
                raw.bytes[0],
                raw.bytes[1],
                raw.bytes[2],
                raw.bytes[3],
                raw.bytes[4],
                raw.bytes[5],
                raw.bytes[6],
                raw.bytes[7],
            ]),
        };
        hops.push(PointerHop {
            index,
            offset,
            read_at: Address(read_at).to_canonical(session.width),
            readable: true,
            raw: Some(hex(&raw.bytes)),
            pointer_value: Some(Address(value).to_canonical(session.width)),
            pointer_value_raw: Some(WireU64(value)),
        });
        cursor = value;
    }

    let value_address = apply_offset(cursor, spec.final_offset, session.width, operation)?;
    Ok(PointerPathResolution {
        base_input: spec.base.clone(),
        base_address: base.address,
        pointer_width: width,
        hops,
        resolved: true,
        value_address: Some(Address(value_address).to_canonical(session.width)),
        value_address_raw: Some(WireU64(value_address)),
        failed_at_hop: None,
        failure: None,
        dereference_order: DEREFERENCE_ORDER.to_owned(),
        stability: STABILITY_CAVEAT.to_owned(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FindReferencesRequest {
    pub target: String,
    #[serde(default)]
    pub filter: RegionFilter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_scanned: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceHit {
    pub address: String,
    pub address_raw: WireU64,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesOutcome {
    pub target: String,
    pub target_raw: WireU64,
    pub pointer_width: usize,
    pub alignment: usize,
    pub hits: Vec<ReferenceHit>,
    pub retained: usize,
    pub total_known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<WireU64>,
    pub truncated: bool,
    pub stop_reason: StopReason,
    pub regions_eligible: usize,
    pub regions_visited: usize,
    pub bytes_eligible: WireU64,
    pub bytes_visited: WireU64,
    pub bytes_unreadable: WireU64,
    pub limitations: Vec<String>,
}

fn pointer_at(bytes: &[u8], offset: usize, width: PointerWidth) -> u64 {
    match width {
        PointerWidth::Four => u64::from(u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])),
        PointerWidth::Eight => u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]),
    }
}

pub fn find_references(
    session: &SessionRef,
    request: &FindReferencesRequest,
    cancel: &Cancel,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<FindReferencesOutcome> {
    let modules = list_modules(session, operation).unwrap_or_default();
    let target = resolve_address(session, &modules, &request.target, operation)?;
    let width = session.width;
    let item = width.bytes();
    let alignment = request.alignment.unwrap_or(item).max(1);
    if alignment > 4096 {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("alignment {alignment} is above the 4096-byte limit"),
        ));
    }
    let max_results = request.max_results.unwrap_or(10_000).max(1);
    let max_bytes = request.max_bytes_scanned.unwrap_or(2 * 1024 * 1024 * 1024);
    let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(30_000).clamp(1, 600_000));

    let regions = crate::scan::list_regions(session, &request.filter, operation)?;
    let mut regions_eligible = 0usize;
    let mut bytes_eligible = 0u64;
    for region in regions.iter().filter(|r| r.eligible) {
        regions_eligible += 1;
        bytes_eligible += region.size.0;
    }

    let started = Instant::now();
    let mut hits: Vec<ReferenceHit> = Vec::new();
    let mut total = 0u64;
    let mut regions_visited = 0usize;
    let mut bytes_visited = 0u64;
    let mut bytes_unreadable = 0u64;
    let mut stop = StopReason::Completed;
    let mut chunks = 0u32;

    'outer: for region in regions.iter().filter(|r| r.eligible) {
        regions_visited += 1;
        let base = region.base_raw.0;
        let size = region.size.0 as usize;
        let mut offset = 0usize;
        while offset < size {
            if cancel.is_cancelled() {
                stop = StopReason::Cancelled;
                break 'outer;
            }
            if started.elapsed() >= timeout {
                stop = StopReason::Timeout;
                break 'outer;
            }
            if bytes_visited >= max_bytes {
                stop = StopReason::MaxBytesScanned;
                break 'outer;
            }
            chunks += 1;
            if chunks.is_multiple_of(16) {
                policy_check()?;
            }

            let core = POINTER_CHUNK_BYTES.min(size - offset);
            let with_tail = (core + item - 1).min(size - offset);
            let address = base + offset as u64;
            let raw = mem::read_raw(session.handle, Address(address), with_tail);
            let got = raw.bytes.len();
            bytes_visited += got as u64;
            if got < with_tail {
                bytes_unreadable += (with_tail - got) as u64;
            }

            let mut slot = 0usize;
            while slot + item <= got {
                if slot >= core && slot > 0 {
                    break;
                }
                if pointer_at(&raw.bytes, slot, width) == target.address_raw.0 {
                    total += 1;
                    if hits.len() < max_results {
                        let hit_address = address + slot as u64;
                        hits.push(ReferenceHit {
                            address: Address(hit_address).to_canonical(width),
                            address_raw: WireU64(hit_address),
                            raw: hex(&raw.bytes[slot..slot + item]),
                            module: module_for(&modules, hit_address).map(|m| m.name.clone()),
                        });
                    } else {
                        stop = StopReason::MaxResults;
                        break 'outer;
                    }
                }
                slot += alignment;
            }

            if got < with_tail {
                offset += core;
                continue;
            }
            offset += core;
        }
    }

    let truncated = stop.truncates();
    Ok(FindReferencesOutcome {
        target: target.address,
        target_raw: target.address_raw,
        pointer_width: item,
        alignment,
        retained: hits.len(),
        hits,
        total_known: !truncated,
        total: (!truncated).then_some(WireU64(total)),
        truncated,
        stop_reason: stop,
        regions_eligible,
        regions_visited,
        bytes_eligible: WireU64(bytes_eligible),
        bytes_visited: WireU64(bytes_visited),
        bytes_unreadable: WireU64(bytes_unreadable),
        limitations: vec![
            "This is a data search only: it reports readable memory slots whose pointer-sized \
             value equals the target address."
                .to_owned(),
            "No instruction is decoded. A reference from executable code that forms the address \
             in registers, or encodes it as a relative displacement, is not found by this search."
                .to_owned(),
            format!(
                "Only {item}-byte aligned-by-{alignment} slots are examined, so a misaligned \
                 copy of the address is not reported."
            ),
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PointerScanRequest {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_alignment: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_index_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub filter: RegionFilter,
    #[serde(default)]
    pub require_module_base: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerPathCandidate {
    pub base: String,
    pub base_address: String,
    pub base_is_module_relative: bool,
    pub deref_offsets: Vec<i64>,
    pub final_offset: i64,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_value_address: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerScanOutcome {
    pub target: String,
    pub target_raw: WireU64,
    pub pointer_width: usize,
    pub max_depth: usize,
    pub max_offset: u64,
    pub offset_alignment: usize,
    pub index_entries: WireU64,
    pub index_values: usize,
    pub index_bytes: WireU64,
    pub search_bytes: WireU64,
    pub peak_bytes: WireU64,
    pub budget_bytes: WireU64,
    pub budget_note: String,
    pub regions_indexed: usize,
    pub bytes_indexed: WireU64,
    pub bytes_unreadable: WireU64,
    pub index_complete: bool,
    pub paths: Vec<PointerPathCandidate>,
    pub retained: usize,
    pub cycles_detected: usize,
    pub truncated: bool,
    pub stop_reason: StopReason,
    pub dereference_order: String,
    pub coverage_note: String,
    pub stability: String,
    pub index_build_us: WireU64,
    pub search_us: WireU64,
}

pub fn pointer_scan(
    session: &SessionRef,
    request: &PointerScanRequest,
    cancel: &Cancel,
    mut policy_check: impl FnMut() -> Result<()>,
    operation: &str,
) -> Result<PointerScanOutcome> {
    let modules = list_modules(session, operation).unwrap_or_default();
    let target = resolve_address(session, &modules, &request.target, operation)?;
    let width = session.width;
    let item = width.bytes();

    let max_depth = request.max_depth.unwrap_or(4);
    if max_depth == 0 || max_depth > MAX_POINTER_SCAN_DEPTH {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("max_depth {max_depth} must be between 1 and {MAX_POINTER_SCAN_DEPTH}"),
        ));
    }
    let max_offset = request.max_offset.unwrap_or(1024);
    if max_offset > MAX_POINTER_SCAN_OFFSET {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("max_offset {max_offset} is above the {MAX_POINTER_SCAN_OFFSET} limit"),
        ));
    }
    let offset_alignment = request.offset_alignment.unwrap_or(item).max(1);
    let max_results = request.max_results.unwrap_or(256).max(1);
    let max_index_bytes = request
        .max_index_bytes
        .unwrap_or(DEFAULT_POINTER_INDEX_BYTES)
        .max(1024);
    let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(30_000).clamp(1, 600_000));

    let started = Instant::now();
    let regions = crate::scan::list_regions(session, &request.filter, operation)?;

    let mut index = PointerIndex::new();
    let mut regions_indexed = 0usize;
    let mut bytes_indexed = 0u64;
    let mut bytes_unreadable = 0u64;
    let mut index_complete = true;
    let mut stop = StopReason::Completed;
    let mut chunks = 0u32;

    'index: for region in regions.iter().filter(|r| r.eligible) {
        regions_indexed += 1;
        let base = region.base_raw.0;
        let size = region.size.0 as usize;
        let mut offset = 0usize;
        while offset < size {
            if cancel.is_cancelled() {
                stop = StopReason::Cancelled;
                index_complete = false;
                break 'index;
            }
            if started.elapsed() >= timeout {
                stop = StopReason::Timeout;
                index_complete = false;
                break 'index;
            }
            if index.bytes() >= max_index_bytes {
                stop = StopReason::MaxSnapshotBytes;
                index_complete = false;
                break 'index;
            }
            chunks += 1;
            if chunks.is_multiple_of(16) {
                policy_check()?;
            }

            let core = POINTER_CHUNK_BYTES.min(size - offset);
            let with_tail = (core + item - 1).min(size - offset);
            let address = base + offset as u64;
            let raw = mem::read_raw(session.handle, Address(address), with_tail);
            let got = raw.bytes.len();
            bytes_indexed += got as u64;
            if got < with_tail {
                bytes_unreadable += (with_tail - got) as u64;
            }

            let mut slot = 0usize;
            while slot + item <= got {
                if slot >= core && slot > 0 {
                    break;
                }
                let value = pointer_at(&raw.bytes, slot, width);
                if value != 0
                    && value <= width.max_address()
                    && !index.insert_within(value, address + slot as u64, max_index_bytes)
                {
                    stop = StopReason::MaxSnapshotBytes;
                    index_complete = false;
                    break 'index;
                }
                slot += item;
            }
            offset += core;
        }
    }
    let index_build_us = started.elapsed().as_micros() as u64;

    let search_started = Instant::now();
    let mut paths: Vec<PointerPathCandidate> = Vec::new();
    let mut cycles_detected = 0usize;
    let final_offset = 0i64;

    let search_limit = max_index_bytes.saturating_sub(index.bytes());
    let mut queue = Frontier::new();
    let mut search_peak_bytes = 0usize;
    if !queue.push_within(
        Work {
            value: target.address_raw.0,
            trail: Vec::new(),
            visited: vec![target.address_raw.0],
        },
        search_limit,
    ) {
        stop = StopReason::MaxSnapshotBytes;
    }
    search_peak_bytes = search_peak_bytes.max(queue.bytes());

    'search: while let Some(work) = queue.pop() {
        if work.trail.len() >= max_depth {
            continue;
        }
        if cancel.is_cancelled() {
            stop = StopReason::Cancelled;
            break;
        }
        if search_started.elapsed() >= timeout {
            stop = StopReason::Timeout;
            break;
        }

        let Some(holders) = index.holders_of(work.value) else {
            continue;
        };
        for &holder in holders {
            let mut offset = 0u64;
            while offset <= max_offset {
                let Some(previous) = holder.checked_sub(offset) else {
                    break;
                };
                let mut trail = Vec::with_capacity(work.trail.len() + 1);
                trail.push(offset as i64);
                trail.extend_from_slice(&work.trail);

                if let Some(module) = module_for(&modules, previous) {
                    let candidate = PointerPathCandidate {
                        base: format!("{}+0x{:x}", module.name, previous - module.base_raw.0),
                        base_address: Address(previous).to_canonical(width),
                        base_is_module_relative: true,
                        deref_offsets: trail.clone(),
                        final_offset,
                        depth: trail.len(),
                        verified_value_address: None,
                        verified: false,
                    };
                    paths.push(candidate);
                    if paths.len() >= max_results {
                        stop = StopReason::MaxResults;
                        break 'search;
                    }
                } else if !request.require_module_base && trail.len() >= max_depth {
                    paths.push(PointerPathCandidate {
                        base: Address(previous).to_canonical(width),
                        base_address: Address(previous).to_canonical(width),
                        base_is_module_relative: false,
                        deref_offsets: trail.clone(),
                        final_offset,
                        depth: trail.len(),
                        verified_value_address: None,
                        verified: false,
                    });
                    if paths.len() >= max_results {
                        stop = StopReason::MaxResults;
                        break 'search;
                    }
                }

                if trail.len() < max_depth {
                    if work.visited.contains(&previous) {
                        cycles_detected += 1;
                    } else {
                        let mut visited = work.visited.clone();
                        visited.push(previous);
                        if !queue.push_within(
                            Work {
                                value: previous,
                                trail,
                                visited,
                            },
                            search_limit,
                        ) {
                            stop = StopReason::MaxSnapshotBytes;
                            break 'search;
                        }
                        search_peak_bytes = search_peak_bytes.max(queue.bytes());
                    }
                }

                if offset_alignment == 0 {
                    break;
                }
                offset += offset_alignment as u64;
            }
        }
    }

    for candidate in &mut paths {
        let spec = PointerPathSpec {
            base: candidate.base.clone(),
            deref_offsets: candidate.deref_offsets.clone(),
            final_offset: candidate.final_offset,
        };
        if let Ok(resolution) = resolve_pointer_path(session, &modules, &spec, operation)
            && resolution.resolved
            && resolution.value_address_raw.map(|a| a.0) == Some(target.address_raw.0)
        {
            candidate.verified_value_address = resolution.value_address;
            candidate.verified = true;
        }
    }

    let truncated = stop.truncates() || !index_complete;
    Ok(PointerScanOutcome {
        target: target.address,
        target_raw: target.address_raw,
        pointer_width: item,
        max_depth,
        max_offset,
        offset_alignment,
        index_entries: WireU64(index.pairs()),
        index_values: index.values(),
        index_bytes: WireU64(index.bytes() as u64),
        search_bytes: WireU64(search_peak_bytes as u64),
        peak_bytes: WireU64((index.bytes() + search_peak_bytes) as u64),
        budget_bytes: WireU64(max_index_bytes as u64),
        budget_note: INDEX_BUDGET_NOTE.to_owned(),
        regions_indexed,
        bytes_indexed: WireU64(bytes_indexed),
        bytes_unreadable: WireU64(bytes_unreadable),
        index_complete,
        retained: paths.len(),
        paths,
        cycles_detected,
        truncated,
        stop_reason: stop,
        dereference_order: DEREFERENCE_ORDER.to_owned(),
        coverage_note: format!(
            "The index covered {regions_indexed} eligible regions and {bytes_indexed} bytes, \
             with {bytes_unreadable} bytes unreadable. A path that passes through memory outside \
             that coverage cannot be found."
        ),
        stability: STABILITY_CAVEAT.to_owned(),
        index_build_us: WireU64(index_build_us),
        search_us: WireU64(search_started.elapsed().as_micros() as u64),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StoredPointerPath {
    pub id: String,
    pub session_id: String,
    pub base: String,
    pub deref_offsets: Vec<i64>,
    #[serde(default)]
    pub final_offset: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_value_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_address_raw: Option<WireU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescanVerdict {
    Survived,
    Broken,
    ResolvedElsewhere,
    ResolvedUnverified,
}

impl RescanVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Survived => "survived",
            Self::Broken => "broken",
            Self::ResolvedElsewhere => "resolved_elsewhere",
            Self::ResolvedUnverified => "resolved_unverified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanResult {
    pub id: String,
    pub verdict: RescanVerdict,
    pub stored_session_id: String,
    pub current_session_id: String,
    pub resolution: PointerPathResolution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_value_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_value_raw: Option<String>,
    pub oracle: String,
    pub reason: String,
}

pub fn rescan_pointer_paths(
    session: &SessionRef,
    paths: &[StoredPointerPath],
    value_bytes: usize,
    operation: &str,
) -> Result<Vec<RescanResult>> {
    if paths.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "rescan_pointer_paths needs at least one stored path",
        ));
    }
    if value_bytes == 0 || value_bytes > 4096 {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!("value_bytes {value_bytes} must be between 1 and 4096"),
        ));
    }
    let modules = list_modules(session, operation).unwrap_or_default();
    let mut out = Vec::with_capacity(paths.len());

    for stored in paths {
        let spec = PointerPathSpec {
            base: stored.base.clone(),
            deref_offsets: stored.deref_offsets.clone(),
            final_offset: stored.final_offset,
        };
        let resolution = match resolve_pointer_path(session, &modules, &spec, operation) {
            Ok(r) => r,
            Err(e) => {
                out.push(RescanResult {
                    id: stored.id.clone(),
                    verdict: RescanVerdict::Broken,
                    stored_session_id: stored.session_id.clone(),
                    current_session_id: session.id.clone(),
                    resolution: PointerPathResolution {
                        base_input: stored.base.clone(),
                        base_address: String::new(),
                        pointer_width: session.width.bytes(),
                        hops: Vec::new(),
                        resolved: false,
                        value_address: None,
                        value_address_raw: None,
                        failed_at_hop: None,
                        failure: Some(e.message.clone()),
                        dereference_order: DEREFERENCE_ORDER.to_owned(),
                        stability: STABILITY_CAVEAT.to_owned(),
                    },
                    current_value_raw: None,
                    expected_value_raw: stored.expected_value_raw.clone(),
                    oracle: "none".to_owned(),
                    reason: format!("the path could not be resolved at all: {}", e.message),
                });
                continue;
            }
        };

        if !resolution.resolved {
            out.push(RescanResult {
                id: stored.id.clone(),
                verdict: RescanVerdict::Broken,
                stored_session_id: stored.session_id.clone(),
                current_session_id: session.id.clone(),
                current_value_raw: None,
                expected_value_raw: stored.expected_value_raw.clone(),
                oracle: "none".to_owned(),
                reason: resolution
                    .failure
                    .clone()
                    .unwrap_or_else(|| "a hop was unreadable".to_owned()),
                resolution,
            });
            continue;
        }

        let value_address = resolution.value_address_raw.expect("resolved").0;
        let raw = mem::read_raw(session.handle, Address(value_address), value_bytes);
        let current = (raw.bytes.len() == value_bytes).then(|| hex(&raw.bytes));

        let same_session = stored.session_id == session.id;
        let (verdict, oracle, reason) = match (
            &stored.expected_value_raw,
            stored.expected_address_raw,
        ) {
            (Some(expected), _) => match &current {
                Some(actual) if actual.eq_ignore_ascii_case(expected) => (
                    RescanVerdict::Survived,
                    "expected value bytes".to_owned(),
                    format!("the path resolved and the value still reads {expected}"),
                ),
                Some(actual) => (
                    RescanVerdict::ResolvedElsewhere,
                    "expected value bytes".to_owned(),
                    format!(
                        "the path resolved to {} but the value reads {actual}, not {expected}",
                        resolution.value_address.clone().unwrap_or_default()
                    ),
                ),
                None => (
                    RescanVerdict::Broken,
                    "expected value bytes".to_owned(),
                    "the path resolved but the value address was not readable".to_owned(),
                ),
            },
            (None, Some(expected_address)) if same_session => {
                if expected_address.0 == value_address {
                    (
                        RescanVerdict::Survived,
                        "expected address from this same session".to_owned(),
                        "the path resolved to the same address it did before".to_owned(),
                    )
                } else {
                    (
                        RescanVerdict::ResolvedElsewhere,
                        "expected address from this same session".to_owned(),
                        format!(
                            "the path resolved to 0x{value_address:x} instead of 0x{:x}",
                            expected_address.0
                        ),
                    )
                }
            }
            (None, Some(_)) => (
                RescanVerdict::ResolvedUnverified,
                "none usable".to_owned(),
                format!(
                    "the path resolved, but the stored absolute address came from session {} and \
                     is not a valid oracle for session {}: an old absolute address proves nothing \
                     after a restart",
                    stored.session_id, session.id
                ),
            ),
            (None, None) => (
                RescanVerdict::ResolvedUnverified,
                "none supplied".to_owned(),
                "the path resolved and is readable, but no independent oracle was supplied, so \
                 only readability and the resolved location are reported"
                    .to_owned(),
            ),
        };

        out.push(RescanResult {
            id: stored.id.clone(),
            verdict,
            stored_session_id: stored.session_id.clone(),
            current_session_id: session.id.clone(),
            resolution,
            current_value_raw: current,
            expected_value_raw: stored.expected_value_raw.clone(),
            oracle,
            reason,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::PointerWidth;

    fn module(name: &str, path: &str, base: u64, size: u64) -> ModuleInfo {
        ModuleInfo {
            name: name.to_owned(),
            path: path.to_owned(),
            base: Address(base).to_canonical(PointerWidth::Eight),
            base_raw: WireU64(base),
            size: WireU64(size),
            end_raw: WireU64(base + size),
        }
    }

    fn real_holder_bytes(index: &PointerIndex) -> usize {
        index
            .holders
            .values()
            .map(|v| v.capacity() * HOLDER_SLOT_BYTES)
            .sum()
    }

    #[test]
    fn a_bucket_count_is_the_tightest_power_of_two_that_holds_the_entries() {
        for entries in [1usize, 3, 4, 7, 8, 9, 100, 1000, 100_000] {
            let bytes = table_bytes_for(entries);
            let buckets = bytes / INDEX_BUCKET_BYTES;
            assert!(
                buckets.is_power_of_two(),
                "{entries} gave {buckets} buckets"
            );
            assert!(
                usable_capacity(buckets) >= entries,
                "{entries} does not fit"
            );
            assert!(
                buckets == MIN_TABLE_BUCKETS || usable_capacity(buckets / 2) < entries,
                "{entries} fits in half as many buckets"
            );
        }
        assert_eq!(table_bytes_for(0), 0);
    }

    #[test]
    fn the_index_charges_the_table_and_every_holder_vector() {
        let mut index = PointerIndex::new();
        let limit = 1 << 20;
        for i in 0..500u64 {
            assert!(index.insert_within(0x1000 + i * 8, 0x40_0000 + i * 8, limit));
        }
        for i in 0..50u64 {
            assert!(index.insert_within(0x1000, 0x50_0000 + i * 8, limit));
        }

        assert_eq!(index.values(), 500);
        assert_eq!(index.pairs(), 550);
        assert_eq!(index.holder_bytes, real_holder_bytes(&index));
        assert_eq!(index.table_bytes, table_bytes_for(index.holders.capacity()));
        assert_eq!(index.bytes(), index.table_bytes + index.holder_bytes);
    }

    #[test]
    fn the_old_sixteen_bytes_per_pointer_model_understated_the_index() {
        let mut index = PointerIndex::new();
        let limit = 1 << 20;
        for i in 0..1000u64 {
            assert!(index.insert_within(0x1000 + i * 8, 0x40_0000 + i * 8, limit));
        }
        let old_model = 2 * size_of::<u64>() * index.pairs() as usize;
        assert!(
            index.bytes() > old_model * 2,
            "one holder per value costs {} bytes, not the {old_model} the old model charged",
            index.bytes()
        );
    }

    #[test]
    fn the_index_never_passes_its_budget() {
        for limit in [1024usize, 4096, 64 * 1024, 300 * 1024] {
            let mut index = PointerIndex::new();
            let mut refused = false;
            for i in 0..200_000u64 {
                let value = 0x1000 + (i % 5000) * 8;
                if !index.insert_within(value, 0x40_0000 + i * 8, limit) {
                    refused = true;
                    break;
                }
                assert!(
                    index.bytes() <= limit,
                    "limit {limit} passed: {} bytes after {i} inserts",
                    index.bytes()
                );
            }
            assert!(refused, "limit {limit} was never enforced");
            assert_eq!(index.holder_bytes, real_holder_bytes(&index));
        }
    }

    #[test]
    fn a_refused_insert_leaves_the_index_unchanged() {
        let mut index = PointerIndex::new();
        let limit = 4096;
        let mut inserted = 0u64;
        for i in 0..100_000u64 {
            if !index.insert_within(0x1000 + i * 8, 0x40_0000 + i * 8, limit) {
                break;
            }
            inserted += 1;
        }
        let bytes = index.bytes();
        let values = index.values();
        assert!(!index.insert_within(0xdead_0000, 0xbeef_0000, limit));
        assert_eq!(index.pairs(), inserted);
        assert_eq!(index.values(), values);
        assert_eq!(index.bytes(), bytes);
    }

    #[test]
    fn a_frontier_charges_its_ring_and_every_queued_path() {
        let mut queue = Frontier::new();
        let limit = 64 * 1024;
        for i in 0..100u64 {
            assert!(queue.push_within(
                Work {
                    value: i,
                    trail: vec![0; 4],
                    visited: vec![0; 4],
                },
                limit,
            ));
            assert!(queue.bytes() <= limit);
        }
        let expected_heap: usize = queue.items.iter().map(Work::heap_bytes).sum();
        assert_eq!(queue.heap_bytes, expected_heap);
        assert_eq!(queue.ring_bytes, queue.items.capacity() * size_of::<Work>());

        let before = queue.bytes();
        let popped = queue.pop().expect("one queued path");
        assert_eq!(queue.bytes(), before - popped.heap_bytes());
    }

    #[test]
    fn a_frontier_refuses_the_push_that_would_pass_its_budget() {
        let mut queue = Frontier::new();
        let limit = 2048;
        let mut pushed = 0;
        while queue.push_within(
            Work {
                value: pushed,
                trail: vec![0; 8],
                visited: vec![0; 8],
            },
            limit,
        ) {
            pushed += 1;
            assert!(queue.bytes() <= limit);
            assert!(pushed < 10_000, "the budget was never enforced");
        }
        assert!(pushed > 0, "nothing fitted in {limit} bytes");
        assert!(queue.bytes() <= limit);
    }

    #[test]
    fn a_zero_budget_frontier_accepts_nothing() {
        let mut queue = Frontier::new();
        assert!(!queue.push_within(
            Work {
                value: 1,
                trail: Vec::new(),
                visited: vec![1],
            },
            0,
        ));
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn a_module_contains_its_base_but_not_its_end() {
        let m = module("a.dll", r"C:\a\a.dll", 0x1000, 0x1000);
        assert!(m.contains(0x1000));
        assert!(m.contains(0x1fff));
        assert!(!m.contains(0x2000));
        assert!(!m.contains(0x0fff));
    }

    #[test]
    fn an_address_maps_to_the_module_that_covers_it() {
        let modules = vec![
            module("a.dll", r"C:\a\a.dll", 0x1000, 0x1000),
            module("b.dll", r"C:\b\b.dll", 0x4000, 0x1000),
        ];
        assert_eq!(
            module_for(&modules, 0x1500).map(|m| m.name.as_str()),
            Some("a.dll")
        );
        assert_eq!(
            module_for(&modules, 0x4500).map(|m| m.name.as_str()),
            Some("b.dll")
        );
        assert!(module_for(&modules, 0x3000).is_none());
    }

    #[test]
    fn a_duplicate_basename_is_refused_unless_a_path_disambiguates_it() {
        let modules = vec![
            module("dup.dll", r"C:\one\dup.dll", 0x1000, 0x1000),
            module("dup.dll", r"C:\two\dup.dll", 0x4000, 0x1000),
        ];
        let err = find_module(&modules, "dup.dll", "resolve_address")
            .expect_err("an ambiguous basename must be refused, not guessed");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert!(err.message.contains("ambiguous"), "got {}", err.message);

        let picked = find_module(&modules, r"C:\two\dup.dll", "resolve_address").expect("by path");
        assert_eq!(picked.base_raw.0, 0x4000);
    }

    #[test]
    fn module_lookup_is_case_insensitive_and_reports_a_missing_name() {
        let modules = vec![module("A.dll", r"C:\a\A.dll", 0x1000, 0x1000)];
        assert!(find_module(&modules, "a.DLL", "resolve_address").is_ok());
        let err = find_module(&modules, "absent.dll", "resolve_address").expect_err("missing");
        assert!(
            err.message.contains("no module named"),
            "got {}",
            err.message
        );
        assert!(find_module(&modules, "   ", "resolve_address").is_err());
    }
}
