use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime};

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, OperationError};
use crate::investigate::{self, DissectRequest, WatchRequest};
use crate::mem::{self, BatchItemRequest, SessionRef, StructFieldSpec, ValueType};
use crate::mutate::{
    self, FailureJournal, FreezeRegistry, FreezeRequest, FreezeStopReason, UndoHistory,
    UndoRequest, UnfreezeRequest, WriteRequest,
};
use crate::policy::Policy;
use crate::ptr::{
    self, FindReferencesRequest, PointerPathSpec, PointerScanRequest, StoredPointerPath,
};
use crate::scan::{
    self, Cancel, FirstScanRequest, GroupScanRequest, ListResultsRequest, NextScanRequest,
    RegionFilter, ScanState,
};
use crate::target::{self, Session};
use crate::wire::Address;

pub const NEGOTIATED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2025_11_25;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub const TOOL_NAMES: [&str; 27] = [
    "server_status",
    "list_processes",
    "attach_process",
    "detach_process",
    "list_regions",
    "first_scan",
    "next_scan",
    "list_results",
    "reset_scan",
    "group_scan",
    "read_memory",
    "read_batch",
    "read_bytes",
    "read_struct",
    "list_modules",
    "resolve_address",
    "pointer_scan",
    "resolve_pointer_path",
    "rescan_pointer_paths",
    "find_references",
    "watch_value",
    "dissect_region",
    "write_memory",
    "undo_write",
    "freeze_value",
    "unfreeze_value",
    "list_frozen",
];

struct ServerState {
    session: Option<Session>,
    scan: Option<ScanState>,
    history: UndoHistory,
    journal: FailureJournal,
    freezes: FreezeRegistry,
    cancel: Cancel,
    started_at: SystemTime,
    active: Option<ActiveOperation>,
    next_operation_id: u64,
}

struct ActiveOperation {
    id: u64,
    operation: &'static str,
    started_at: Instant,
    owns_scan_state: bool,
    scan_state_present: bool,
}

impl ActiveOperation {
    fn refusal(&self, operation: &str) -> OperationError {
        OperationError::new(
            ErrorCode::OperationInFlight,
            operation,
            format!(
                "{} has been running for {} ms and holds this session",
                self.operation,
                self.started_at.elapsed().as_millis()
            ),
        )
        .with_next_step(
            "One long-running tool runs at a time. Wait for it, or cancel its request with a              notifications/cancelled for that request id, then retry.",
        )
    }
}

fn no_scan_state(operation: &str) -> OperationError {
    OperationError::new(
        ErrorCode::ScanStateInvalid,
        operation,
        "no scan state exists in this session",
    )
    .with_next_step("Run first_scan before narrowing or listing results.")
}

#[derive(Clone)]
pub struct MemScope {
    policy: Arc<Mutex<Policy>>,
    state: Arc<Mutex<ServerState>>,
    tool_router: ToolRouter<Self>,
}

type ToolResult = std::result::Result<CallToolResult, McpError>;

fn ok<T: Serialize>(value: &T) -> ToolResult {
    let json = serde_json::to_value(value)
        .map_err(|e| McpError::internal_error(format!("cannot serialise the result: {e}"), None))?;
    let text = serde_json::to_string(&json).unwrap_or_default();
    if text.len() > MAX_RESPONSE_BYTES {
        return Ok(fail(
            OperationError::new(
                ErrorCode::BudgetExceeded,
                "serialise_response",
                format!(
                    "the response is {} bytes, over the {MAX_RESPONSE_BYTES}-byte limit",
                    text.len()
                ),
            )
            .with_next_step("Lower display_limit or narrow the request, then retry."),
        ));
    }
    let mut result = CallToolResult::structured(json);
    result.content = vec![ContentBlock::text(text)];
    Ok(result)
}

fn fail(error: OperationError) -> CallToolResult {
    let json = serde_json::to_value(&error).unwrap_or_else(|_| serde_json::json!({}));
    let text = serde_json::to_string_pretty(&json).unwrap_or_else(|_| error.to_string());
    let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
    result.structured_content = Some(json);
    result
}

fn done<T: Serialize>(outcome: crate::error::Result<T>) -> ToolResult {
    match outcome {
        Ok(value) => ok(&value),
        Err(error) => Ok(fail(error)),
    }
}

impl ServerState {
    fn session_for(&self, operation: &str) -> crate::error::Result<&Session> {
        self.session.as_ref().ok_or_else(|| {
            OperationError::new(
                ErrorCode::NotAttached,
                operation,
                "no process is attached to this server",
            )
            .with_next_step("Call attach_process with a live PID first.")
        })
    }

    fn read_ref(&self, operation: &str) -> crate::error::Result<SessionRef> {
        Ok(self.session_for(operation)?.read_ref())
    }

    fn scan_for(&mut self, operation: &str) -> crate::error::Result<&mut ScanState> {
        self.refuse_if_scan_busy(operation)?;
        self.scan.as_mut().ok_or_else(|| no_scan_state(operation))
    }

    fn refuse_if_busy(&self, operation: &str) -> crate::error::Result<()> {
        match &self.active {
            Some(active) => Err(active.refusal(operation)),
            None => Ok(()),
        }
    }

    fn refuse_if_scan_busy(&self, operation: &str) -> crate::error::Result<()> {
        match &self.active {
            Some(active) if active.owns_scan_state => Err(active.refusal(operation)),
            _ => Ok(()),
        }
    }

    fn scan_present(&self) -> bool {
        self.scan.is_some()
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.scan_state_present)
    }
}

struct OperationLease<'a> {
    server: &'a MemScope,
    id: u64,
    session: SessionRef,
    exe: String,
    owns_scan: bool,
    scan: Option<ScanState>,
    _handle: crate::win::OwnedHandle,
}

impl Drop for OperationLease<'_> {
    fn drop(&mut self) {
        let Ok(mut state) = self.server.state.lock() else {
            return;
        };
        if self.owns_scan && state.session.is_some() {
            state.scan = self.scan.take();
        }
        if state.active.as_ref().is_some_and(|a| a.id == self.id) {
            state.active = None;
        }
    }
}

impl MemScope {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(Mutex::new(policy)),
            state: Arc::new(Mutex::new(ServerState {
                session: None,
                scan: None,
                history: UndoHistory::default(),
                journal: FailureJournal::default(),
                freezes: FreezeRegistry::default(),
                cancel: Cancel::new(),
                started_at: SystemTime::now(),
                active: None,
                next_operation_id: 1,
            })),
            tool_router: Self::tool_router(),
        }
    }

    fn lock_state(&self, operation: &str) -> crate::error::Result<MutexGuard<'_, ServerState>> {
        self.state.lock().map_err(|_| {
            OperationError::new(
                ErrorCode::ScanStateInvalid,
                operation,
                "the server state lock is poisoned by an earlier panic",
            )
            .with_next_step("Restart the server; its in-memory state can no longer be trusted.")
        })
    }

    fn lock_policy(&self, operation: &str) -> crate::error::Result<MutexGuard<'_, Policy>> {
        self.policy.lock().map_err(|_| {
            OperationError::new(
                ErrorCode::TargetNotAllowed,
                operation,
                "the policy lock is poisoned by an earlier panic",
            )
            .with_next_step("Restart the server; the policy can no longer be trusted.")
        })
    }

    async fn run_cancellable<W, T>(
        &self,
        ct: tokio_util::sync::CancellationToken,
        operation: &'static str,
        work: W,
    ) -> ToolResult
    where
        W: FnOnce(&MemScope, Cancel) -> crate::error::Result<T> + Send + 'static,
        T: Serialize + Send + 'static,
    {
        let cancel = Cancel::new();
        let watcher_cancel = cancel.clone();
        let watcher_token = ct.clone();
        let watcher = tokio::spawn(async move {
            watcher_token.cancelled().await;
            watcher_cancel.cancel();
        });

        let server = self.clone();
        let joined = tokio::task::spawn_blocking(move || work(&server, cancel)).await;
        watcher.abort();

        match joined {
            Ok(outcome) => done(outcome),
            Err(e) => Ok(fail(
                OperationError::new(
                    ErrorCode::Cancelled,
                    operation,
                    format!("the operation task ended before returning a result: {e}"),
                )
                .with_next_step(
                    "The request was cancelled or the worker panicked; no partial result is \
                     reported as complete.",
                ),
            )),
        }
    }

    fn begin(
        &self,
        operation: &'static str,
        take_scan: bool,
    ) -> crate::error::Result<OperationLease<'_>> {
        let mut state = self.lock_state(operation)?;
        state.refuse_if_busy(operation)?;
        self.checkpoint(&state, operation)?;

        let (exe, handle, mut session) = {
            let attached = state.session_for(operation)?;
            let handle = crate::win::duplicate_for_worker(
                attached.handle(),
                operation,
                "a long-running tool",
            )?;
            (
                attached.identity().exe_canonical.clone(),
                handle,
                attached.read_ref(),
            )
        };
        session.handle = handle.raw();

        let scan = if take_scan { state.scan.take() } else { None };
        let id = state.next_operation_id;
        state.next_operation_id = state.next_operation_id.wrapping_add(1);
        state.active = Some(ActiveOperation {
            id,
            operation,
            started_at: Instant::now(),
            owns_scan_state: take_scan,
            scan_state_present: scan.is_some(),
        });

        Ok(OperationLease {
            server: self,
            id,
            session,
            exe,
            owns_scan: take_scan,
            scan,
            _handle: handle,
        })
    }

    fn checkpoint(&self, state: &ServerState, operation: &str) -> crate::error::Result<()> {
        let session = state.session_for(operation)?;
        let mut policy = self.lock_policy(operation)?;
        session.ensure_identity(&mut policy, operation)
    }

    fn policy_checker(
        &self,
        _exe_path: String,
        operation: &'static str,
    ) -> Box<dyn Fn() -> crate::error::Result<()> + Send> {
        let policy = Arc::clone(&self.policy);
        Box::new(move || {
            let mut guard = policy.lock().map_err(|_| {
                OperationError::new(
                    ErrorCode::TargetNotAllowed,
                    operation,
                    "the policy lock is poisoned",
                )
            })?;
            guard.revalidate()
        })
    }
}

#[derive(Debug, Serialize)]
struct ServerStatus {
    server: &'static str,
    version: &'static str,
    protocol_version: String,
    tool_count: usize,
    uptime_seconds: u64,
    host_supported: bool,
    writes_enabled_in_environment: bool,
    native_paused_mode: &'static str,
    target_selection: &'static str,
    policy_source: String,
    policy_entries: usize,
    policy_usable: bool,
    policy_problem: Option<String>,
    denied_roots: Vec<String>,
    attached: bool,
    session: Option<SessionSummary>,
    scan_present: bool,
    operation_in_flight: Option<InFlight>,
    concurrency_note: &'static str,
    undo_entries: usize,
    undo_dropped: usize,
    failed_operations: usize,
    active_freezes: usize,
    limits: Limits,
    capabilities_note: &'static str,
}

#[derive(Debug, Serialize)]
struct InFlight {
    operation: &'static str,
    running_ms: u64,
    owns_scan_state: bool,
}

#[derive(Debug, Serialize)]
struct Limits {
    max_response_bytes: usize,
    max_read_bytes: usize,
    max_write_bytes: usize,
    max_batch_items: usize,
    max_struct_fields: usize,
    max_freeze_workers: usize,
    max_scan_timeout_ms: u64,
    max_watch_duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct SessionSummary {
    session_id: String,
    pid: u32,
    creation_time: String,
    architecture: String,
    pointer_width_bytes: usize,
    executable: String,
    executable_sha256: String,
    owner_sid: String,
    capabilities: target::Capabilities,
    liveness: target::Liveness,
}

fn session_summary(session: &Session) -> SessionSummary {
    SessionSummary {
        session_id: session.id().to_owned(),
        pid: session.pid(),
        creation_time: session.identity().creation_time.clone(),
        architecture: session.arch().as_str().to_owned(),
        pointer_width_bytes: session.arch().pointer_width().bytes(),
        executable: session.identity().exe_canonical.clone(),
        executable_sha256: session.exe_sha256().to_owned(),
        owner_sid: session.owner_sid().to_owned(),
        capabilities: session.capabilities(),
        liveness: session.liveness(),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NoParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AttachParams {
    pub pid: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DetachParams {
    #[serde(default)]
    pub restore_frozen_values: bool,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegionsParams {
    #[serde(default)]
    pub filter: RegionFilter,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadMemoryParams {
    pub address: String,
    pub value_type: ValueType,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default)]
    pub max_chars: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadBytesParams {
    pub address: String,
    pub length: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadBatchParams {
    pub items: Vec<BatchItemRequest>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadStructParams {
    pub address: String,
    pub fields: Vec<StructFieldSpec>,
    #[serde(default)]
    pub total_size: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveAddressParams {
    pub address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RescanPathsParams {
    pub paths: Vec<StoredPointerPath>,
    pub value_bytes: usize,
}

#[derive(Debug, Serialize)]
struct DetachOutcome {
    detached: bool,
    session_id: String,
    pid: u32,
    stopped_freezes: Vec<String>,
    restored: Vec<mutate::UnfreezeOutcome>,
    cleared_scan: bool,
    cleared_undo_entries: usize,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AttachOutcome {
    session: SessionSummary,
    authorisation: AuthorisationSummary,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AuthorisationSummary {
    canonical_path: String,
    measured_sha256: String,
    note: Option<String>,
    policy_source: String,
    hash_pin_meaning: &'static str,
}

#[tool_router(vis = "pub")]
impl MemScope {
    #[tool(
        name = "server_status",
        description = "Report server capabilities, limits, policy state, and the attached session."
    )]
    fn server_status(&self, _p: Parameters<NoParams>) -> ToolResult {
        const OP: &str = "server_status";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let mut policy = match self.lock_policy(OP) {
            Ok(p) => p,
            Err(e) => return Ok(fail(e)),
        };
        let _ = policy.revalidate();

        ok(&ServerStatus {
            server: "memscope",
            version: crate::VERSION,
            protocol_version: NEGOTIATED_PROTOCOL_VERSION.to_string(),
            tool_count: TOOL_NAMES.len(),
            uptime_seconds: state.started_at.elapsed().map(|d| d.as_secs()).unwrap_or(0),
            host_supported: target::host_is_supported(),
            writes_enabled_in_environment: crate::writes_enabled_in_environment(),
            native_paused_mode: "not implemented; consistency=paused is refused with \
                                 CONSISTENCY_UNAVAILABLE and no target thread is ever suspended",
            target_selection: "unrestricted",
            policy_source: policy.source().display().to_string(),
            policy_entries: policy.entry_count(),
            policy_usable: policy.poisoned_reason().is_none(),
            policy_problem: policy.poisoned_reason().map(str::to_owned),
            denied_roots: policy
                .denied_roots()
                .iter()
                .map(|r| format!("{} ({})", r.path.display, r.reason))
                .collect(),
            attached: state.session.is_some(),
            session: state.session.as_ref().map(session_summary),
            scan_present: state.scan_present(),
            operation_in_flight: state.active.as_ref().map(|active| InFlight {
                operation: active.operation,
                running_ms: active.started_at.elapsed().as_millis() as u64,
                owns_scan_state: active.owns_scan_state,
            }),
            concurrency_note: "A long-running tool holds a duplicated handle and no server                                lock, so status, reads, writes and freezes stay answerable while                                it runs. One long-running tool runs at a time: a second, and                                detach_process, are refused with OPERATION_IN_FLIGHT, as are the                                scan-state tools while a scan owns that state.",
            undo_entries: state.history.len(),
            undo_dropped: state.history.dropped(),
            failed_operations: state.journal.len(),
            active_freezes: state.freezes.active_count(),
            limits: Limits {
                max_response_bytes: MAX_RESPONSE_BYTES,
                max_read_bytes: mem::MAX_READ_BYTES,
                max_write_bytes: mutate::MAX_WRITE_BYTES,
                max_batch_items: mem::MAX_BATCH_ITEMS,
                max_struct_fields: mem::MAX_STRUCT_FIELDS,
                max_freeze_workers: mutate::MAX_FREEZE_WORKERS,
                max_scan_timeout_ms: scan::MAX_TIMEOUT_MS,
                max_watch_duration_ms: investigate::MAX_WATCH_DURATION_MS,
            },
            capabilities_note: "This server reads and, when both write gates are open, modifies \
                                memory of processes accessible to the current Windows token. It never executes code \
                                in a target, injects a library, attaches a debugger, elevates, or \
                                changes page protection.",
        })
    }

    #[tool(
        name = "list_processes",
        description = "Enumerate processes with owner, architecture, and Windows access limitations."
    )]
    fn list_processes(&self, _p: Parameters<NoParams>) -> ToolResult {
        const OP: &str = "list_processes";
        let mut policy = match self.lock_policy(OP) {
            Ok(p) => p,
            Err(e) => return Ok(fail(e)),
        };
        done(target::list_processes(&mut policy, OP))
    }

    #[tool(
        name = "attach_process",
        description = "Attach to any PID Windows permits, binding a session to its handle, creation time and executable identity."
    )]
    fn attach_process(&self, Parameters(params): Parameters<AttachParams>) -> ToolResult {
        const OP: &str = "attach_process";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if state.session.is_some() {
            return Ok(fail(
                OperationError::new(
                    ErrorCode::InvalidArgument,
                    OP,
                    "this server already holds a session",
                )
                .with_next_step("Call detach_process before attaching to another target."),
            ));
        }
        let mut policy = match self.lock_policy(OP) {
            Ok(p) => p,
            Err(e) => return Ok(fail(e)),
        };
        match Session::attach(params.pid, &mut policy, OP) {
            Err(e) => Ok(fail(e)),
            Ok((session, authorisation)) => {
                let summary = session_summary(&session);
                state.session = Some(session);
                state.scan = None;
                state.cancel = Cancel::new();
                ok(&AttachOutcome {
                    session: summary,
                    authorisation: AuthorisationSummary {
                        canonical_path: authorisation.canonical_path,
                        measured_sha256: authorisation.measured_sha256,
                        note: authorisation.note,
                        policy_source: authorisation.policy_source,
                        hash_pin_meaning: "Optional SHA-256 metadata, empty when unavailable. \
                                           It is not a target restriction and not Authenticode \
                                           verification; mapped pages may differ from the file.",
                    },
                    notes: vec![
                        "Reads are available. Writes additionally require MEMSCOPE_ALLOW_WRITE=1 \
                         and confirm=true on each mutating call."
                            .to_owned(),
                    ],
                })
            }
        }
    }

    #[tool(
        name = "detach_process",
        description = "Stop all workers, clear scan and undo state, and release the session. Optionally restore frozen values first."
    )]
    fn detach_process(&self, Parameters(params): Parameters<DetachParams>) -> ToolResult {
        const OP: &str = "detach_process";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = state.refuse_if_busy(OP) {
            return Ok(fail(e));
        }
        let Some(session) = state.session.as_ref() else {
            return Ok(fail(
                OperationError::new(ErrorCode::NotAttached, OP, "no process is attached")
                    .with_next_step("Nothing to detach."),
            ));
        };
        let session_id = session.id().to_owned();
        let pid = session.pid();
        let read_ref = session.read_ref();

        let mut restored = Vec::new();
        let mut notes = Vec::new();
        if params.restore_frozen_values {
            let ids: Vec<String> = state
                .freezes
                .views()
                .into_iter()
                .filter(|v| v.stats.running && v.session_id == session_id)
                .map(|v| v.freeze_id)
                .collect();
            let write_handle = state.session.as_ref().and_then(|s| s.write_handle(OP).ok());
            for id in ids {
                match write_handle {
                    None => notes.push(format!(
                        "freeze {id} was stopped but not restored: this session holds no write \
                         handle"
                    )),
                    Some(handle) => {
                        let policy = Arc::clone(&self.policy);
                        let outcome = mutate::unfreeze_value(
                            &read_ref,
                            handle,
                            &UnfreezeRequest {
                                freeze_id: id.clone(),
                                restore_original: true,
                                confirm: params.confirm,
                            },
                            &mut state.freezes,
                            || {
                                let mut guard = policy.lock().map_err(|_| {
                                    OperationError::new(
                                        ErrorCode::TargetNotAllowed,
                                        OP,
                                        "the policy lock is poisoned",
                                    )
                                })?;
                                guard.revalidate()
                            },
                            OP,
                        );
                        match outcome {
                            Ok(o) => restored.push(o),
                            Err(e) => notes.push(format!("freeze {id}: {e}")),
                        }
                    }
                }
            }
        } else {
            notes.push(
                "restore_frozen_values was not set, so frozen values were left in place. \
                 Detaching stops workers; it does not restore bytes."
                    .to_owned(),
            );
        }

        let stopped = state
            .freezes
            .stop_all(FreezeStopReason::ShutdownRequested, OP);
        let cleared_scan = state.scan.is_some();
        state.scan = None;
        let cleared_undo = state.history.clear_session(&session_id);
        state.cancel.cancel();
        state.cancel = Cancel::new();
        state.session = None;

        notes.push(format!(
            "{} freeze workers were stopped and joined before the session was released",
            stopped.len()
        ));
        notes.push(
            "Undo entries for this session were discarded: they are never applied to a different \
             or restarted process."
                .to_owned(),
        );

        ok(&DetachOutcome {
            detached: true,
            session_id,
            pid,
            stopped_freezes: stopped,
            restored,
            cleared_scan,
            cleared_undo_entries: cleared_undo,
            notes,
        })
    }

    #[tool(
        name = "list_regions",
        description = "Enumerate memory regions with mapping metadata, module attribution, and every applicable exclusion reason."
    )]
    fn list_regions(&self, Parameters(params): Parameters<RegionsParams>) -> ToolResult {
        const OP: &str = "list_regions";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(scan::list_regions(&session, &params.filter, OP))
    }

    #[tool(
        name = "first_scan",
        description = "Start a scan with an explicit operator, region filter, alignment and resource budget."
    )]
    async fn first_scan(
        &self,
        Parameters(params): Parameters<FirstScanRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "first_scan";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let mut lease = server.begin(OP, true)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            match scan::first_scan(&lease.session, &params, cancel, checker, OP) {
                Err(e) => {
                    lease.scan = None;
                    Err(e)
                }
                Ok((new_state, outcome)) => {
                    lease.scan = Some(new_state);
                    Ok(outcome)
                }
            }
        })
        .await
    }

    #[tool(
        name = "next_scan",
        description = "Narrow the current scan against the previous scan or the initial baseline."
    )]
    async fn next_scan(
        &self,
        Parameters(params): Parameters<NextScanRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "next_scan";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let mut lease = server.begin(OP, true)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            let scan_state = lease.scan.as_mut().ok_or_else(|| no_scan_state(OP))?;
            scan::next_scan(&lease.session, scan_state, &params, cancel, checker, OP)
        })
        .await
    }

    #[tool(
        name = "list_results",
        description = "Page through retained scan candidates. Pagination never discards undisplayed candidates."
    )]
    fn list_results(&self, Parameters(params): Parameters<ListResultsRequest>) -> ToolResult {
        const OP: &str = "list_results";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let scan_state = match state.scan_for(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(scan::list_results(&session, scan_state, &params, OP))
    }

    #[tool(
        name = "reset_scan",
        description = "Discard the current scan state and report what was cleared."
    )]
    fn reset_scan(&self, _p: Parameters<NoParams>) -> ToolResult {
        const OP: &str = "reset_scan";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = state.refuse_if_scan_busy(OP) {
            return Ok(fail(e));
        }
        match state.scan.take() {
            None => Ok(fail(
                OperationError::new(ErrorCode::ScanStateInvalid, OP, "there is no scan to reset")
                    .with_next_step("Run first_scan before resetting."),
            )),
            Some(scan_state) => ok(&scan::reset_scan(scan_state)),
        }
    }

    #[tool(
        name = "group_scan",
        description = "Find bases where several typed fields at fixed offsets all match, keeping field-level evidence."
    )]
    async fn group_scan(
        &self,
        Parameters(params): Parameters<GroupScanRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "group_scan";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let lease = server.begin(OP, false)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            scan::group_scan(&lease.session, &params, cancel, checker, OP)
        })
        .await
    }

    #[tool(
        name = "read_memory",
        description = "Read one typed value with full provenance: raw bytes, requested and actual sizes, and timing."
    )]
    fn read_memory(&self, Parameters(params): Parameters<ReadMemoryParams>) -> ToolResult {
        const OP: &str = "read_memory";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let address = match Address::parse_hex(&params.address, OP) {
            Ok(a) => a,
            Err(e) => return Ok(fail(e)),
        };
        done(mem::read_memory(
            &session,
            address,
            params.value_type,
            params.max_bytes,
            params.max_chars,
            OP,
        ))
    }

    #[tool(
        name = "read_bytes",
        description = "Read a bounded raw byte range, reporting the readable prefix honestly if the mapping ends."
    )]
    fn read_bytes(&self, Parameters(params): Parameters<ReadBytesParams>) -> ToolResult {
        const OP: &str = "read_bytes";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let address = match Address::parse_hex(&params.address, OP) {
            Ok(a) => a,
            Err(e) => return Ok(fail(e)),
        };
        done(mem::read_bytes(&session, address, params.length, OP))
    }

    #[tool(
        name = "read_batch",
        description = "Read several addresses with independent per-item outcomes. A batch is never an atomic snapshot."
    )]
    fn read_batch(&self, Parameters(params): Parameters<ReadBatchParams>) -> ToolResult {
        const OP: &str = "read_batch";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(mem::read_batch(&session, &params.items, OP))
    }

    #[tool(
        name = "read_struct",
        description = "Read declared fields at caller-given offsets. No compiler packing is ever inferred."
    )]
    fn read_struct(&self, Parameters(params): Parameters<ReadStructParams>) -> ToolResult {
        const OP: &str = "read_struct";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let address = match Address::parse_hex(&params.address, OP) {
            Ok(a) => a,
            Err(e) => return Ok(fail(e)),
        };
        done(mem::read_struct(
            &session,
            address,
            &params.fields,
            params.total_size,
            OP,
        ))
    }

    #[tool(
        name = "list_modules",
        description = "List loaded modules with base, size and path, for module-relative addressing."
    )]
    fn list_modules(&self, _p: Parameters<NoParams>) -> ToolResult {
        const OP: &str = "list_modules";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(ptr::list_modules(&session, OP))
    }

    #[tool(
        name = "resolve_address",
        description = "Resolve an absolute address, a module base, or module+offset, reporting the form and stability caveat."
    )]
    fn resolve_address(&self, Parameters(params): Parameters<ResolveAddressParams>) -> ToolResult {
        const OP: &str = "resolve_address";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let modules = ptr::list_modules(&session, OP).unwrap_or_default();
        done(ptr::resolve_address(
            &session,
            &modules,
            &params.address,
            OP,
        ))
    }

    #[tool(
        name = "resolve_pointer_path",
        description = "Walk a pointer path hop by hop using one documented dereference order, reporting every hop."
    )]
    fn resolve_pointer_path(&self, Parameters(params): Parameters<PointerPathSpec>) -> ToolResult {
        const OP: &str = "resolve_pointer_path";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let modules = ptr::list_modules(&session, OP).unwrap_or_default();
        done(ptr::resolve_pointer_path(&session, &modules, &params, OP))
    }

    #[tool(
        name = "pointer_scan",
        description = "Search for bounded pointer paths to an address, with cycle detection and reported index coverage."
    )]
    async fn pointer_scan(
        &self,
        Parameters(params): Parameters<PointerScanRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "pointer_scan";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let lease = server.begin(OP, false)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            ptr::pointer_scan(&lease.session, &params, &cancel, checker, OP)
        })
        .await
    }

    #[tool(
        name = "rescan_pointer_paths",
        description = "Re-resolve stored paths, separating survived, broken, resolved elsewhere, and resolved unverified."
    )]
    fn rescan_pointer_paths(
        &self,
        Parameters(params): Parameters<RescanPathsParams>,
    ) -> ToolResult {
        const OP: &str = "rescan_pointer_paths";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(ptr::rescan_pointer_paths(
            &session,
            &params.paths,
            params.value_bytes,
            OP,
        ))
    }

    #[tool(
        name = "find_references",
        description = "Search readable memory for pointer-sized values equal to an address. A data search only; no instruction is decoded."
    )]
    async fn find_references(
        &self,
        Parameters(params): Parameters<FindReferencesRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "find_references";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let lease = server.begin(OP, false)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            ptr::find_references(&lease.session, &params, &cancel, checker, OP)
        })
        .await
    }

    #[tool(
        name = "watch_value",
        description = "Poll one address on a bounded schedule, reporting per-sample timestamps and the limits of polling."
    )]
    async fn watch_value(
        &self,
        Parameters(params): Parameters<WatchRequest>,
        context: RequestContext<RoleServer>,
    ) -> ToolResult {
        const OP: &str = "watch_value";
        self.run_cancellable(context.ct.clone(), OP, move |server, cancel| {
            let lease = server.begin(OP, false)?;
            let checker = server.policy_checker(lease.exe.clone(), OP);
            investigate::watch_value(
                &lease.session,
                &params,
                move || {
                    if cancel.is_cancelled() {
                        return Err(OperationError::new(
                            ErrorCode::Cancelled,
                            OP,
                            "the client cancelled this watch",
                        ));
                    }
                    checker()
                },
                OP,
            )
        })
        .await
    }

    #[tool(
        name = "dissect_region",
        description = "Suggest possible types, strings and pointers in a byte range. Every inference is labelled a heuristic."
    )]
    fn dissect_region(&self, Parameters(params): Parameters<DissectRequest>) -> ToolResult {
        const OP: &str = "dissect_region";
        let state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.read_ref(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        done(investigate::dissect_region(&session, &params, OP))
    }

    #[tool(
        name = "write_memory",
        description = "Write a pre-encoded payload after capturing the original bytes, then verify byte for byte. Requires MEMSCOPE_ALLOW_WRITE=1 and confirm=true."
    )]
    fn write_memory(&self, Parameters(params): Parameters<WriteRequest>) -> ToolResult {
        const OP: &str = "write_memory";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = mutate::require_write_authorisation(params.confirm, OP) {
            return Ok(fail(e));
        }
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.session.as_mut() {
            Some(s) => s,
            None => {
                return Ok(fail(OperationError::new(
                    ErrorCode::NotAttached,
                    OP,
                    "no process is attached",
                )));
            }
        };
        if let Err(e) = session.enable_writes(OP) {
            return Ok(fail(e));
        }
        let read_ref = session.read_ref();
        let handle = match session.write_handle(OP) {
            Ok(h) => h,
            Err(e) => return Ok(fail(e)),
        };
        let ServerState {
            history,
            journal,
            freezes,
            ..
        } = &mut *state;
        done(mutate::write_memory(
            &read_ref,
            handle,
            &params,
            history,
            journal,
            freezes.ranges(),
            OP,
        ))
    }

    #[tool(
        name = "undo_write",
        description = "Restore the original bytes of a retained write, refusing a conflict unless explicitly overridden. Requires both write gates."
    )]
    fn undo_write(&self, Parameters(params): Parameters<UndoRequest>) -> ToolResult {
        const OP: &str = "undo_write";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = mutate::require_write_authorisation(params.confirm, OP) {
            return Ok(fail(e));
        }
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let session = match state.session.as_mut() {
            Some(s) => s,
            None => {
                return Ok(fail(OperationError::new(
                    ErrorCode::NotAttached,
                    OP,
                    "no process is attached",
                )));
            }
        };
        if let Err(e) = session.enable_writes(OP) {
            return Ok(fail(e));
        }
        let read_ref = session.read_ref();
        let handle = match session.write_handle(OP) {
            Ok(h) => h,
            Err(e) => return Ok(fail(e)),
        };
        let ServerState {
            history,
            journal,
            freezes,
            ..
        } = &mut *state;
        done(mutate::undo_write(
            &read_ref,
            handle,
            &params,
            history,
            journal,
            freezes.ranges(),
            OP,
        ))
    }

    #[tool(
        name = "freeze_value",
        description = "Hold a value in place with a bounded worker using session-bound process handles. Requires both write gates."
    )]
    fn freeze_value(&self, Parameters(params): Parameters<FreezeRequest>) -> ToolResult {
        const OP: &str = "freeze_value";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        if let Err(e) = mutate::require_write_authorisation(params.confirm, OP) {
            return Ok(fail(e));
        }
        if let Err(e) = self.checkpoint(&state, OP) {
            return Ok(fail(e));
        }
        let exe = match state.session_for(OP) {
            Ok(s) => s.identity().exe_canonical.clone(),
            Err(e) => return Ok(fail(e)),
        };
        let session = match state.session.as_mut() {
            Some(s) => s,
            None => {
                return Ok(fail(OperationError::new(
                    ErrorCode::NotAttached,
                    OP,
                    "no process is attached",
                )));
            }
        };
        if let Err(e) = session.enable_writes(OP) {
            return Ok(fail(e));
        }
        let read_ref = session.read_ref();
        let handle = match session.write_handle(OP) {
            Ok(h) => h,
            Err(e) => return Ok(fail(e)),
        };
        let checker = self.policy_checker(exe, OP);
        let freezes = &mut state.freezes;
        done(mutate::freeze_value(
            &read_ref, handle, &params, freezes, checker, OP,
        ))
    }

    #[tool(
        name = "unfreeze_value",
        description = "Stop and join a freeze worker, then optionally restore the pre-freeze bytes with both write gates."
    )]
    fn unfreeze_value(&self, Parameters(params): Parameters<UnfreezeRequest>) -> ToolResult {
        const OP: &str = "unfreeze_value";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let session = match state.session.as_mut() {
            Some(s) => s,
            None => {
                return Ok(fail(OperationError::new(
                    ErrorCode::NotAttached,
                    OP,
                    "no process is attached",
                )));
            }
        };
        let read_ref = session.read_ref();
        let handle = session
            .write_handle(OP)
            .unwrap_or_else(|_| session.handle());
        let policy = Arc::clone(&self.policy);
        let freezes = &mut state.freezes;
        done(mutate::unfreeze_value(
            &read_ref,
            handle,
            &params,
            freezes,
            || {
                let mut guard = policy.lock().map_err(|_| {
                    OperationError::new(
                        ErrorCode::TargetNotAllowed,
                        OP,
                        "the policy lock is poisoned",
                    )
                })?;
                guard.revalidate()
            },
            OP,
        ))
    }

    #[tool(
        name = "list_frozen",
        description = "List active and recently stopped freezes with worker state, measured timing, and retained stop reasons."
    )]
    fn list_frozen(&self, _p: Parameters<NoParams>) -> ToolResult {
        const OP: &str = "list_frozen";
        let mut state = match self.lock_state(OP) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };
        let views = mutate::list_frozen(&mut state.freezes);
        ok(&views)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MemScope {
    fn get_info(&self) -> ServerConfig {
        let mut server_info = Implementation::default();
        server_info.name = "memscope".to_owned();
        server_info.version = crate::VERSION.to_owned();
        server_info.title = Some("MemScope".to_owned());

        let mut config = ServerConfig::default();
        config.protocol_version = NEGOTIATED_PROTOCOL_VERSION;
        config.capabilities = ServerCapabilities::builder().enable_tools().build();
        config.server_info = server_info;
        config.instructions = Some(
            "MemScope inspects the memory of Windows processes with unrestricted target selection.\n\n\
                 Workflow: server_status, list_processes, attach_process, list_modules and \
                 list_regions, then read_* to inspect, first_scan and next_scan to discover and \
                 narrow, group_scan and dissect_region and watch_value to investigate, \
                 resolve_address and resolve_pointer_path and pointer_scan to express stable \
                 locations, and finally detach_process.\n\n\
                 Mutation is off unless the server was started with MEMSCOPE_ALLOW_WRITE=1, and \
                 every mutating call also needs confirm=true.\n\n\
                 Honesty rules this server follows: unread bytes are never zero-filled; a \
                 truncated scan never claims a total; one candidate is never proof of a \
                 variable's identity; dissection output is heuristic; watch_value is polling and \
                 cannot see every write; a natively paused observation is refused with \
                 CONSISTENCY_UNAVAILABLE because no target thread is ever suspended.\n\n\
                 This server never executes code in a target, injects a library, attaches a \
                 debugger, elevates privilege, or changes page protection to force access."
                .to_owned(),
        );
        config
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Owned(vec![
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_03_26,
            ProtocolVersion::V_2024_11_05,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle_state() -> ServerState {
        ServerState {
            session: None,
            scan: None,
            history: UndoHistory::default(),
            journal: FailureJournal::default(),
            freezes: FreezeRegistry::default(),
            cancel: Cancel::new(),
            started_at: SystemTime::now(),
            active: None,
            next_operation_id: 1,
        }
    }

    fn running(operation: &'static str, owns_scan_state: bool) -> ActiveOperation {
        ActiveOperation {
            id: 1,
            operation,
            started_at: Instant::now(),
            owns_scan_state,
            scan_state_present: owns_scan_state,
        }
    }

    #[test]
    fn an_idle_server_refuses_nothing() {
        let mut state = idle_state();
        assert!(state.refuse_if_busy("detach_process").is_ok());
        assert!(state.refuse_if_scan_busy("list_results").is_ok());
        assert!(!state.scan_present());
        assert_eq!(
            state.scan_for("list_results").unwrap_err().code,
            ErrorCode::ScanStateInvalid,
            "with nothing running, a missing scan is still a missing scan"
        );
    }

    #[test]
    fn a_tool_in_flight_refuses_a_second_long_operation_and_a_detach() {
        let mut state = idle_state();
        state.active = Some(running("pointer_scan", false));

        for operation in ["first_scan", "watch_value", "detach_process"] {
            let error = state
                .refuse_if_busy(operation)
                .expect_err("a long-running tool must refuse a second one");
            assert_eq!(error.code, ErrorCode::OperationInFlight);
            assert_eq!(error.operation, operation);
            assert!(
                error.message.contains("pointer_scan"),
                "the refusal must name what is running: {}",
                error.message
            );
            assert!(
                error
                    .next_step
                    .as_deref()
                    .is_some_and(|s| s.contains("notifications/cancelled")),
                "the refusal must say how to get out of it"
            );
        }
    }

    #[test]
    fn a_tool_that_does_not_own_the_scan_state_leaves_the_scan_tools_alone() {
        let mut state = idle_state();
        state.active = Some(running("watch_value", false));

        assert!(state.refuse_if_scan_busy("list_results").is_ok());
        assert_eq!(
            state.scan_for("list_results").unwrap_err().code,
            ErrorCode::ScanStateInvalid
        );
        assert!(!state.scan_present());
    }

    #[test]
    fn a_scan_that_owns_the_state_refuses_the_scan_tools_by_name() {
        let mut state = idle_state();
        state.active = Some(running("next_scan", true));

        for operation in ["list_results", "reset_scan"] {
            let error = state
                .refuse_if_scan_busy(operation)
                .expect_err("the scan state is checked out");
            assert_eq!(error.code, ErrorCode::OperationInFlight);
            assert!(error.message.contains("next_scan"));
        }
        assert_eq!(
            state.scan_for("list_results").unwrap_err().code,
            ErrorCode::OperationInFlight,
            "a checked-out scan state must not be reported as a missing one"
        );
        assert!(
            state.scan_present(),
            "a scan state checked out by a running scan still exists"
        );
    }

    #[test]
    fn exactly_twenty_seven_tools_are_named() {
        assert_eq!(TOOL_NAMES.len(), 27);
        let mut sorted = TOOL_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 27, "tool names must be unique");
    }

    #[test]
    fn the_named_tool_set_matches_the_brief_groups_exactly() {
        let session = [
            "server_status",
            "list_processes",
            "attach_process",
            "detach_process",
        ];
        let regions = [
            "list_regions",
            "first_scan",
            "next_scan",
            "list_results",
            "reset_scan",
        ];
        let composite = ["group_scan"];
        let reading = ["read_memory", "read_batch", "read_bytes", "read_struct"];
        let addressing = [
            "list_modules",
            "resolve_address",
            "pointer_scan",
            "resolve_pointer_path",
            "rescan_pointer_paths",
            "find_references",
        ];
        let investigation = ["watch_value", "dissect_region"];
        let mutation = [
            "write_memory",
            "undo_write",
            "freeze_value",
            "unfreeze_value",
            "list_frozen",
        ];

        let mut expected: Vec<&str> = Vec::new();
        expected.extend(session);
        expected.extend(regions);
        expected.extend(composite);
        expected.extend(reading);
        expected.extend(addressing);
        expected.extend(investigation);
        expected.extend(mutation);
        assert_eq!(expected.len(), 27);

        let mut expected_sorted = expected.clone();
        expected_sorted.sort_unstable();
        let mut actual_sorted = TOOL_NAMES.to_vec();
        actual_sorted.sort_unstable();
        assert_eq!(actual_sorted, expected_sorted);
    }

    #[test]
    fn the_router_registers_exactly_the_named_tools_and_nothing_else() {
        let router = MemScope::tool_router();
        let mut registered: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        registered.sort_unstable();
        let mut expected = TOOL_NAMES.map(str::to_owned).to_vec();
        expected.sort_unstable();
        assert_eq!(
            registered, expected,
            "the registered tool set must match the named set exactly, with no extras"
        );
    }

    #[test]
    fn every_registered_tool_has_a_description_and_an_object_input_schema() {
        let router = MemScope::tool_router();
        for tool in router.list_all() {
            let description = tool
                .description
                .as_ref()
                .unwrap_or_else(|| panic!("{} has no description", tool.name));
            assert!(
                description.len() > 20,
                "{} has a uselessly short description",
                tool.name
            );
            let schema = serde_json::to_value(&tool.input_schema)
                .unwrap_or_else(|e| panic!("{} input schema is not JSON: {e}", tool.name));
            assert_eq!(
                schema.get("type").and_then(|t| t.as_str()),
                Some("object"),
                "{} must take an object",
                tool.name
            );
        }
    }

    #[test]
    fn no_registered_tool_offers_execution_or_another_prohibited_capability() {
        let router = MemScope::tool_router();
        let forbidden = [
            "exec",
            "eval",
            "shell",
            "command",
            "inject",
            "thread",
            "debug",
            "privilege",
            "elevate",
            "protect",
            "suspend",
            "resume",
            "load_library",
            "allocate",
        ];
        for tool in router.list_all() {
            let name = tool.name.to_ascii_lowercase();
            for bad in forbidden {
                assert!(
                    !name.contains(bad),
                    "tool {} looks like a {bad} capability, which this server must not offer",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn the_negotiated_protocol_revision_still_has_an_initialize_handshake() {
        assert!(
            NEGOTIATED_PROTOCOL_VERSION.has_initialize(),
            "a client that cannot run initialize cannot connect"
        );
        assert_eq!(NEGOTIATED_PROTOCOL_VERSION, ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn the_server_advertises_tools_and_names_its_honesty_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let server = MemScope::new(Policy::load(allowlist));
        let info = server.get_info();

        assert_eq!(info.protocol_version, NEGOTIATED_PROTOCOL_VERSION);
        assert!(info.capabilities.tools.is_some());
        assert_eq!(info.server_info.name, "memscope");

        let instructions = info.instructions.expect("instructions");
        for phrase in [
            "never zero-filled",
            "never claims a total",
            "never proof",
            "heuristic",
            "CONSISTENCY_UNAVAILABLE",
            "MEMSCOPE_ALLOW_WRITE=1",
            "confirm=true",
        ] {
            assert!(
                instructions.contains(phrase),
                "the instructions must state {phrase:?}"
            );
        }
        for phrase in [
            "never executes code",
            "injects a library",
            "attaches a debugger",
            "changes page protection",
        ] {
            assert!(
                instructions.contains(phrase),
                "the instructions must disclaim {phrase:?}"
            );
        }
    }

    #[test]
    fn a_tool_call_without_a_session_is_a_named_operation_failure_not_a_protocol_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let server = MemScope::new(Policy::load(allowlist));

        let result = server
            .list_modules(Parameters(NoParams {}))
            .expect("a missing session must not be a protocol error");
        assert_eq!(result.is_error, Some(true));
        let structured = result.structured_content.expect("structured error");
        assert_eq!(structured["code"], "NOT_ATTACHED");
        assert_eq!(structured["operation"], "list_modules");
        assert!(structured["next_step"].is_string());
    }

    #[test]
    fn server_status_reports_the_limits_and_the_absent_paused_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let server = MemScope::new(Policy::load(allowlist));

        let result = server
            .server_status(Parameters(NoParams {}))
            .expect("status");
        assert_ne!(result.is_error, Some(true));
        let body = result.structured_content.expect("structured status");
        assert_eq!(body["tool_count"], 27);
        assert_eq!(body["attached"], false);
        assert_eq!(body["policy_entries"], 0);
        assert_eq!(body["protocol_version"], "2025-11-25");
        assert!(
            body["native_paused_mode"]
                .as_str()
                .expect("native_paused_mode")
                .contains("not implemented")
        );
        assert!(body["limits"]["max_response_bytes"].as_u64().unwrap() > 0);
        assert!(body["denied_roots"].as_array().expect("roots").is_empty());
        assert_eq!(body["target_selection"], "unrestricted");
    }

    #[test]
    fn a_mutating_tool_refuses_before_it_needs_a_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let server = MemScope::new(Policy::load(allowlist));

        let result = server
            .write_memory(Parameters(WriteRequest {
                address: "0x1000".to_owned(),
                payload: mutate::WritePayload::Bytes {
                    hex: "00".to_owned(),
                },
                confirm: true,
                expect_original_raw: None,
                attempt_recovery_on_failure: true,
            }))
            .expect("a closed gate is an operation failure");
        assert_eq!(result.is_error, Some(true));
        let structured = result.structured_content.expect("structured error");
        assert_eq!(
            structured["code"], "WRITE_DISABLED",
            "the write gate is checked before anything else"
        );
    }
}
