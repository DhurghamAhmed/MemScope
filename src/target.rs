use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{
    FILETIME, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessHandleCount, GetProcessTimes, IsWow64Process,
    OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::core::PWSTR;

use crate::error::{ErrorCode, OperationError, Result};
use crate::policy::{self, Authorisation, Policy};
use crate::win::{self, OwnedHandle};
use crate::wire::TargetArch;

const SYNCHRONIZE_RIGHT: u32 = 0x0010_0000;

const RIGHTS_IDENTIFY: PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_LIMITED_INFORMATION;

fn rights_read() -> PROCESS_ACCESS_RIGHTS {
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_ACCESS_RIGHTS(SYNCHRONIZE_RIGHT)
}

fn rights_write() -> PROCESS_ACCESS_RIGHTS {
    PROCESS_VM_WRITE | PROCESS_VM_OPERATION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Alive,
    Exited,
    WaitFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time: String,
    pub exe_canonical: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub read: bool,
    pub write: bool,
    pub suspend: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<TargetArch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    pub owned_by_current_user: bool,
    pub allowlisted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
}

pub fn own_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub fn peak_working_set_bytes() -> Option<u64> {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    let pseudo = unsafe { GetCurrentProcess() };
    match unsafe {
        GetProcessMemoryInfo(
            pseudo,
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    } {
        Ok(()) => Some(counters.PeakWorkingSetSize as u64),
        Err(_) => None,
    }
}

pub fn own_handle_count() -> Option<u32> {
    let mut count = 0u32;
    let pseudo = unsafe { GetCurrentProcess() };
    match unsafe { GetProcessHandleCount(pseudo, &mut count) } {
        Ok(()) => Some(count),
        Err(_) => None,
    }
}

pub fn host_is_supported() -> bool {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    let arch = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture };
    arch == PROCESSOR_ARCHITECTURE_AMD64
}

pub fn require_supported_host(operation: &str) -> Result<()> {
    if host_is_supported() {
        return Ok(());
    }
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    let arch = unsafe { info.Anonymous.Anonymous.wProcessorArchitecture }.0;
    Err(OperationError::new(
        ErrorCode::UnsupportedArchitecture,
        operation,
        format!("this build supports an AMD64 host only; the native architecture is {arch}"),
    )
    .with_next_step("Run MemScope on an x64 Windows host."))
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

fn open_for(pid: u32, rights: PROCESS_ACCESS_RIGHTS, operation: &str) -> Result<OwnedHandle> {
    let handle = unsafe { OpenProcess(rights, false, pid) };
    match handle {
        Ok(h) => Ok(unsafe { OwnedHandle::from_raw(h) }),
        Err(_) => {
            let code = win::last_error();
            Err(win32_open_failure(pid, rights, code, operation))
        }
    }
}

fn win32_open_failure(
    pid: u32,
    rights: PROCESS_ACCESS_RIGHTS,
    code: u32,
    operation: &str,
) -> OperationError {
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_ACCESS_DENIED: u32 = 5;
    let (named, next_step) = match code {
        ERROR_INVALID_PARAMETER => (
            ErrorCode::ProcessGone,
            "The process is no longer running. Re-enumerate and pick a live PID.",
        ),
        ERROR_ACCESS_DENIED => (
            ErrorCode::PermissionDenied,
            "Windows refused these access rights for this process. The underlying \
             cause is not inferable from the code alone; confirm the target is one \
             the current Windows token can access with the requested rights.",
        ),
        _ => (
            ErrorCode::PermissionDenied,
            "OpenProcess failed. The OS code is preserved above; it has not been \
             interpreted further.",
        ),
    };
    win::win32_failure(
        named,
        operation,
        format!("OpenProcess(pid {pid}, rights 0x{:08x}) failed", rights.0),
        code,
    )
    .with_pid(pid)
    .with_next_step(next_step)
}

fn query_exe_path(handle: &OwnedHandle, pid: u32, operation: &str) -> Result<String> {
    let mut buffer = vec![0u16; 1024];
    loop {
        let mut size = buffer.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle.raw(),
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };
        match result {
            Ok(()) => return Ok(win::from_wide(&buffer[..size as usize])),
            Err(_) => {
                const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
                let code = win::last_error();
                if code == ERROR_INSUFFICIENT_BUFFER && buffer.len() < 64 * 1024 {
                    buffer = vec![0u16; buffer.len() * 2];
                    continue;
                }
                return Err(win::win32_failure(
                    ErrorCode::PermissionDenied,
                    operation,
                    format!("cannot read the executable path of pid {pid}"),
                    code,
                )
                .with_pid(pid)
                .with_next_step(
                    "Windows must allow querying the executable path to establish session identity.",
                ));
            }
        }
    }
}

fn query_owner_sid(handle: &OwnedHandle, pid: u32, operation: &str) -> Result<String> {
    let mut raw_token = HANDLE::default();
    unsafe { OpenProcessToken(handle.raw(), TOKEN_QUERY, &mut raw_token) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot open the token of pid {pid} to establish its owner"),
            code,
        )
        .with_pid(pid)
        .with_next_step("Owner metadata is unavailable; process access is determined separately.")
    })?;
    let token = unsafe { OwnedHandle::from_raw(raw_token) };

    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        let code = win::last_error();
        return Err(win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot size the token information of pid {pid}"),
            code,
        )
        .with_pid(pid)
        .with_next_step("Ownership cannot be established, so the target is refused."));
    }

    let mut buffer = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot read the token information of pid {pid}"),
            code,
        )
        .with_pid(pid)
        .with_next_step("Ownership cannot be established, so the target is refused.")
    })?;

    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut text) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot convert the owner SID of pid {pid} to text"),
            code,
        )
        .with_pid(pid)
    })?;
    let sid = unsafe { text.to_string() }.unwrap_or_default();
    unsafe { LocalFree(Some(HLOCAL(text.as_ptr().cast()))) };
    if sid.is_empty() {
        return Err(OperationError::new(
            ErrorCode::PermissionDenied,
            operation,
            format!("the owner SID of pid {pid} decoded to nothing"),
        )
        .with_pid(pid));
    }
    Ok(sid)
}

fn query_arch(handle: &OwnedHandle, pid: u32, operation: &str) -> Result<TargetArch> {
    require_supported_host(operation)?;
    let mut wow64 = windows::core::BOOL::from(false);
    unsafe { IsWow64Process(handle.raw(), &mut wow64) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::UnsupportedArchitecture,
            operation,
            format!("cannot determine the architecture of pid {pid}"),
            code,
        )
        .with_pid(pid)
        .with_next_step("An unknown pointer width is refused rather than assumed.")
    })?;
    Ok(if wow64.as_bool() {
        TargetArch::X86Wow64
    } else {
        TargetArch::X64
    })
}

fn query_creation_time(handle: &OwnedHandle, pid: u32, operation: &str) -> Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            handle.raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot read the creation time of pid {pid}"),
            code,
        )
        .with_pid(pid)
        .with_next_step("Session identity needs a creation time, so the target is refused.")
    })?;
    Ok(filetime_to_u64(creation))
}

pub fn current_user_sid(operation: &str) -> Result<String> {
    let pseudo = unsafe { GetCurrentProcess() };
    let mut raw_token = HANDLE::default();
    unsafe { OpenProcessToken(pseudo, TOKEN_QUERY, &mut raw_token) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            "cannot open this process's own token",
            code,
        )
    })?;
    let token = unsafe { OwnedHandle::from_raw(raw_token) };

    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed) };
    let mut buffer = vec![0u8; needed.max(1) as usize];
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            "cannot read this process's own token information",
            code,
        )
    })?;
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut text) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            "cannot convert this user's SID to text",
            code,
        )
    })?;
    let sid = unsafe { text.to_string() }.unwrap_or_default();
    unsafe { LocalFree(Some(HLOCAL(text.as_ptr().cast()))) };
    Ok(sid)
}

fn snapshot_processes(operation: &str) -> Result<Vec<(u32, String)>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|_| {
        let code = win::last_error();
        win::win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            "cannot enumerate processes",
            code,
        )
    })?;
    let snapshot = unsafe { OwnedHandle::from_raw(snapshot) };

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) }.is_err() {
        return Ok(out);
    }
    loop {
        let name = win::from_wide(&entry.szExeFile);
        out.push((entry.th32ProcessID, name));
        entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_err() {
            break;
        }
    }
    Ok(out)
}

pub fn list_processes(_policy: &mut Policy, operation: &str) -> Result<Vec<ProcessSummary>> {
    require_supported_host(operation)?;
    let current_sid = current_user_sid(operation).unwrap_or_default();
    let entries = snapshot_processes(operation)?;

    let mut summaries = Vec::with_capacity(entries.len());
    for (pid, name) in entries {
        if pid == 0 {
            continue;
        }
        let mut summary = ProcessSummary {
            pid,
            name,
            exe_path: None,
            arch: None,
            owner_sid: None,
            creation_time: None,
            owned_by_current_user: false,
            allowlisted: true,
            limitation: None,
        };

        let handle = match open_for(pid, RIGHTS_IDENTIFY, operation) {
            Ok(h) => h,
            Err(e) => {
                summary.limitation = Some(format!("{}: {}", e.code, e.message));
                summaries.push(summary);
                continue;
            }
        };

        match query_owner_sid(&handle, pid, operation) {
            Ok(sid) => {
                summary.owned_by_current_user = sid.eq_ignore_ascii_case(&current_sid);
                summary.owner_sid = Some(sid);
            }
            Err(e) => summary.limitation = Some(format!("{}: {}", e.code, e.message)),
        }
        if let Ok(path) = query_exe_path(&handle, pid, operation) {
            summary.exe_path = Some(path);
        }
        if let Ok(arch) = query_arch(&handle, pid, operation) {
            summary.arch = Some(arch);
        }
        if let Ok(created) = query_creation_time(&handle, pid, operation) {
            summary.creation_time = Some(created.to_string());
        }
        summaries.push(summary);
    }
    summaries.sort_by_key(|s| s.pid);
    Ok(summaries)
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_session_id(pid: u32) -> String {
    let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("s{n}-{pid}-{stamp:x}")
}

#[derive(Debug)]
pub struct Session {
    id: String,
    identity: ProcessIdentity,
    creation_time_raw: u64,
    arch: TargetArch,
    owner_sid: String,
    exe_sha256: String,
    handle: OwnedHandle,
    write_handle: Option<OwnedHandle>,
    opened_at: SystemTime,
}

impl Session {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn pid(&self) -> u32 {
        self.identity.pid
    }

    pub fn arch(&self) -> TargetArch {
        self.arch
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    pub fn exe_sha256(&self) -> &str {
        &self.exe_sha256
    }

    pub fn opened_at(&self) -> SystemTime {
        self.opened_at
    }

    pub fn handle(&self) -> HANDLE {
        self.handle.raw()
    }

    pub fn read_ref(&self) -> crate::mem::SessionRef {
        crate::mem::SessionRef {
            id: self.id.clone(),
            pid: self.identity.pid,
            creation_time: self.identity.creation_time.clone(),
            width: self.arch.pointer_width(),
            handle: self.handle.raw(),
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            read: true,
            write: self.write_handle.is_some(),
            suspend: false,
        }
    }

    pub fn attach(pid: u32, policy: &mut Policy, operation: &str) -> Result<(Self, Authorisation)> {
        require_supported_host(operation)?;
        let identify = open_for(pid, RIGHTS_IDENTIFY, operation)?;
        let owner_sid = query_owner_sid(&identify, pid, operation).unwrap_or_default();

        let exe_path = query_exe_path(&identify, pid, operation)?;
        let authorisation = policy.authorise(&exe_path, operation)?;
        let arch = query_arch(&identify, pid, operation)?;
        let creation_time = query_creation_time(&identify, pid, operation)?;

        let handle = open_for(pid, rights_read(), operation)?;
        let observed_creation = query_creation_time(&handle, pid, operation)?;
        let observed_identity = ProcessIdentity {
            pid,
            creation_time: observed_creation.to_string(),
            exe_canonical: query_exe_path(&handle, pid, operation)
                .and_then(|p| policy::canonicalise(&p, operation).map(|c| c.display))
                .unwrap_or_else(|_| authorisation.canonical_path.clone()),
        };
        let expected_identity = ProcessIdentity {
            pid,
            creation_time: creation_time.to_string(),
            exe_canonical: authorisation.canonical_path.clone(),
        };
        compare_identity(&expected_identity, &observed_identity, operation)?;

        drop(identify);

        Ok((
            Self {
                id: next_session_id(pid),
                identity: observed_identity,
                creation_time_raw: observed_creation,
                arch,
                owner_sid,
                exe_sha256: authorisation.measured_sha256.clone(),
                handle,
                write_handle: None,
                opened_at: SystemTime::now(),
            },
            authorisation,
        ))
    }

    pub fn liveness(&self) -> Liveness {
        let result = unsafe { WaitForSingleObject(self.handle.raw(), 0) };
        if result == WAIT_TIMEOUT {
            Liveness::Alive
        } else if result == WAIT_OBJECT_0 {
            Liveness::Exited
        } else {
            Liveness::WaitFailed
        }
    }

    pub fn ensure_live(&self, operation: &str) -> Result<()> {
        match self.liveness() {
            Liveness::Alive => Ok(()),
            Liveness::Exited => Err(OperationError::new(
                ErrorCode::ProcessGone,
                operation,
                format!("process {} has exited", self.identity.pid),
            )
            .with_session(&self.id)
            .with_pid(self.identity.pid)
            .with_next_step("Detach and attach to a live process.")),
            Liveness::WaitFailed => {
                let code = win::last_error();
                Err(win::win32_failure(
                    ErrorCode::PermissionDenied,
                    operation,
                    format!(
                        "the liveness wait on process {} failed; its state is unknown",
                        self.identity.pid
                    ),
                    code,
                )
                .with_session(&self.id)
                .with_pid(self.identity.pid)
                .with_next_step(
                    "A failed wait is not treated as either alive or exited. Retry, \
                     or detach if it persists.",
                ))
            }
        }
    }

    pub fn ensure_identity(&self, policy: &mut Policy, operation: &str) -> Result<()> {
        self.ensure_live(operation)?;
        policy.revalidate()?;
        let observed = query_creation_time(&self.handle, self.identity.pid, operation)?;
        if observed != self.creation_time_raw {
            return Err(OperationError::new(
                ErrorCode::ProcessReplaced,
                operation,
                format!(
                    "pid {} no longer identifies the process this session opened",
                    self.identity.pid
                ),
            )
            .with_session(&self.id)
            .with_pid(self.identity.pid)
            .with_next_step("Detach and attach again; a reused PID is never silently adopted."));
        }
        Ok(())
    }

    pub fn enable_writes(&mut self, operation: &str) -> Result<()> {
        if self.write_handle.is_some() {
            return Ok(());
        }
        if !crate::writes_enabled_in_environment() {
            return Err(OperationError::new(
                ErrorCode::WriteDisabled,
                operation,
                format!("{} is not set to 1", crate::WRITE_ENABLE_VAR),
            )
            .with_session(&self.id)
            .with_next_step(
                "Restart the server with MEMSCOPE_ALLOW_WRITE=1 to permit mutations.",
            ));
        }
        let handle = open_for(self.identity.pid, rights_write(), operation)?;
        self.write_handle = Some(handle);
        Ok(())
    }

    pub fn write_handle(&self, operation: &str) -> Result<HANDLE> {
        self.write_handle
            .as_ref()
            .map(OwnedHandle::raw)
            .ok_or_else(|| {
                OperationError::new(
                    ErrorCode::WriteDisabled,
                    operation,
                    "this session holds no write handle",
                )
                .with_session(&self.id)
                .with_next_step("Mutations require MEMSCOPE_ALLOW_WRITE=1 and confirm=true.")
            })
    }

    pub fn release_write_handle(&mut self) {
        self.write_handle = None;
    }
}

pub fn compare_identity(
    expected: &ProcessIdentity,
    observed: &ProcessIdentity,
    operation: &str,
) -> Result<()> {
    if expected.pid != observed.pid {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "identity comparison received pid {} against pid {}",
                expected.pid, observed.pid
            ),
        ));
    }
    if expected.creation_time != observed.creation_time {
        return Err(OperationError::new(
            ErrorCode::ProcessReplaced,
            operation,
            format!(
                "pid {} was created at {} but now reports {}",
                expected.pid, expected.creation_time, observed.creation_time
            ),
        )
        .with_pid(expected.pid)
        .with_next_step("Attach again; a reused PID is never silently adopted."));
    }
    if !expected
        .exe_canonical
        .eq_ignore_ascii_case(&observed.exe_canonical)
    {
        return Err(OperationError::new(
            ErrorCode::ProcessReplaced,
            operation,
            format!(
                "pid {} ran {} but now reports {}",
                expected.pid, expected.exe_canonical, observed.exe_canonical
            ),
        )
        .with_pid(expected.pid)
        .with_next_step("Attach again; the PID now identifies a different executable."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(pid: u32, created: &str, exe: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            creation_time: created.to_owned(),
            exe_canonical: exe.to_owned(),
        }
    }

    #[test]
    fn the_host_architecture_is_amd64_in_this_environment() {
        assert!(host_is_supported());
        assert!(require_supported_host("test").is_ok());
    }

    #[test]
    fn this_process_reports_a_plausible_pid_and_sid() {
        assert!(own_pid() > 0);
        let sid = current_user_sid("test").expect("own SID");
        assert!(sid.starts_with("S-1-"), "got {sid}");
    }

    #[test]
    fn requested_rights_never_include_process_all_access() {
        let all_access = 0x001F_0FFFu32;
        for rights in [RIGHTS_IDENTIFY, rights_read(), rights_write()] {
            assert_ne!(
                rights.0, all_access,
                "PROCESS_ALL_ACCESS must never be requested"
            );
        }
    }

    #[test]
    fn identification_requests_query_rights_only() {
        assert_eq!(RIGHTS_IDENTIFY.0, PROCESS_QUERY_LIMITED_INFORMATION.0);
        assert_eq!(RIGHTS_IDENTIFY.0 & PROCESS_VM_READ.0, 0);
        assert_eq!(RIGHTS_IDENTIFY.0 & PROCESS_VM_WRITE.0, 0);
        assert_eq!(RIGHTS_IDENTIFY.0 & PROCESS_VM_OPERATION.0, 0);
    }

    #[test]
    fn a_read_session_asks_for_vm_read_and_synchronize_but_not_write() {
        let rights = rights_read();
        assert_ne!(rights.0 & PROCESS_VM_READ.0, 0);
        assert_ne!(rights.0 & SYNCHRONIZE_RIGHT, 0);
        assert_eq!(rights.0 & PROCESS_VM_WRITE.0, 0);
        assert_eq!(rights.0 & PROCESS_VM_OPERATION.0, 0);
    }

    #[test]
    fn write_rights_are_requested_separately_from_read_rights() {
        let rights = rights_write();
        assert_ne!(rights.0 & PROCESS_VM_WRITE.0, 0);
        assert_ne!(rights.0 & PROCESS_VM_OPERATION.0, 0);
        assert_eq!(rights.0 & PROCESS_VM_READ.0, 0);
    }

    #[test]
    fn a_reused_pid_is_reported_as_replaced_not_as_an_invalid_address() {
        let expected = identity(4321, "132000000000000000", r"C:\fixtures\a.exe");
        let observed = identity(4321, "132999999999999999", r"C:\fixtures\a.exe");
        let err = compare_identity(&expected, &observed, "read_memory")
            .expect_err("a different creation time is a different process");
        assert_eq!(err.code, ErrorCode::ProcessReplaced);
        assert_eq!(err.context.pid, Some(4321));
    }

    #[test]
    fn a_pid_now_running_a_different_executable_is_reported_as_replaced() {
        let expected = identity(4321, "132000000000000000", r"C:\fixtures\a.exe");
        let observed = identity(4321, "132000000000000000", r"C:\fixtures\b.exe");
        let err = compare_identity(&expected, &observed, "read_memory")
            .expect_err("a different image is a different process");
        assert_eq!(err.code, ErrorCode::ProcessReplaced);
    }

    #[test]
    fn an_unchanged_identity_compares_equal_including_path_case() {
        let expected = identity(4321, "132000000000000000", r"C:\Fixtures\A.exe");
        let observed = identity(4321, "132000000000000000", r"c:\fixtures\a.exe");
        assert!(compare_identity(&expected, &observed, "read_memory").is_ok());
    }

    #[test]
    fn comparing_two_different_pids_is_a_programming_error_not_a_replacement() {
        let expected = identity(1, "1", "a");
        let observed = identity(2, "1", "a");
        let err = compare_identity(&expected, &observed, "read_memory").expect_err("mismatch");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_filetime_becomes_a_single_sixty_four_bit_value() {
        let ft = FILETIME {
            dwLowDateTime: 0x8899_AABB,
            dwHighDateTime: 0x0011_2233,
        };
        assert_eq!(filetime_to_u64(ft), 0x0011_2233_8899_AABB);
    }

    #[test]
    fn enumeration_includes_this_process_without_a_target_restriction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let mut policy = Policy::load(allowlist);

        let processes = list_processes(&mut policy, "list_processes").expect("enumerate");
        assert!(processes.len() > 5, "expected a populated process list");

        let me = processes
            .iter()
            .find(|p| p.pid == own_pid())
            .expect("this process must appear in its own enumeration");
        assert!(me.limitation.is_none());
        assert!(me.allowlisted);
    }

    #[test]
    fn enumeration_reports_a_limitation_instead_of_failing_on_an_inaccessible_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let mut policy = Policy::load(allowlist);

        let processes = list_processes(&mut policy, "list_processes").expect("enumerate");
        let refused = processes.iter().filter(|p| p.limitation.is_some()).count();
        assert!(
            refused > 0,
            "at least the System process should be inaccessible and reported, not dropped"
        );
        assert!(
            processes.iter().all(|p| p.allowlisted),
            "selection is unrestricted even when Windows denies access"
        );
    }

    #[test]
    fn attaching_to_this_server_is_allowed_and_preserves_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let mut policy = Policy::load(allowlist);

        let (session, _) = Session::attach(own_pid(), &mut policy, "attach_process")
            .expect("self selection is allowed");
        assert_eq!(session.pid(), own_pid());
        session
            .ensure_identity(&mut policy, "read_memory")
            .expect("bound identity");
    }

    #[test]
    fn attaching_to_a_dead_pid_is_refused_with_the_os_code_preserved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"schema": 1, "entries": []}"#).expect("write");
        let mut policy = Policy::load(allowlist);

        let err = Session::attach(0xFFFF_FFF0, &mut policy, "attach_process")
            .expect_err("a PID this high is not running");
        assert!(
            matches!(
                err.code,
                ErrorCode::ProcessGone | ErrorCode::PermissionDenied
            ),
            "got {}",
            err.code
        );
        assert!(
            err.context.win32_error.is_some(),
            "the OS code must survive"
        );
    }
}
