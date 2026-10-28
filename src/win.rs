use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::PWSTR;

use crate::error::{ErrorCode, OperationError};

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub const unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0.is_invalid() {
            return;
        }

        let result = unsafe { CloseHandle(self.0) };
        if let Err(e) = result {
            crate::diag::warn(&format!("CloseHandle failed: {e}"));
        }
    }
}

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

pub fn duplicate_for_worker(
    handle: HANDLE,
    operation: &str,
    purpose: &str,
) -> crate::error::Result<OwnedHandle> {
    let mut target = HANDLE::default();
    let current = unsafe { GetCurrentProcess() };
    unsafe {
        DuplicateHandle(
            current,
            handle,
            current,
            &mut target,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|_| {
        let code = last_error();
        win32_failure(
            ErrorCode::PermissionDenied,
            operation,
            format!("cannot duplicate the target handle for {purpose}"),
            code,
        )
        .with_next_step(
            "Work that outlives the server lock owns its own handle, so a borrowed handle can              never be closed under it.",
        )
    })?;
    Ok(unsafe { OwnedHandle::from_raw(target) })
}

pub fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }.0
}

pub fn error_message(code: u32) -> Option<String> {
    let mut buffer = [0u16; 512];

    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code,
            0,
            PWSTR(buffer.as_mut_ptr()),
            buffer.len() as u32,
            None,
        )
    };
    if len == 0 {
        return None;
    }
    let text = from_wide(&buffer[..len as usize]);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub fn win32_failure(
    code: ErrorCode,
    operation: &str,
    message: impl Into<String>,
    win32: u32,
) -> OperationError {
    OperationError::new(code, operation, message).with_win32(win32, error_message(win32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_strings_are_nul_terminated() {
        let w = wide("ab");
        assert_eq!(w, vec![0x61, 0x62, 0x00]);
    }

    #[test]
    fn decoding_stops_at_the_first_nul_and_ignores_the_tail() {
        let buffer = [0x61u16, 0x62, 0x00, 0x63];
        assert_eq!(from_wide(&buffer), "ab");
    }

    #[test]
    fn a_round_trip_through_utf16_preserves_a_path() {
        let path = r"C:\Program Files\x\y.exe";
        assert_eq!(from_wide(&wide(path)), path);
    }

    #[test]
    fn access_denied_formats_to_a_message_without_being_interpreted() {
        let message = error_message(5).expect("the system has a message for error 5");
        assert!(!message.is_empty());
    }

    #[test]
    fn an_unknown_error_code_yields_no_message_rather_than_a_guess() {
        assert_eq!(error_message(0xFFFF_FFFF), None);
    }

    #[test]
    fn a_win32_failure_keeps_both_the_code_and_the_message() {
        let err = win32_failure(ErrorCode::PermissionDenied, "attach_process", "denied", 5);
        assert_eq!(err.context.win32_error, Some(5));
        assert!(err.context.win32_message.is_some());
    }
}
