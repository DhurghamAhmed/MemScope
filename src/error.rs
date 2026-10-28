use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    NotAttached,
    TargetNotAllowed,
    PermissionDenied,
    ProcessGone,
    ProcessReplaced,
    InvalidAddress,
    PartialRead,
    DecodeError,
    WriteDisabled,
    ConfirmationRequired,
    PartialWrite,
    VerifyFailed,
    AddressFrozen,
    UndoConflict,
    UnsupportedArchitecture,
    UnsupportedPointerWidth,
    ConsistencyUnavailable,
    ScanStateInvalid,
    BudgetExceeded,
    Cancelled,
    OperationInFlight,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotAttached => "NOT_ATTACHED",
            Self::TargetNotAllowed => "TARGET_NOT_ALLOWED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ProcessGone => "PROCESS_GONE",
            Self::ProcessReplaced => "PROCESS_REPLACED",
            Self::InvalidAddress => "INVALID_ADDRESS",
            Self::PartialRead => "PARTIAL_READ",
            Self::DecodeError => "DECODE_ERROR",
            Self::WriteDisabled => "WRITE_DISABLED",
            Self::ConfirmationRequired => "CONFIRMATION_REQUIRED",
            Self::PartialWrite => "PARTIAL_WRITE",
            Self::VerifyFailed => "VERIFY_FAILED",
            Self::AddressFrozen => "ADDRESS_FROZEN",
            Self::UndoConflict => "UNDO_CONFLICT",
            Self::UnsupportedArchitecture => "UNSUPPORTED_ARCHITECTURE",
            Self::UnsupportedPointerWidth => "UNSUPPORTED_POINTER_WIDTH",
            Self::ConsistencyUnavailable => "CONSISTENCY_UNAVAILABLE",
            Self::ScanStateInvalid => "SCAN_STATE_INVALID",
            Self::BudgetExceeded => "BUDGET_EXCEEDED",
            Self::Cancelled => "CANCELLED",
            Self::OperationInFlight => "OPERATION_IN_FLIGHT",
        }
    }

    pub const REQUIRED: usize = 21;

    pub const ALL: [Self; 22] = [
        Self::InvalidArgument,
        Self::NotAttached,
        Self::TargetNotAllowed,
        Self::PermissionDenied,
        Self::ProcessGone,
        Self::ProcessReplaced,
        Self::InvalidAddress,
        Self::PartialRead,
        Self::DecodeError,
        Self::WriteDisabled,
        Self::ConfirmationRequired,
        Self::PartialWrite,
        Self::VerifyFailed,
        Self::AddressFrozen,
        Self::UndoConflict,
        Self::UnsupportedArchitecture,
        Self::UnsupportedPointerWidth,
        Self::ConsistencyUnavailable,
        Self::ScanStateInvalid,
        Self::BudgetExceeded,
        Self::Cancelled,
        Self::OperationInFlight,
    ];
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_error: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub win32_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationError {
    pub code: ErrorCode,
    pub message: String,

    pub operation: String,
    #[serde(flatten)]
    pub context: ErrorContext,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
}

impl OperationError {
    pub fn new(code: ErrorCode, operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            operation: operation.into(),
            context: ErrorContext::default(),
            next_step: None,
        }
    }

    pub fn with_next_step(mut self, step: impl Into<String>) -> Self {
        self.next_step = Some(step.into());
        self
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.context.session_id = Some(session_id.into());
        self
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.context.pid = Some(pid);
        self
    }

    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.context.address = Some(address.into());
        self
    }

    pub fn with_win32(mut self, code: u32, message: Option<String>) -> Self {
        self.context.win32_error = Some(code);
        self.context.win32_message = message;
        self
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {}: {}", self.code, self.operation, self.message)?;
        if let Some(code) = self.context.win32_error {
            write!(f, " (win32 {code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for OperationError {}

pub type Result<T> = std::result::Result<T, OperationError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_required_error_code_keeps_its_brief_spelling() {
        let expected = [
            "INVALID_ARGUMENT",
            "NOT_ATTACHED",
            "TARGET_NOT_ALLOWED",
            "PERMISSION_DENIED",
            "PROCESS_GONE",
            "PROCESS_REPLACED",
            "INVALID_ADDRESS",
            "PARTIAL_READ",
            "DECODE_ERROR",
            "WRITE_DISABLED",
            "CONFIRMATION_REQUIRED",
            "PARTIAL_WRITE",
            "VERIFY_FAILED",
            "ADDRESS_FROZEN",
            "UNDO_CONFLICT",
            "UNSUPPORTED_ARCHITECTURE",
            "UNSUPPORTED_POINTER_WIDTH",
            "CONSISTENCY_UNAVAILABLE",
            "SCAN_STATE_INVALID",
            "BUDGET_EXCEEDED",
            "CANCELLED",
        ];
        let actual: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(expected.len(), ErrorCode::REQUIRED);
        assert_eq!(actual[..ErrorCode::REQUIRED], expected);
    }

    #[test]
    fn every_code_beyond_the_brief_is_named_here_too() {
        let added: Vec<&str> = ErrorCode::ALL[ErrorCode::REQUIRED..]
            .iter()
            .map(|c| c.as_str())
            .collect();
        assert_eq!(added, ["OPERATION_IN_FLIGHT"]);
    }

    #[test]
    fn error_code_serialises_as_its_wire_string() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).expect("serialise");
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }

    #[test]
    fn a_win32_code_survives_into_the_serialised_failure() {
        let err = OperationError::new(ErrorCode::PermissionDenied, "attach_process", "denied")
            .with_pid(4321)
            .with_win32(5, Some("Access is denied.".into()))
            .with_next_step("Confirm the target is owned by the current user.");
        let value = serde_json::to_value(&err).expect("serialise");
        assert_eq!(value["code"], "PERMISSION_DENIED");
        assert_eq!(value["operation"], "attach_process");
        assert_eq!(value["win32_error"], 5);
        assert_eq!(value["pid"], 4321);

        assert!(value.get("address").is_none());
        assert!(value.get("session_id").is_none());
    }
}
