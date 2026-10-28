use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    fn from_env_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }
}

pub const LEVEL_VAR: &str = "MEMSCOPE_LOG";

static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn init_from_environment() {
    if let Ok(raw) = std::env::var(LEVEL_VAR) {
        match Level::from_env_value(&raw) {
            Some(level) => THRESHOLD.store(level as u8, Ordering::Relaxed),
            None => warn(&format!(
                "{LEVEL_VAR}={raw:?} is not one of error|warn|info|debug; keeping info"
            )),
        }
    }
}

pub fn enabled(level: Level) -> bool {
    (level as u8) <= THRESHOLD.load(Ordering::Relaxed)
}

pub fn log(level: Level, message: &str) {
    if !enabled(level) {
        return;
    }

    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "[memscope {}] {message}", level.as_str());
}

pub fn error(message: &str) {
    log(Level::Error, message);
}

pub fn warn(message: &str) {
    log(Level::Warn, message);
}

pub fn info(message: &str) {
    log(Level::Info, message);
}

pub fn debug(message: &str) {
    log(Level::Debug, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_names_parse_case_insensitively_and_reject_nonsense() {
        assert_eq!(Level::from_env_value("DEBUG"), Some(Level::Debug));
        assert_eq!(Level::from_env_value(" warning "), Some(Level::Warn));
        assert_eq!(Level::from_env_value("error"), Some(Level::Error));
        assert_eq!(Level::from_env_value("verbose"), None);
        assert_eq!(Level::from_env_value(""), None);
    }

    #[test]
    fn ordering_puts_error_above_debug_so_thresholds_filter_correctly() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }
}
