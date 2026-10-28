#![allow(clippy::result_large_err)]
#![allow(clippy::missing_safety_doc)]

pub mod diag;
pub mod error;
pub mod wire;

pub mod win;

pub mod policy;

pub mod target;

pub mod mem;

pub mod investigate;
pub mod kernel;
pub mod scan;

pub mod ptr;

pub mod mutate;

pub mod mcp;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const WRITE_ENABLE_VAR: &str = "MEMSCOPE_ALLOW_WRITE";

pub fn writes_enabled_in_environment() -> bool {
    std::env::var(WRITE_ENABLE_VAR).is_ok_and(|v| v == "1")
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_an_exact_one_enables_writes() {
        let accepts = |v: &str| v == "1";
        assert!(accepts("1"));
        for rejected in ["", "0", "true", "yes", "on", " 1", "1 ", "01", "TRUE"] {
            assert!(!accepts(rejected), "{rejected:?} must not enable writes");
        }
    }
}
