use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
};
use windows::core::PCWSTR;

use crate::error::{ErrorCode, OperationError, Result};
use crate::win::{self, OwnedHandle};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowlistDocument {
    pub schema: u32,
    #[serde(default)]
    pub entries: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    pub path: String,

    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    pub display: String,

    key: String,
}

impl CanonicalPath {
    pub fn as_str(&self) -> &str {
        &self.display
    }

    fn components(&self) -> impl Iterator<Item = &str> {
        self.key.split('\\').filter(|c| !c.is_empty())
    }

    pub fn is_under(&self, root: &CanonicalPath) -> bool {
        let mut mine = self.components();
        for component in root.components() {
            match mine.next() {
                Some(c) if c == component => {}
                _ => return false,
            }
        }
        true
    }
}

fn normalise_text(path: &str) -> String {
    let mut text = path.trim().replace('/', "\\");
    for prefix in ["\\\\?\\UNC\\", "\\\\.\\UNC\\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = format!("\\\\{rest}");
        }
    }
    for prefix in ["\\\\?\\", "\\\\.\\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.to_owned();
        }
    }

    let leading_unc = text.starts_with("\\\\");
    while text.contains("\\\\") {
        text = text.replace("\\\\", "\\");
    }
    if leading_unc {
        text.insert(0, '\\');
    }

    while text.len() > 3 && text.ends_with('\\') {
        text.pop();
    }
    text
}

fn key_of(normalised: &str) -> String {
    normalised.to_lowercase()
}

pub fn canonicalise(path: &str, operation: &str) -> Result<CanonicalPath> {
    let wide = win::wide(path);

    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match handle {
        Ok(h) => unsafe { OwnedHandle::from_raw(h) },
        Err(_) => {
            let code = win::last_error();
            return Err(win::win32_failure(
                ErrorCode::TargetNotAllowed,
                operation,
                format!("cannot resolve the identity of {path:?}"),
                code,
            )
            .with_next_step(
                "Supply a path that exists and is readable; an unresolvable path is refused.",
            ));
        }
    };

    let mut buffer = vec![0u16; 1024];
    loop {
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle.raw(),
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        };
        if len == 0 {
            let code = win::last_error();
            return Err(win::win32_failure(
                ErrorCode::TargetNotAllowed,
                operation,
                format!("cannot normalise the path of {path:?}"),
                code,
            )
            .with_next_step(
                "Windows could not resolve the file path; inspect the returned OS error.",
            ));
        }

        if (len as usize) >= buffer.len() {
            buffer = vec![0u16; len as usize + 1];
            continue;
        }
        let resolved = win::from_wide(&buffer[..len as usize]);
        let display = normalise_text(&resolved);
        return Ok(CanonicalPath {
            key: key_of(&display),
            display,
        });
    }
}

pub fn sha256_file(path: &Path, operation: &str) -> Result<String> {
    let mut file = File::open(path).map_err(|e| {
        OperationError::new(
            ErrorCode::TargetNotAllowed,
            operation,
            format!("cannot read {} to measure its hash: {e}", path.display()),
        )
        .with_next_step("Make the file readable to obtain its optional SHA-256 metadata.")
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            OperationError::new(
                ErrorCode::TargetNotAllowed,
                operation,
                format!("failed while hashing {}: {e}", path.display()),
            )
            .with_next_step("Retry once the file is readable; a partial hash is never accepted.")
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[derive(Debug, Clone)]
pub struct DeniedRoot {
    pub path: CanonicalPath,
    pub reason: &'static str,
    pub resolved: bool,
}

#[derive(Debug, Clone)]
pub struct Authorisation {
    pub canonical_path: String,
    pub measured_sha256: String,
    pub note: Option<String>,
    pub policy_source: String,
}

#[derive(Default)]
pub struct Policy {}

impl Policy {
    pub fn load(_source: PathBuf) -> Self {
        Self::default()
    }

    pub fn source(&self) -> &Path {
        Path::new("windows_access")
    }

    pub fn denied_roots(&self) -> &[DeniedRoot] {
        &[]
    }

    pub fn entry_count(&self) -> usize {
        0
    }

    pub fn poisoned_reason(&self) -> Option<&str> {
        None
    }

    pub fn reload(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn revalidate(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn authorise(&mut self, exe_path: &str, operation: &str) -> Result<Authorisation> {
        let canonical_path = canonicalise(exe_path, operation)
            .map(|p| p.display)
            .unwrap_or_else(|_| normalise_text(exe_path));
        let measured_sha256 =
            sha256_file(Path::new(&canonical_path), operation).unwrap_or_default();
        Ok(Authorisation {
            canonical_path,
            measured_sha256,
            note: None,
            policy_source: self.source().display().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> CanonicalPath {
        let display = normalise_text(text);
        CanonicalPath {
            key: key_of(&display),
            display,
        }
    }

    #[test]
    fn separator_and_device_path_variants_normalise_to_one_form() {
        let expected = r"C:\Program Files\app\app.exe";
        for variant in [
            r"C:\Program Files\app\app.exe",
            r"C:/Program Files/app/app.exe",
            r"\\?\C:\Program Files\app\app.exe",
            r"\\.\C:\Program Files\app\app.exe",
            r"C:\Program Files\\app\\app.exe",
            r"  C:\Program Files\app\app.exe  ",
        ] {
            assert_eq!(normalise_text(variant), expected, "variant {variant:?}");
        }
    }

    #[test]
    fn a_unc_path_keeps_its_leading_double_separator() {
        assert_eq!(
            normalise_text(r"\\server\share\x.exe"),
            r"\\server\share\x.exe"
        );
        assert_eq!(
            normalise_text(r"\\?\UNC\server\share\x.exe"),
            r"\\server\share\x.exe"
        );
    }

    #[test]
    fn a_trailing_separator_does_not_change_the_decision() {
        assert_eq!(canon(r"C:\Windows\").key, canon(r"C:\Windows").key);
    }

    #[test]
    fn a_prefix_collision_does_not_place_a_path_under_a_root() {
        let program = canon(r"C:\Program");
        assert!(!canon(r"C:\ProgramData\x.exe").is_under(&program));
        assert!(canon(r"C:\Program\x.exe").is_under(&program));

        let program_files = canon(r"C:\Program Files");
        assert!(!canon(r"C:\Program Files Extra\x.exe").is_under(&program_files));
        assert!(canon(r"C:\Program Files\sub\x.exe").is_under(&program_files));
    }

    #[test]
    fn being_under_a_root_is_case_insensitive_like_the_filesystem() {
        let root = canon(r"C:\Windows");
        assert!(canon(r"c:\WINDOWS\system32\x.exe").is_under(&root));
    }

    #[test]
    fn a_path_equals_its_own_root() {
        let root = canon(r"C:\Windows");
        assert!(canon(r"C:\Windows").is_under(&root));
    }

    #[test]
    fn canonicalising_resolves_an_eight_dot_three_short_name() {
        let long = canonicalise(r"C:\Program Files", "test").expect("Program Files exists");
        match canonicalise(r"C:\PROGRA~1", "test") {
            Ok(short) => assert_eq!(
                short.key, long.key,
                "8.3 name must resolve to the long form"
            ),
            Err(e) => assert_eq!(e.code, ErrorCode::TargetNotAllowed),
        }
    }

    #[test]
    fn an_unresolvable_path_is_refused_rather_than_compared_textually() {
        let err = canonicalise(r"C:\this\does\not\exist\anywhere.exe", "attach_process")
            .expect_err("a non-existent path has no resolvable identity");
        assert_eq!(err.code, ErrorCode::TargetNotAllowed);
        assert!(
            err.context.win32_error.is_some(),
            "the OS code must be preserved"
        );
    }

    #[test]
    fn sha256_of_a_known_file_matches_the_published_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("abc.bin");
        std::fs::write(&path, b"abc").expect("write");

        assert_eq!(
            sha256_file(&path, "test").expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashing_an_empty_file_gives_the_empty_digest_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").expect("write");
        assert_eq!(
            sha256_file(&path, "test").expect("hash"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn target_selection_accepts_system_and_program_files_paths_without_readable_files() {
        let mut policy = Policy::default();
        for path in [
            r"C:\Windows\missing.exe",
            r"C:\Program Files\missing.exe",
            r"C:\Program Files (x86)\missing.exe",
            r"D:\Games\missing.exe",
        ] {
            let target = policy
                .authorise(path, "test")
                .expect("no path restrictions");
            assert_eq!(target.canonical_path, path);
        }
        assert!(policy.denied_roots().is_empty());
    }

    #[test]
    fn missing_malformed_or_mismatched_legacy_allowlists_do_not_restrict_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("allowlist.json");
        let mut policy = Policy::load(source.clone());
        for contents in [
            None,
            Some("invalid json"),
            Some(r#"{"schema":99,"entries":[]}"#),
            Some(r#"{"schema":1,"entries":[{"path":"missing","sha256":"wrong"}]}"#),
        ] {
            if let Some(contents) = contents {
                std::fs::write(&source, contents).expect("write");
            }
            policy.reload().expect("legacy file is ignored");
            policy
                .authorise(r"D:\Games\missing.exe", "test")
                .expect("accepted");
            assert!(policy.poisoned_reason().is_none());
        }
    }

    #[test]
    fn hashing_is_optional_metadata_and_never_a_target_selection_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.exe");
        let mut policy = Policy::default();
        let path = target.to_str().expect("path");
        assert!(
            policy
                .authorise(path, "test")
                .expect("missing file")
                .measured_sha256
                .is_empty()
        );
        std::fs::write(&target, b"abc").expect("write");
        let before = policy.authorise(path, "test").expect("readable file");
        assert_eq!(
            before.measured_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::write(&target, b"changed").expect("rewrite");
        let after = policy
            .authorise(path, "test")
            .expect("changed file is accepted");
        assert_ne!(before.measured_sha256, after.measured_sha256);
    }
}
