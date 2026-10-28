#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixture_exe(arch: &str) -> PathBuf {
    repo_root()
        .join("fixtures")
        .join("bin")
        .join(arch)
        .join("memscope-fixture.exe")
}

pub fn require_fixtures() {
    for arch in ["x64", "x86"] {
        let exe = fixture_exe(arch);
        assert!(
            exe.exists(),
            "{} is missing; run `& fixtures/build.ps1` first",
            exe.display()
        );
    }
}

pub fn write_allowlist(dir: &Path, entries: &[(PathBuf, String)]) -> PathBuf {
    let path = dir.join("allowlist.json");
    let items: Vec<Value> = entries
        .iter()
        .map(|(exe, sha)| serde_json::json!({ "path": exe.display().to_string(), "sha256": sha }))
        .collect();
    let document = serde_json::json!({ "schema": 1, "entries": items });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).expect("serialise"),
    )
    .expect("write allowlist");
    path
}

pub fn allowlist_for(dir: &Path, arch: &str) -> PathBuf {
    let exe = fixture_exe(arch);
    let sha = memscope::policy::sha256_file(&exe, "test").expect("hash the fixture");
    write_allowlist(dir, &[(exe, sha)])
}

pub struct Fixture {
    child: Child,
    pub meta: Value,
    pipe: std::fs::File,
    lines: Arc<Mutex<Vec<String>>>,
    pub arch: String,
}

impl Fixture {
    pub fn start(arch: &str) -> Self {
        Self::start_with_args(arch, &[])
    }

    pub fn start_with_args(arch: &str, args: &[&str]) -> Self {
        let exe = fixture_exe(arch);
        assert!(exe.exists(), "{} is missing", exe.display());
        let mut child = Command::new(&exe)
            .args(args)
            .current_dir(exe.parent().expect("fixture directory"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the fixture");

        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);

        let mut json_line = String::new();
        reader.read_line(&mut json_line).expect("read startup json");
        let meta: Value = serde_json::from_str(json_line.trim())
            .unwrap_or_else(|e| panic!("startup line was not JSON: {e}\n{json_line}"));

        let mut ready = String::new();
        reader.read_line(&mut ready).expect("read ready sentinel");
        assert_eq!(ready.trim(), "ready", "fixture did not become ready");

        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let drain = Arc::clone(&lines);
        std::thread::spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => drain
                        .lock()
                        .expect("lines lock")
                        .push(line.trim().to_owned()),
                }
            }
        });

        let pipe_path = meta["pipe_path"].as_str().expect("pipe_path").to_owned();
        let pipe = Self::connect(&pipe_path);

        Self {
            child,
            meta,
            pipe,
            lines,
            arch: arch.to_owned(),
        }
    }

    fn connect(pipe_path: &str) -> std::fs::File {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pipe_path)
            {
                Ok(f) => return f,
                Err(e) if Instant::now() < deadline => {
                    if matches!(e.kind(), std::io::ErrorKind::NotFound) {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("cannot open {pipe_path}: {e}"),
            }
        }
    }

    pub fn send(&mut self, command: &str) -> String {
        self.pipe
            .write_all(format!("{command}\n").as_bytes())
            .expect("write command");
        self.pipe.flush().expect("flush command");
        let mut byte = [0u8; 1];
        let mut out = Vec::new();
        loop {
            let read = self.pipe.read(&mut byte).expect("read reply");
            if read == 0 {
                break;
            }
            if byte[0] == b'\n' {
                break;
            }
            out.push(byte[0]);
        }
        String::from_utf8_lossy(&out).trim_end().to_owned()
    }

    pub fn pid(&self) -> u32 {
        self.meta["pid"].as_u64().expect("pid") as u32
    }

    pub fn exe(&self) -> PathBuf {
        PathBuf::from(self.meta["exe"].as_str().expect("exe"))
    }

    pub fn area(&self, name: &str) -> u64 {
        let text = self.meta["areas"][name]["address"]
            .as_str()
            .unwrap_or_else(|| panic!("area {name} has no address"));
        u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("hex address")
    }

    pub fn layout(&self, name: &str) -> u64 {
        self.meta["layout"][name]
            .as_u64()
            .unwrap_or_else(|| panic!("layout has no {name}"))
    }

    pub fn counter_address(&self) -> u64 {
        self.area("block") + self.layout("counter")
    }

    pub fn stdout_lines(&self) -> Vec<String> {
        self.lines.lock().expect("lines lock").clone()
    }

    pub fn wait_for_exit(&mut self, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => return status.code(),
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                None => return None,
            }
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill();
    }
}
