//! CLI-level tests for PLAN Sub-phase 2.1 (tasks 2.1.1 / 2.1.5 / 2.1.7).
//!
//! These run the real `pkt` binary against a temporary repository. No test
//! touches the public network: mirror tests talk to a loopback `TcpListener`
//! started by the test itself, and the remaining sync test uses an origin that
//! is guaranteed to have no configured mirrors.
//!
//! The configured-mirror tests are regression tests for the runtime panic
//! ("Cannot drop a runtime in a context where blocking is not allowed", exit
//! 101) that every mirror-backed `pkt -S` used to hit while `main` was a
//! `#[tokio::main]` wrapper around `reqwest::blocking`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A `pkt` invocation pinned to a temporary repository.
fn pkt(repository: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkt"));
    cmd.arg("--repository").arg(repository);
    // Keep ambient configuration from changing the outcome.
    cmd.env_remove("EXTOS_MIRRORS_L1_UNCONFIGURED_ORIGIN")
        .env_remove("EXTOS_MIRRORS_ARCHLINUX")
        .env_remove("EXTOS_CACHE_DIR");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Arch-style `.pkg.tar.xz` fixture, synthesized at runtime (no committed blobs).
fn arch_fixture(tmpdir: &Path) -> PathBuf {
    arch_package_archive(tmpdir, "hello-1.0.0-1-x86_64.pkg.tar.xz").0
}

/// Build an Arch-style `.pkg.tar.xz` named `filename` and return it with its bytes.
///
/// Synthesized at test runtime with the system `tar` (same technique as the
/// `libextos` ingest tests) — nothing is committed to the repository.
fn arch_package_archive(tmpdir: &Path, filename: &str) -> (PathBuf, Vec<u8>) {
    let src = tmpdir.join(format!("pkg_src-{filename}"));
    fs::create_dir_all(src.join("usr/bin")).unwrap();
    fs::write(src.join(".PKGINFO"), "pkgname = hello\npkgver = 1.0.0-1\n").unwrap();
    fs::write(src.join("usr/bin/hello"), "#!/bin/sh\necho hello\n").unwrap();

    let archive = tmpdir.join(filename);
    let status = Command::new("tar")
        .arg("--xz")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "failed to create test archive");
    let bytes = fs::read(&archive).expect("read test archive");
    (archive, bytes)
}

// ─── std-only loopback HTTP mirror ──────────────────────────────

/// Minimal HTTP/1.1 mirror served from a loopback `TcpListener`.
///
/// Answers every request with `200 OK` + `body` (or `404 Not Found` when no body
/// is configured) and records the requested paths. No HTTP crate involved, so
/// the test binary keeps its existing dependency set.
struct TestMirror {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestMirror {
    /// Start a mirror on an ephemeral loopback port.
    fn start(body: Option<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test mirror");
        let addr = listener.local_addr().expect("mirror address");
        listener
            .set_nonblocking(true)
            .expect("non-blocking mirror listener");

        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let body = Arc::new(body);

        let handle = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => serve_one(stream, &body, &requests),
                        Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            base_url: format!("http://{addr}"),
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// Paths requested so far, in arrival order.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("mirror request log").clone()
    }
}

impl Drop for TestMirror {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one request and write the canned response, then close the connection.
fn serve_one(stream: TcpStream, body: &Option<Vec<u8>>, requests: &Mutex<Vec<String>>) {
    let mut writer = stream.try_clone().expect("clone mirror stream");
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    // Drain the header block; the request body is irrelevant (`GET` only).
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    requests.lock().expect("mirror request log").push(path);

    let written = match body {
        Some(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                bytes.len()
            );
            writer
                .write_all(header.as_bytes())
                .and_then(|()| writer.write_all(bytes))
        }
        None => writer.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ),
    };
    let _ = written.and_then(|()| writer.flush());
}

/// A `pkt` invocation whose `testorigin` mirrors point at `base_url`.
fn pkt_with_mirror(repository: &Path, base_url: &str) -> Command {
    let mut cmd = pkt(repository);
    cmd.env("EXTOS_MIRRORS_TESTORIGIN", base_url);
    cmd
}

/// No run of `pkt` may ever hit the Tokio/`reqwest::blocking` runtime panic.
fn assert_no_runtime_panic(output: &Output) {
    let err = stderr(output);
    let out = stdout(output);
    assert!(!err.contains("panicked"), "panic in stderr: {err}");
    assert!(
        !err.contains("Cannot drop a runtime"),
        "blocking-inside-runtime panic: {err}"
    );
    assert!(
        !out.contains("Cannot drop a runtime"),
        "blocking-inside-runtime panic: {out}"
    );
    assert_ne!(output.status.code(), Some(101), "runtime abort: {err}");
}

#[test]
fn query_all_refs_on_empty_repository_succeeds() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = pkt(tmpdir.path())
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No refs in repository."));
}

#[test]
fn sync_without_mirror_exits_nonzero_with_a_clean_message() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = pkt(tmpdir.path())
        .args(["-S", "l1-unconfigured-origin/hello=1.0.0"])
        .output()
        .expect("run pkt");

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("cannot fetch l1-unconfigured-origin/hello 1.0.0"), "{err}");
    assert!(err.contains("EXTOS_MIRRORS_L1_UNCONFIGURED_ORIGIN"), "{err}");
    assert!(err.contains("failed to sync"), "{err}");
    // No panic, no backtrace.
    assert!(!err.contains("panicked"), "{err}");
    assert!(!err.contains("RUST_BACKTRACE"), "{err}");
}

#[test]
fn sync_requires_an_explicit_version() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = pkt(tmpdir.path())
        .args(["-S", "htop"])
        .output()
        .expect("run pkt");

    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("needs an explicit version"), "{err}");
}

#[test]
fn upgrade_then_query_all_refs_shows_the_ingested_row() {
    let tmpdir = tempfile::tempdir().unwrap();
    let archive = arch_fixture(tmpdir.path());
    let repository = tmpdir.path().join("repository");

    let output = pkt(&repository)
        .arg("-U")
        .arg(&archive)
        .output()
        .expect("run pkt -U");
    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(out.contains("✓ archlinux/hello 1.0.0-1 → BLAKE3-"), "{out}");

    let output = pkt(&repository)
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt -Q --all-refs");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("archlinux/hello 1.0.0-1 → BLAKE3-"), "{out}");

    // The same package is visible through the plain `-Q` listing.
    let output = pkt(&repository).arg("-Q").output().expect("run pkt -Q");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("archlinux/hello"), "{}", stdout(&output));
}

// ─── Configured-mirror sync (regression: runtime-panic class) ───

/// T1 — `-S origin/name=ver` against a configured mirror downloads, ingests and
/// commits the ref, with no runtime panic (used to exit 101 before the fix).
#[test]
fn sync_from_configured_mirror_ingests_without_panicking() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (_archive, bytes) = arch_package_archive(tmpdir.path(), "hello-1.0.0.pkg.tar.xz");
    let mirror = TestMirror::start(Some(bytes));
    let repository = tmpdir.path().join("repository");

    let output = pkt_with_mirror(&repository, &mirror.base_url)
        .args(["-S", "testorigin/hello=1.0.0"])
        .output()
        .expect("run pkt -S");

    let out = stdout(&output);
    let err = stderr(&output);
    assert_no_runtime_panic(&output);
    assert_eq!(output.status.code(), Some(0), "stdout: {out} stderr: {err}");
    assert!(out.contains("✓ testorigin/hello"), "stdout: {out}");
    assert!(out.contains("hello-1.0.0.pkg.tar.xz"), "stdout: {out}");
    assert_eq!(mirror.requests(), vec!["/hello-1.0.0.pkg.tar.xz".to_string()]);

    // The ref is committed and visible through the ref listing.
    let output = pkt(&repository)
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt -Q --all-refs");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("testorigin/hello 1.0.0-1 → BLAKE3-"), "stdout: {out}");
}

/// T2 — `-S -w` downloads to the cache but never ingests or writes a ref.
#[test]
fn sync_download_only_from_configured_mirror_skips_ingest() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (_archive, bytes) = arch_package_archive(tmpdir.path(), "hello-1.0.0.pkg.tar.xz");
    let mirror = TestMirror::start(Some(bytes));
    let repository = tmpdir.path().join("repository");

    let output = pkt_with_mirror(&repository, &mirror.base_url)
        .args(["-S", "-w", "testorigin/hello=1.0.0"])
        .output()
        .expect("run pkt -S -w");

    let out = stdout(&output);
    let err = stderr(&output);
    assert_no_runtime_panic(&output);
    assert_eq!(output.status.code(), Some(0), "stdout: {out} stderr: {err}");
    assert!(out.contains("↓ "), "stdout: {out}");
    assert!(out.contains("hello-1.0.0.pkg.tar.xz"), "stdout: {out}");
    assert!(
        repository.join("cache/testorigin/hello-1.0.0.pkg.tar.xz").is_file(),
        "cached archive missing"
    );

    let output = pkt(&repository)
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt -Q --all-refs");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("No refs in repository."),
        "download-only must not commit a ref: {}",
        stdout(&output)
    );
}

/// T3 — a 404 from every configured mirror is a clean "not found", not a panic.
#[test]
fn sync_from_mirror_404_exits_nonzero_with_a_clean_not_found_error() {
    let tmpdir = tempfile::tempdir().unwrap();
    let mirror = TestMirror::start(None);
    let repository = tmpdir.path().join("repository");

    let output = pkt_with_mirror(&repository, &mirror.base_url)
        .args(["-S", "testorigin/hello=1.0.0"])
        .output()
        .expect("run pkt -S");

    let err = stderr(&output);
    assert_no_runtime_panic(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("Package not found: testorigin/hello/1.0.0"), "stderr: {err}");
    assert!(err.contains("failed to sync"), "stderr: {err}");
    assert!(!mirror.requests().is_empty(), "mirror was never contacted");
}

/// T4 — an unreachable mirror (connection refused) fails cleanly, no panic.
#[test]
fn sync_from_unreachable_mirror_exits_nonzero_with_a_clean_error() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");

    // Grab an ephemeral port and release it so the connect is refused.
    let dead = TcpListener::bind("127.0.0.1:0").expect("bind placeholder");
    let addr = dead.local_addr().expect("placeholder address");
    drop(dead);

    let output = pkt_with_mirror(&repository, &format!("http://{addr}"))
        .args(["-S", "testorigin/hello=1.0.0"])
        .output()
        .expect("run pkt -S");

    let err = stderr(&output);
    assert_no_runtime_panic(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("all mirrors failed for testorigin/hello/1.0.0"), "stderr: {err}");
    assert!(err.contains("failed to sync"), "stderr: {err}");
}

// ─── Sub-phase 2.2: files search, remove, database GC ──────────

/// Ingest the standard Arch fixture into `repository` via `-U`.
fn ingest_fixture(repository: &Path, tmpdir: &Path) {
    let archive = arch_fixture(tmpdir);
    let output = pkt(repository)
        .arg("-U")
        .arg(&archive)
        .output()
        .expect("run pkt -U");
    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        stdout(&output),
        stderr(&output)
    );
}

/// Number of object directories in `<repository>/objects`.
fn object_count(repository: &Path) -> usize {
    fs::read_dir(repository.join("objects"))
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

/// `-F <path>` finds the file ingested by `-U` and names its owner.
#[test]
fn files_search_finds_an_ingested_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");
    ingest_fixture(&repository, tmpdir.path());

    let output = pkt(&repository)
        .args(["-F", "/usr/bin/hello"])
        .output()
        .expect("run pkt -F");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("archlinux/hello 1.0.0-1 /usr/bin/hello"), "stdout: {out}");

    // A glob query matches the same file.
    let output = pkt(&repository)
        .args(["-F", "hel*"])
        .output()
        .expect("run pkt -F");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("/usr/bin/hello"), "{}", stdout(&output));
}

/// A miss prints no result row and still exits 0 (quiet grep-like behaviour).
///
/// `tracing` writes its INFO lines to stdout, so absence is asserted on the
/// result rows themselves rather than on an empty stream.
#[test]
fn files_search_miss_exits_zero_with_no_rows() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");
    ingest_fixture(&repository, tmpdir.path());

    let output = pkt(&repository)
        .args(["-F", "/no/such/file"])
        .output()
        .expect("run pkt -F");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(!out.contains("archlinux/hello"), "stdout: {out}");
    assert!(!out.contains("/usr/bin/hello"), "stdout: {out}");
    assert!(!out.contains("owns a file"), "stdout: {out}");

    // Empty repository: still a clean, empty result.
    let empty = tmpdir.path().join("empty-repository");
    let output = pkt(&empty)
        .args(["-F", "/no/such/file"])
        .output()
        .expect("run pkt -F");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(!stdout(&output).contains("archlinux/hello"), "{}", stdout(&output));
}

/// `-R` without operands is a usage error, not a silent no-op.
#[test]
fn remove_without_packages_exits_nonzero() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = pkt(tmpdir.path()).arg("-R").output().expect("run pkt -R");
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("no packages specified"), "stderr: {err}");
}

/// `-R --recursive` clears the ref rows and lets GC purge the objects.
#[test]
fn remove_recursive_drops_rows_and_purges_objects() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");
    ingest_fixture(&repository, tmpdir.path());
    assert_eq!(object_count(&repository), 1, "fixture should store one object");

    let output = pkt(&repository)
        .args(["-R", "--recursive", "hello"])
        .output()
        .expect("run pkt -R");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("Removed archlinux/hello/1.0.0-1"), "stdout: {out}");
    assert!(out.contains("archlinux/hello: removed 1 version(s)"), "stdout: {out}");
    assert!(out.contains("GC: purged 1 orphaned objects"), "stdout: {out}");

    // No rows, no objects left behind.
    assert_eq!(object_count(&repository), 0, "objects not purged");
    let output = pkt(&repository)
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt -Q --all-refs");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No refs in repository."));
    let output = pkt(&repository).arg("-Q").output().expect("run pkt -Q");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(!stdout(&output).contains("archlinux/hello"), "{}", stdout(&output));
}

/// `-R` also works for a package that arrived through `-S`.
#[test]
fn sync_then_remove_leaves_no_refs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (_archive, bytes) = arch_package_archive(tmpdir.path(), "hello-1.0.0.pkg.tar.xz");
    let mirror = TestMirror::start(Some(bytes));
    let repository = tmpdir.path().join("repository");

    let output = pkt_with_mirror(&repository, &mirror.base_url)
        .args(["-S", "testorigin/hello=1.0.0"])
        .output()
        .expect("run pkt -S");
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let output = pkt(&repository)
        .args(["-R", "hello"])
        .output()
        .expect("run pkt -R");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("testorigin/hello: removed 1 version(s)"));

    let output = pkt(&repository)
        .args(["-Q", "--all-refs"])
        .output()
        .expect("run pkt -Q --all-refs");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No refs in repository."));
}

/// Removing an unknown package is an error but must not abort the whole run.
#[test]
fn remove_unknown_package_reports_and_exits_nonzero() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");
    ingest_fixture(&repository, tmpdir.path());

    let output = pkt(&repository)
        .args(["-R", "hello", "does-not-exist"])
        .output()
        .expect("run pkt -R");
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("package 'does-not-exist' was not found"), "stderr: {err}");
    assert!(err.contains("1 package(s) not found"), "stderr: {err}");
    // The known package was still removed.
    assert!(stdout(&output).contains("archlinux/hello: removed 1 version(s)"));
}

/// `-D --gc` purges orphaned objects through `cas::garbage_collect()`.
#[test]
fn database_gc_purges_orphaned_objects() {
    let tmpdir = tempfile::tempdir().unwrap();
    let repository = tmpdir.path().join("repository");
    ingest_fixture(&repository, tmpdir.path());
    assert_eq!(object_count(&repository), 1);

    // Drop the ref table by hand: the object becomes unreachable.
    fs::remove_dir_all(repository.join("refs")).expect("drop refs");

    let output = pkt(&repository)
        .args(["-D", "--gc"])
        .output()
        .expect("run pkt -D --gc");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("Purged 1 objects:"), "stdout: {out}");
    assert_eq!(object_count(&repository), 0);
}

/// `-D --gc` on an empty repository reports cleanly.
#[test]
fn database_gc_on_empty_repository_is_clean() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = pkt(tmpdir.path())
        .args(["-D", "--gc"])
        .output()
        .expect("run pkt -D --gc");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("No orphaned objects found."));
}
