//! CLI-level tests for PLAN 5.2.4 — `pkt -F --soname <soname>`.
//!
//! These spawn the real `pkt` binary (`CARGO_BIN_EXE_pkt`) against a temporary
//! CAS fixture built with `libextos` directly, so no archive, no mirror and no
//! network are involved.
//!
//! The positional `-F <query>` form is the Phase-2 file search and stays
//! bit-stable (`core/pkt/tests/cli.rs::files_search_*`); the capability index is
//! reached through the explicit `--soname` flag, which is the documented tie
//! between PLAN 5.2.4 ("`pkt -F <soname>`") and the existing `-F` contract.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use libextos::cas::CasRepository;
use libextos::types::HashAlgorithm;

// ─── Fixture ────────────────────────────────────────────────────

/// Publish one package with a `capabilities.libraries` manifest into `repo`.
fn publish(
    repo: &CasRepository,
    staging: &Path,
    origin: &str,
    name: &str,
    version: &str,
    libraries: &[&str],
) -> String {
    let src = staging.join(format!("{origin}-{name}-{version}"));
    let marker = src.join(format!("usr/share/doc/{name}/{version}"));
    fs::create_dir_all(&marker).unwrap();
    fs::write(marker.join("version"), version).unwrap();

    let hash = repo.store_directory(&src).unwrap();
    let list = libraries
        .iter()
        .map(|soname| format!("\"{soname}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let manifest = format!(
        "{{ identity = {{ origin = \"{origin}\"; name = \"{name}\"; version = \"{version}\"; }};\n\
         capabilities = {{ libraries = [ {list} ]; }}; }}"
    );
    repo.write_manifest(&hash, &manifest).unwrap();
    repo.create_ref(origin, name, version, &hash).unwrap();
    hash
}

/// Build a repository with `archlinux/openssl` (libssl.so.3) and
/// `rpm/openssl` (libssl.so.10). Returns `(tempdir, repository path)`.
fn repository() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repository");
    let repo = CasRepository::open(&root, HashAlgorithm::Blake3).unwrap();
    publish(
        &repo,
        tmp.path(),
        "archlinux",
        "openssl",
        "3.3.1-1",
        &["libssl.so.3", "libcrypto.so.3"],
    );
    publish(
        &repo,
        tmp.path(),
        "rpm",
        "openssl",
        "3.0.13",
        &["libssl.so.10"],
    );
    (tmp, root)
}

fn pkt(repository: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pkt"));
    cmd.arg("--repository").arg(repository);
    // Keep ambient configuration/output formatting from changing the outcome.
    cmd.env_remove("EXTOS_REPOSITORY")
        .env_remove("EXTOS_CACHE_DIR")
        .env_remove("RUST_LOG")
        .env("NO_COLOR", "1");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run `pkt -F --soname <soname>` against a fresh fixture repository.
fn query_soname(soname: &str) -> Output {
    let (_tmp, root) = repository();
    pkt(&root)
        .args(["-F", "--soname", soname])
        .output()
        .expect("run pkt -F --soname")
}

// ─── Tests ──────────────────────────────────────────────────────

#[test]
fn soname_query_prints_the_archlinux_provider() {
    let (_tmp, root) = repository();
    let output = pkt(&root)
        .args(["-F", "--soname", "libssl.so.3"])
        .output()
        .expect("run pkt -F --soname");

    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(out.contains("libssl.so.3:"), "stdout: {out}");
    assert!(out.contains("archlinux/openssl 3.3.1-1 → BLAKE3-"), "stdout: {out}");
    assert!(out.contains("1 provider(s) for libssl.so.3"), "stdout: {out}");
    assert!(out.contains("indexed 3 SONAME(s) across 2 ref(s)"), "stdout: {out}");
    // The other origin must not leak into a libssl.so.3 answer.
    assert!(!out.contains("rpm/openssl"), "stdout: {out}");
}

#[test]
fn soname_query_resolves_the_negative_case() {
    let output = query_soname("libssl.so.10");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("rpm/openssl 3.0.13 → BLAKE3-"), "stdout: {out}");
    assert!(out.contains("1 provider(s) for libssl.so.10"), "stdout: {out}");
    assert!(!out.contains("archlinux/openssl"), "stdout: {out}");
}

#[test]
fn missing_soname_exits_zero_with_the_documented_message() {
    let output = query_soname("libnope.so.9");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("no providers for libnope.so.9"),
        "stdout: {}",
        stdout(&output)
    );
}

#[test]
fn repository_comes_from_extos_repository_env() {
    let (_tmp, root) = repository();
    let output = Command::new(env!("CARGO_BIN_EXE_pkt"))
        .env("EXTOS_REPOSITORY", &root)
        .env_remove("EXTOS_CACHE_DIR")
        .env_remove("RUST_LOG")
        .env("NO_COLOR", "1")
        .args(["-F", "--soname", "libssl.so.3"])
        .output()
        .expect("run pkt with EXTOS_REPOSITORY");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("archlinux/openssl"),
        "stdout: {}",
        stdout(&output)
    );
}

#[test]
fn malformed_soname_is_a_typed_error_with_nonzero_exit() {
    let output = query_soname("../../etc/passwd");
    assert_eq!(output.status.code(), Some(1), "stdout: {}", stdout(&output));
    let err = stderr(&output);
    assert!(err.contains("invalid capability SONAME"), "stderr: {err}");
    assert!(err.contains("path separator") || err.contains("path-traversal"), "stderr: {err}");
    // No panic, no backtrace.
    assert!(!err.contains("panicked"), "stderr: {err}");
}

#[test]
fn bare_dash_f_is_a_usage_error() {
    let (_tmp, root) = repository();
    let output = pkt(&root).arg("-F").output().expect("run pkt -F");
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("no query specified"), "stderr: {err}");
}

#[test]
fn file_query_and_soname_are_mutually_exclusive() {
    let (_tmp, root) = repository();
    let output = pkt(&root)
        .args(["-F", "/usr/lib/libssl.so.3", "--soname", "libssl.so.3"])
        .output()
        .expect("run pkt -F ... --soname ...");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("choose either a file query or --soname"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn skipped_rows_are_warned_about_and_do_not_hide_healthy_providers() {
    let (tmp, root) = repository();
    let repo = CasRepository::open(&root, HashAlgorithm::Blake3).unwrap();
    // A ref whose object has no manifest: population must skip it with a warning.
    let orphan = repo.store_bytes(b"no manifest").unwrap();
    repo.create_ref("debian", "libssl", "3.0.13", &orphan)
        .unwrap();

    let output = pkt(&root)
        .args(["-F", "--soname", "libssl.so.3"])
        .output()
        .expect("run pkt -F --soname");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("archlinux/openssl"),
        "stdout: {}",
        stdout(&output)
    );
    let err = stderr(&output);
    assert!(err.contains("warning: skipped debian/libssl/3.0.13"), "stderr: {err}");
    assert!(
        stdout(&output).contains("(1 warning(s))"),
        "stdout: {}",
        stdout(&output)
    );
    drop(tmp);
}

#[test]
fn corrupt_manifest_is_a_warned_miss_not_a_fatal_error() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repository");
    let repo = CasRepository::open(&root, HashAlgorithm::Blake3).unwrap();
    // A parseable-looking but invalid manifest.nix on a live ref.
    let broken = repo.store_bytes(b"broken").unwrap();
    repo.write_manifest(&broken, "{ not = valid = nix").unwrap();
    repo.create_ref("archlinux", "openssl", "3.3.1", &broken)
        .unwrap();

    let output = pkt(&root)
        .args(["-F", "--soname", "libssl.so.3"])
        .output()
        .expect("run pkt -F --soname");

    // The corrupt row is skipped (warned, not fatal) and the query is an
    // honest miss — exit 0 with the documented message.
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("no providers for libssl.so.3"),
        "stdout: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("warning: skipped archlinux/openssl/3.3.1"),
        "stderr: {}",
        stderr(&output)
    );
}
