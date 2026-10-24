//! Integration tests for the `pkt` gRPC control plane (PLAN 8.1.3).
//!
//! The server is driven in-process through the REAL tonic stack over a tmpdir
//! UDS: `server::serve` runs on a background OS thread with its own explicit
//! multi-thread runtime (exactly the `pkt serve` path — repo open, runtime
//! build, UDS bind with the §15 mode, `serve_with_incoming`), and the
//! generated `PktServiceClient` connects through a `unix://` `Endpoint`.
//!
//! The module is compiled in from `src/server.rs` with `#[path]` because pkt
//! is a pure binary crate (no lib target to link against); that also re-runs
//! server.rs's in-module unit tests inside this test binary.
//!
//! Every archive fixture is synthesized at test runtime with `tar` (the
//! `libextos/tests/ingest_local.rs` pattern — no binary blobs committed), and
//! no test touches the network: the mirror path only exercises the
//! unconfigured-origin domain error.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use libextos::pb::extos::common::ErrorCode;
use libextos::pb::extos::pkt::pkt_service_client::PktServiceClient;
use libextos::pb::extos::pkt::{
    FilesRequest, IngestRequest, QueryRequest, SonameRequest, SyncRequest,
};
use libextos::rosetta::registry::RosettaRegistry;
use libextos::types::HashAlgorithm;
use tonic::transport::Endpoint;

#[path = "../src/server.rs"]
mod server;

use server::ServeError;

/// Spawn `server::serve` on a detached OS thread — the real `pkt serve` path,
/// including its explicit multi-thread runtime construction.
fn spawn_serve(repo_root: PathBuf, socket: PathBuf) {
    thread::spawn(move || {
        let rosetta = RosettaRegistry::discover();
        server::serve(&repo_root, HashAlgorithm::Blake3, &socket, rosetta)
            .expect("serve loop failed");
    });
}

/// Wait (bounded) until the control socket file exists.
fn wait_for_socket(socket: &Path) {
    for _ in 0..500 {
        if socket.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("control socket {} never appeared", socket.display());
}

/// Connect a generated client through a `unix://` Endpoint, tolerating the
/// tick between socket-file creation and the accept loop start.
async fn connect(socket: &Path) -> PktServiceClient<tonic::transport::Channel> {
    let endpoint =
        Endpoint::from_shared(format!("unix://{}", socket.display())).expect("unix endpoint");
    for _ in 0..250 {
        match endpoint.connect().await {
            Ok(channel) => return PktServiceClient::new(channel),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("could not connect to {}", socket.display());
}

/// Native `.pkt.tar.xz` fixture: `metadata/manifest.nix` + `content/`,
/// synthesized with `tar`. The manifest declares a SONAME so the `Soname`
/// RPC has something to index.
fn native_fixture(tmpdir: &Path) -> PathBuf {
    let src = tmpdir.join("fixture_src");
    fs::create_dir_all(src.join("metadata")).expect("metadata dir");
    fs::create_dir_all(src.join("content/usr/bin")).expect("bin dir");
    fs::create_dir_all(src.join("content/usr/lib")).expect("lib dir");
    fs::write(
        src.join("metadata/manifest.nix"),
        r#"{
  identity = {
    origin = "scratch";
    name = "wire-native";
    version = "3.1.4";
  };
  format = "extracted-tree";
  capabilities = {
    binaries = [ "wire-bin" ];
    libraries = [ "libwiretest.so.1" ];
  };
  requires = [];
}"#,
    )
    .expect("manifest");
    fs::write(src.join("content/usr/bin/wire-bin"), "#!/bin/sh\necho wire\n")
        .expect("binary payload");
    fs::write(
        src.join("content/usr/lib/libwiretest.so.1"),
        "placeholder: not a real ELF object\n",
    )
    .expect("library payload");

    let archive = tmpdir.join("wire-native-3.1.4.pkt.tar.xz");
    let status = Command::new("tar")
        .arg("--xz")
        .arg("-cf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg("metadata")
        .arg("content")
        .status()
        .expect("spawn tar");
    assert!(status.success(), "failed to create {}", archive.display());
    archive
}

#[tokio::test(flavor = "multi_thread")]
async fn full_round_trip_over_uds() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let repo_root = tmp.path().join("repository");
    let socket = tmp.path().join("pkt.sock");
    spawn_serve(repo_root, socket.clone());
    wait_for_socket(&socket);
    let mut client = connect(&socket).await;

    // ── Socket hygiene (ARCHITECTURE §15): mode 0660 ────────────────────────
    // Group wiring (`wheel`) is PLAN 8.1.5 and deliberately not asserted here.
    let mode = fs::metadata(&socket).expect("socket stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "control socket mode");

    // ── Ingest: native fixture, origin auto-detect → embedded manifest ──────
    let archive = native_fixture(tmp.path());
    let ingest_resp = client
        .ingest(IngestRequest {
            archive_path: archive.display().to_string(),
            origin: None,
            rosetta: false,
        })
        .await
        .expect("ingest rpc")
        .into_inner();
    assert!(
        ingest_resp.error.is_none(),
        "ingest failed: {:?}",
        ingest_resp.error
    );
    assert_eq!(ingest_resp.origin, "scratch");
    assert_eq!(ingest_resp.name, "wire-native");
    assert_eq!(ingest_resp.version, "3.1.4");
    assert!(ingest_resp.hash.starts_with("BLAKE3-"), "{}", ingest_resp.hash);
    assert_eq!(ingest_resp.sanitized_bits, 0);
    assert!(!ingest_resp.rosetta_translated);
    let caps = ingest_resp.capabilities.as_ref().expect("capabilities set");
    assert!(
        caps.libraries.iter().any(|s| s == "libwiretest.so.1"),
        "{caps:?}"
    );
    let hash = ingest_resp.hash.clone();

    // ── Query: full table, origin filter, malformed-filter domain error ─────
    let query_resp = client
        .query(QueryRequest { origin: None })
        .await
        .expect("query rpc")
        .into_inner();
    assert!(query_resp.error.is_none(), "{:?}", query_resp.error);
    let row = query_resp
        .refs
        .iter()
        .find(|r| r.name == "wire-native")
        .expect("ingested ref visible through Query");
    assert_eq!(row.origin, "scratch");
    assert_eq!(row.version, "3.1.4");
    assert_eq!(row.object_hash.as_deref(), Some(hash.as_str()));

    let filtered = client
        .query(QueryRequest { origin: Some("scratch".into()) })
        .await
        .expect("filtered query rpc")
        .into_inner();
    assert!(filtered.error.is_none());
    assert!(!filtered.refs.is_empty());
    assert!(filtered.refs.iter().all(|r| r.origin == "scratch"));

    let bad_filter = client
        .query(QueryRequest { origin: Some(String::new()) })
        .await
        .expect("bad filter rpc (transport stays OK)")
        .into_inner();
    let err = bad_filter
        .error
        .expect("empty origin filter is a domain error");
    assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");

    // ── Files: substring hit with leading-slash path; quiet miss otherwise ──
    let files_resp = client
        .files(FilesRequest { path_query: "wire-bin".into() })
        .await
        .expect("files rpc")
        .into_inner();
    assert!(files_resp.error.is_none(), "{:?}", files_resp.error);
    assert_eq!(files_resp.hits.len(), 1, "{:?}", files_resp.hits);
    assert_eq!(files_resp.hits[0].path, "/usr/bin/wire-bin");
    let hit_ref = files_resp.hits[0].ref_entry.as_ref().expect("ref on hit");
    assert_eq!(hit_ref.name, "wire-native");

    // ── Soname: capability index over the ingested fixture ──────────────────
    let soname_resp = client
        .soname(SonameRequest { soname: "libwiretest.so.1".into() })
        .await
        .expect("soname rpc")
        .into_inner();
    assert!(soname_resp.error.is_none(), "{:?}", soname_resp.error);
    assert_eq!(soname_resp.providers.len(), 1, "{:?}", soname_resp.providers);
    let provider = &soname_resp.providers[0];
    assert_eq!(provider.origin, "scratch");
    assert_eq!(provider.name, "wire-native");
    assert_eq!(provider.ref_version, "3.1.4");
    assert_eq!(provider.object_hash.as_deref(), Some(hash.as_str()));
    assert!(soname_resp.sonames_indexed >= 1, "{soname_resp:?}");

    let bad_soname = client
        .soname(SonameRequest { soname: "/etc/../passwd".into() })
        .await
        .expect("bad soname rpc (transport stays OK)")
        .into_inner();
    let err = bad_soname
        .error
        .expect("malformed SONAME is a domain error");
    assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");

    // ── Sync (download-only) against an unconfigured mirror: domain error ───
    let sync_resp = client
        .sync(SyncRequest {
            // An origin whose `EXTOS_MIRRORS_*` variable no test environment
            // configures — no network access happens.
            origin: "extos-no-mirrors-origin".into(),
            name: "absent-pkg".into(),
            version: "1.0".into(),
            download_only: true,
        })
        .await
        .expect("sync rpc (transport stays OK)")
        .into_inner();
    let err = sync_resp
        .error
        .expect("unconfigured mirror is a domain error");
    assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
    assert!(sync_resp.archive_path.is_empty(), "nothing was downloaded");
}

#[test]
fn serve_reports_taken_socket_as_typed_bind_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let socket = tmp.path().join("taken.sock");
    // Hold the path with a plain std listener: a second bind must fail typed,
    // naming the socket path (the operator-facing `pkt serve` behaviour).
    let _held = std::os::unix::net::UnixListener::bind(&socket).expect("hold socket");
    match server::bind_control_socket(&socket) {
        Err(ServeError::Bind { path, .. }) => assert_eq!(path, socket),
        other => panic!("expected ServeError::Bind, got {other:?}"),
    }
}
