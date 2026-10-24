//! `pkt` gRPC control-plane server (PLAN 8.1.3).
//!
//! Serves the generated `PktService` (schemas: PLAN 8.1.1, module
//! `libextos::pb`) over a Unix domain socket (ARCHITECTURE §15), mapping each
//! RPC onto the libextos domain APIs one-to-one:
//!
//! | RPC       | CLI surface          | libextos API                                                        |
//! |-----------|----------------------|---------------------------------------------------------------------|
//! | `Sync`    | `pkt -S`             | `ingest::download_from_mirror_to` + `ingest_local_archive_with_rosetta` |
//! | `Query`   | `pkt -Q --all-refs`  | `cas::CasRepository::list_refs` joined with `resolve_ref`            |
//! | `Files`   | `pkt -F <query>`     | `cas::CasRepository::search_files`                                   |
//! | `Soname`  | `pkt -F --soname`    | `caps::CapabilityIndex::populate` + `query`                          |
//! | `Ingest`  | `pkt -U`             | `ingest_local_archive_with_rosetta` / `ingest_native_package`        |
//!
//! # Runtime discipline (the sync main is preserved)
//!
//! `main` stays synchronous — the Phase-2 repair (`reqwest::blocking` panics
//! with "Cannot drop a runtime in a context where blocking is not allowed"
//! when run on runtime worker threads) must not regress. The `serve` command
//! is the single sanctioned exception: it builds an *explicit*
//! `tokio::runtime::Builder::new_multi_thread().enable_all()` runtime and
//! bridges every blocking domain call through `tokio::task::spawn_blocking`.
//! Blocking-pool worker threads permit blocking drops, so the mirror
//! download's `reqwest::blocking` stack is safe exactly there.
//!
//! # Error convention (pinned by the 8.1.1 schemas)
//!
//! gRPC status codes are transport-only (socket not listening, worker panic,
//! malformed wire data). A *domain* failure rides the response's
//! `error: Option<extos.common::Error>` field while gRPC reports OK; an unset
//! `error` field means success. `ExtosError` variants map 1:1 onto
//! `ErrorCode` via an exhaustive match with no catch-all arm — a future
//! variant breaks this build instead of silently mis-mapping.
//!
//! # Socket hygiene (PLAN 8.1.5 closed)
//!
//! The control socket is bound with mode [`SOCKET_MODE`] (0o660, §15) and
//! chowned to its §15 group through the shared libextos helper
//! (`libextos::socket`): the group defaults to `wheel` — the daemon's entry
//! in `libextos::daemons::DEFAULT_SOCKETS` — and an operator
//! `pkt serve --group <name>` overrides it (`--group none`/empty disables
//! the chown). Per the shared policy, an *explicit* flag failure is fatal
//! and typed ([`ServeError::SocketGroup`]); a *declarative default* the
//! host cannot honor (group absent, or EPERM for a non-member) degrades to
//! a logged honest skip — the mode and the serving are unaffected. A stale
//! or already-bound socket path is reported as a typed
//! [`ServeError::Bind`] to the operator; this server never unlinks a socket
//! it did not just create.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libextos::caps::{CapabilityIndex, CapabilityProvider};
use libextos::cas::{self, CasRepository};
use libextos::error::ExtosError;
use libextos::extract::ArchiveKind;
use libextos::ingest;
use libextos::manifest::Capabilities as DomainCapabilities;
use libextos::pb::extos::common::{Error as PbError, ErrorCode};
use libextos::pb::extos::pkt as pb;
use libextos::pb::extos::pkt::pkt_service_server::PktServiceServer;
use libextos::rosetta::registry::RosettaRegistry;
use libextos::socket::{self, ResolvedSocketGroup, SocketGroupError, SocketGroupOutcome};
use libextos::types::HashAlgorithm;

/// Design §15 control socket for `pkt`.
///
/// Kept in lockstep with `libextos::daemons::DEFAULT_SOCKETS` (pinned by a
/// unit test). Overridable per invocation via `pkt serve --socket` /
/// `EXTOS_PKT_SOCKET`; tests always use tmpdir sockets.
pub const DEFAULT_SOCKET: &str = "/run/extos/pkt.sock";

/// File mode applied to the bound control socket (ARCHITECTURE §15).
///
/// Owner + group read/write, no world access. The group itself (`wheel`)
/// rides the shared §15 wiring in `libextos::socket` (PLAN 8.1.5).
pub const SOCKET_MODE: u32 = 0o660;

/// Typed failure of the `pkt serve` path.
///
/// `main` surfaces these through `anyhow`'s `Error` rendering; every variant
/// names the offending path where one exists.
#[derive(Debug)]
pub enum ServeError {
    /// The CAS repository could not be opened or created.
    Repository {
        /// Repository root that failed to open.
        path: PathBuf,
        /// Underlying domain error.
        source: ExtosError,
    },
    /// The control socket could not be bound — already in use (live daemon or
    /// stale file), or the parent directory cannot be created.
    Bind {
        /// Socket path that failed to bind.
        path: PathBuf,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The §15 mode could not be applied to the bound socket.
    SocketMode {
        /// Socket path whose mode could not be set.
        path: PathBuf,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The §15 socket-group wiring failed fatally (PLAN 8.1.5): an explicit
    /// `--group` flag named an unresolvable group, or the chown failed with
    /// something other than the honest per-host EPERM skip. A declarative
    /// default that cannot be honored is *not* fatal — it degrades to a
    /// logged skip inside [`bind_control_socket_with_group`].
    SocketGroup {
        /// Socket path whose group could not be applied.
        path: PathBuf,
        /// The typed libextos socket-group error.
        source: SocketGroupError,
    },
    /// The explicit Tokio runtime could not be built.
    Runtime(io::Error),
    /// The serve loop terminated with a tonic transport error.
    Serve(tonic::transport::Error),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::Repository { path, source } => {
                write!(f, "cannot open CAS repository {}: {source}", path.display())
            }
            ServeError::Bind { path, source } => write!(
                f,
                "cannot bind control socket {}: {source} \
                 (another pkt serve may be listening; if no daemon is running, \
                 remove the stale socket file)",
                path.display()
            ),
            ServeError::SocketMode { path, source } => write!(
                f,
                "cannot apply mode {SOCKET_MODE:o} to control socket {}: {source}",
                path.display()
            ),
            ServeError::SocketGroup { path, source } => write!(
                f,
                "cannot apply the §15 socket group to control socket {}: {source}",
                path.display()
            ),
            ServeError::Runtime(source) => {
                write!(f, "cannot build the serve runtime: {source}")
            }
            ServeError::Serve(source) => write!(f, "serve loop failed: {source}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Repository { source, .. } => Some(source),
            ServeError::Bind { source, .. } => Some(source),
            ServeError::SocketMode { source, .. } => Some(source),
            ServeError::SocketGroup { source, .. } => Some(source),
            ServeError::Runtime(source) => Some(source),
            ServeError::Serve(source) => Some(source),
        }
    }
}

/// Run the `pkt serve` command (PLAN 8.1.3), applying the daemon's §15
/// socket group (`wheel`, PLAN 8.1.5) to the control socket.
///
/// Opens the CAS repository exactly like the existing CLI commands
/// (`--repository` / `EXTOS_REPOSITORY`), reuses the Rosetta registry the CLI
/// already discovered at startup, builds an explicit multi-thread Tokio
/// runtime (the sync `main` never installs one) and serves the generated
/// `PktService` on `socket` until the transport fails.
///
/// # Errors
///
/// [`ServeError`] names the failing stage: repository open, socket bind, §15
/// socket mode or group, runtime construction, or the serve loop itself.
pub fn serve(
    repo_root: &Path,
    algo: HashAlgorithm,
    socket: &Path,
    rosetta: RosettaRegistry,
) -> Result<(), ServeError> {
    let repo = CasRepository::open(repo_root, algo).map_err(|source| {
        ServeError::Repository { path: repo_root.to_path_buf(), source }
    })?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    rt.block_on(run(repo, Arc::new(rosetta), socket))
}

/// [`serve`] with an operator socket-group override (PLAN 8.1.5).
///
/// `group` is the `--group` value: `None` (flag absent) resolves to the
/// daemon's §15 default (`wheel`, from `libextos::daemons::DEFAULT_SOCKETS`),
/// `Some("none")`/`Some("")` disables the chown, anything else is an
/// explicit hard contract (failures are fatal and typed). See
/// [`ResolvedSocketGroup`] and `libextos::socket` for the shared policy both
/// servers run.
///
/// # Errors
///
/// [`ServeError`] as for [`serve`].
pub fn serve_with_group(
    repo_root: &Path,
    algo: HashAlgorithm,
    socket: &Path,
    rosetta: RosettaRegistry,
    group: Option<&str>,
) -> Result<(), ServeError> {
    let repo = CasRepository::open(repo_root, algo).map_err(|source| {
        ServeError::Repository { path: repo_root.to_path_buf(), source }
    })?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    let resolved = socket::resolve_socket_group("pkt", group);
    rt.block_on(run_with_group(repo, Arc::new(rosetta), socket, resolved))
}

/// Async serve loop: bind the control socket, apply the §15 mode and the
/// daemon's §15 group (PLAN 8.1.5) and serve the generated service over the
/// accepted UDS connections.
///
/// The incoming stream is tokio-stream's `UnixListenerStream`, reached
/// through tonic's own public re-export (`tonic::codegen::tokio_stream`) —
/// no additional dependency is needed for UDS serving.
pub async fn run(
    repo: CasRepository,
    rosetta: Arc<RosettaRegistry>,
    socket: &Path,
) -> Result<(), ServeError> {
    let std_listener = bind_control_socket(socket)?;
    serve_accepted(repo, rosetta, socket, std_listener).await
}

/// [`run`] with a pre-resolved socket-group request (PLAN 8.1.5).
pub async fn run_with_group(
    repo: CasRepository,
    rosetta: Arc<RosettaRegistry>,
    socket: &Path,
    resolved_group: ResolvedSocketGroup,
) -> Result<(), ServeError> {
    let std_listener = bind_control_socket_with_group(socket, &resolved_group)?;
    serve_accepted(repo, rosetta, socket, std_listener).await
}

/// Serve the generated service over an already-bound (non-blocking) control
/// socket: the shared accept loop of [`run`]/[`run_with_group`].
async fn serve_accepted(
    repo: CasRepository,
    rosetta: Arc<RosettaRegistry>,
    socket: &Path,
    std_listener: std::os::unix::net::UnixListener,
) -> Result<(), ServeError> {
    // Register the bound socket with this runtime's IO driver (must happen
    // inside the runtime context; the listener is already non-blocking).
    let listener = tokio::net::UnixListener::from_std(std_listener).map_err(|source| {
        ServeError::Bind { path: socket.to_path_buf(), source }
    })?;
    let incoming =
        tonic::codegen::tokio_stream::wrappers::UnixListenerStream::new(listener);
    let service = PktServiceServer::new(PktServiceImpl { repo, rosetta });
    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming)
        .await
        .map_err(ServeError::Serve)
}

/// Bind `socket` as the control socket, apply the design §15 mode and the
/// daemon's §15 group (`wheel`, PLAN 8.1.5).
///
/// See [`bind_control_socket_with_group`] for the full contract; this
/// convenience keeps the pre-8.1.5 signature and applies the daemon default.
///
/// # Errors
///
/// [`ServeError::Bind`] for parent-directory creation, bind, or non-blocking
/// failures; [`ServeError::SocketMode`] when the chmod fails after a
/// successful bind; [`ServeError::SocketGroup`] per the shared policy.
pub fn bind_control_socket(
    socket: &Path,
) -> Result<std::os::unix::net::UnixListener, ServeError> {
    bind_control_socket_with_group(socket, &socket::resolve_socket_group("pkt", None))
}

/// [`bind_control_socket`] with a pre-resolved socket-group request
/// (PLAN 8.1.5).
///
/// The parent directory is created when missing (`/run/extos` is not
/// guaranteed to exist for a bare `pkt serve`). An already-bound or stale
/// socket path surfaces as [`ServeError::Bind`] with the OS error — deciding
/// whether that is a live daemon or a leftover belongs to the operator, so
/// this function never unlinks anything.
///
/// The returned listener is a std socket in non-blocking mode; the async
/// caller registers it with its runtime's IO driver via
/// `tokio::net::UnixListener::from_std`.
///
/// The mode ([`SOCKET_MODE`]) is always applied. The group rides the shared
/// `libextos::socket` policy: [`ResolvedSocketGroup::Disabled`] skips the
/// chown, an [`ResolvedSocketGroup::Explicit`] failure is fatal and typed,
/// and a [`ResolvedSocketGroup::Default`] the host cannot honor (group
/// absent, or EPERM for a non-member) degrades to a logged honest skip —
/// never silent, never fatal for the declarative default.
///
/// # Errors
///
/// [`ServeError::Bind`] for parent-directory creation, bind, or non-blocking
/// failures; [`ServeError::SocketMode`] when the chmod fails after a
/// successful bind; [`ServeError::SocketGroup`] per the shared policy above.
pub fn bind_control_socket_with_group(
    socket: &Path,
    resolved_group: &ResolvedSocketGroup,
) -> Result<std::os::unix::net::UnixListener, ServeError> {
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ServeError::Bind {
                path: socket.to_path_buf(),
                source,
            })?;
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(socket).map_err(|source| {
        ServeError::Bind { path: socket.to_path_buf(), source }
    })?;
    listener.set_nonblocking(true).map_err(|source| ServeError::Bind {
        path: socket.to_path_buf(),
        source,
    })?;
    fs::set_permissions(socket, fs::Permissions::from_mode(SOCKET_MODE)).map_err(
        |source| ServeError::SocketMode { path: socket.to_path_buf(), source },
    )?;
    match socket::enforce_socket_group(socket, resolved_group) {
        Ok(outcome) => match outcome {
            SocketGroupOutcome::Applied { gid, group } => {
                tracing::info!(
                    "control socket {}: §15 group {group:?} applied (gid {gid})",
                    socket.display()
                );
            }
            SocketGroupOutcome::Skipped { group, reason } => {
                tracing::warn!(
                    "control socket {}: §15 group {group:?} not applied (honest per-host \
                     skip): {reason}",
                    socket.display()
                );
            }
            SocketGroupOutcome::Disabled => {
                tracing::info!(
                    "control socket {}: socket-group wiring disabled by operator flag",
                    socket.display()
                );
            }
        },
        Err(source) => {
            return Err(ServeError::SocketGroup { path: socket.to_path_buf(), source });
        }
    }
    Ok(listener)
}

/// The `PktService` implementation state (PLAN 8.1.3): one open CAS repository
/// plus the Rosetta registry the CLI discovered at startup.
///
/// Cloning is cheap: the repository is two small fields, and the registry is
/// shared through an `Arc` because plugin instances are reference-counted
/// `Send + Sync` objects.
#[derive(Clone)]
pub struct PktServiceImpl {
    /// The CAS repository this server manages (opened once at startup).
    repo: CasRepository,
    /// Rosetta registry used by `Sync`/`Ingest` metadata translation.
    rosetta: Arc<RosettaRegistry>,
}

#[tonic::async_trait]
impl pb::pkt_service_server::PktService for PktServiceImpl {
    async fn sync(
        &self,
        request: tonic::Request<pb::SyncRequest>,
    ) -> Result<tonic::Response<pb::SyncResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("sync", move || svc.sync_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn query(
        &self,
        request: tonic::Request<pb::QueryRequest>,
    ) -> Result<tonic::Response<pb::QueryResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("query", move || svc.query_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn files(
        &self,
        request: tonic::Request<pb::FilesRequest>,
    ) -> Result<tonic::Response<pb::FilesResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("files", move || svc.files_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn soname(
        &self,
        request: tonic::Request<pb::SonameRequest>,
    ) -> Result<tonic::Response<pb::SonameResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("soname", move || svc.soname_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn ingest(
        &self,
        request: tonic::Request<pb::IngestRequest>,
    ) -> Result<tonic::Response<pb::IngestResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("ingest", move || svc.ingest_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }
}

/// Bridge one blocking domain operation onto the async runtime.
///
/// Every RPC handler routes its domain call through here: the libextos APIs
/// are synchronous (blocking fs/network work), so they must run on the
/// blocking pool, not on runtime worker threads.
///
/// A `JoinError` (panicking worker) is *not* a domain error — it is a server
/// bug surfacing on the transport, so it maps to `Status::internal` per the
/// schema's convention that gRPC statuses are transport-only.
///
/// # Errors
///
/// [`tonic::Status::internal`] when the blocking worker panicked or was
/// cancelled.
async fn spawn_blocking<T, F>(rpc: &str, task: F) -> Result<T, tonic::Status>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let rpc = rpc.to_string();
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| tonic::Status::internal(format!("{rpc} worker failed: {err}")))
}

impl PktServiceImpl {
    /// `Sync` domain path (blocking): mirror download, then ingest unless
    /// `download_only` (pacman's `-S -w`).
    ///
    /// On ingest failure the download fields stay filled (best-effort payload
    /// per the schema header) and the domain error rides in `error`.
    fn sync_blocking(&self, req: pb::SyncRequest) -> pb::SyncResponse {
        let mut resp = pb::SyncResponse::default();
        if req.origin.is_empty() || req.name.is_empty() || req.version.is_empty() {
            resp.error = Some(domain_error(&config_parse_error(
                "extos.pkt.SyncRequest",
                "origin, name and version must all be non-empty \
                 (mirror index resolution does not exist)",
            )));
            return resp;
        }

        let cache_dir = self.repo.root.join("cache");
        let archive = match ingest::download_from_mirror_to(
            &req.origin,
            &req.name,
            &req.version,
            &cache_dir,
        ) {
            Ok(archive) => archive,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        // The CLI prints the same pair; a metadata failure renders as 0 there too.
        resp.archive_path = archive.display().to_string();
        resp.archive_bytes = fs::metadata(&archive).map(|meta| meta.len()).unwrap_or(0);

        if req.download_only {
            // Download-only: the ingest half of the response stays unset
            // (proto3 defaults), matching the schema's `pkt -S -w` semantics.
            return resp;
        }

        match ingest::ingest_local_archive_with_rosetta(
            &self.repo,
            &archive,
            &req.origin,
            Some(self.rosetta.as_ref()),
        ) {
            Ok(result) => fill_sync_from_ingest(&mut resp, &result),
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// `Query` domain path (blocking): the ref table joined with the resolved
    /// object hash, optionally filtered by origin.
    ///
    /// A dangling ref keeps its row with `object_hash` unset — the `(dangling)`
    /// rendering of `pkt -Q --all-refs`.
    fn query_blocking(&self, req: pb::QueryRequest) -> pb::QueryResponse {
        let mut resp = pb::QueryResponse::default();
        // Absent = all origins; the empty string is not a valid origin
        // (explicit-presence convention of the schema) — a typed domain error,
        // never a silent "match nothing".
        if req.origin.as_deref().is_some_and(str::is_empty) {
            resp.error = Some(domain_error(&config_parse_error(
                "extos.pkt.QueryRequest.origin",
                "the origin filter must not be empty (absent = all origins)",
            )));
            return resp;
        }
        let rows = match self.repo.list_refs() {
            Ok(rows) => rows,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        for row in rows {
            if let Some(filter) = req.origin.as_deref() {
                if row.origin != filter {
                    continue;
                }
            }
            let object_hash = self
                .repo
                .resolve_ref(&row.origin, &row.name, &row.version)
                .ok();
            resp.refs.push(ref_entry_to_proto(&row, object_hash));
        }
        resp
    }

    /// `Files` domain path (blocking): `cas::search_files` over the CAS file
    /// database (the positional `-F` arm; `--soname` is the `Soname` RPC).
    fn files_blocking(&self, req: pb::FilesRequest) -> pb::FilesResponse {
        let mut resp = pb::FilesResponse::default();
        match self.repo.search_files(&req.path_query) {
            // An empty query is a quiet miss in `search_files` (no hits), the
            // same contract the CLI inherits.
            Ok(hits) => resp.hits = hits.iter().map(file_hit_to_proto).collect(),
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// `Soname` domain path (blocking): populate the capability index, report
    /// the population summary (warnings included — never silently lossy) and
    /// answer the lookup.
    fn soname_blocking(&self, req: pb::SonameRequest) -> pb::SonameResponse {
        let mut resp = pb::SonameResponse::default();
        let populated = match CapabilityIndex::populate(&self.repo) {
            Ok(populated) => populated,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        resp.refs_scanned = populated.summary.refs_scanned as u64;
        resp.packages_indexed = populated.summary.packages as u64;
        resp.entries = populated.summary.entries as u64;
        resp.sonames_indexed = populated.summary.sonames as u64;
        resp.warnings = populated
            .summary
            .warnings
            .iter()
            .map(ToString::to_string)
            .collect();
        match populated.index.query(&req.soname) {
            Ok(providers) => {
                resp.providers = providers.iter().map(provider_to_proto).collect();
            }
            // A malformed key is a CONFIG_PARSE domain error, not an empty
            // provider list (pinned by the 8.1.1 schema docs).
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// `Ingest` domain path (blocking): the `pkt -U` pipeline.
    ///
    /// Explicit origin beats the format auto-detection table; an unknown
    /// format falls back to `scratch`, exactly like the CLI. Native
    /// `.pkt.tar.xz` archives always delegate to `ingest_native_package`
    /// inside the pipeline (the embedded manifest is authoritative).
    fn ingest_blocking(&self, req: pb::IngestRequest) -> pb::IngestResponse {
        let archive = PathBuf::from(&req.archive_path);
        let kind = ArchiveKind::detect(&archive);
        let rosetta = req.rosetta.then_some(self.rosetta.as_ref());
        let result = match req.origin.as_deref() {
            Some(origin) => {
                ingest::ingest_local_archive_with_rosetta(&self.repo, &archive, origin, rosetta)
            }
            None => {
                let origin = kind
                    .map(ingest::default_origin_for_archive)
                    .unwrap_or("scratch");
                ingest::ingest_local_archive_with_rosetta(&self.repo, &archive, origin, rosetta)
            }
        };
        match result {
            Ok(result) => ingest_result_to_response(&result),
            Err(err) => {
                let mut resp = pb::IngestResponse::default();
                resp.error = Some(domain_error(&err));
                resp
            }
        }
    }
}

// ─── Domain ↔ proto conversions ─────────────────────────────────────────────

/// Map an `ExtosError` onto the wire error.
///
/// The match is exhaustive with no catch-all arm: a future `ExtosError`
/// variant breaks this build instead of silently mis-mapping (the `ErrorCode`
/// enum mirrors the variants one-to-one by design). The message carries the
/// error's `Display` rendering, payload fields included.
fn domain_error(err: &ExtosError) -> PbError {
    let code = match err {
        ExtosError::Io(_) => ErrorCode::Io,
        ExtosError::ConfigParse { .. } => ErrorCode::ConfigParse,
        ExtosError::CasIntegrity { .. } => ErrorCode::CasIntegrity,
        ExtosError::PackageNotFound { .. } => ErrorCode::PackageNotFound,
        ExtosError::DependencyUnresolvable(_) => ErrorCode::DependencyUnresolvable,
        ExtosError::Collision { .. } => ErrorCode::Collision,
        ExtosError::Weave(_) => ErrorCode::Weave,
        ExtosError::Snapshot(_) => ErrorCode::Snapshot,
        ExtosError::Container(_) => ErrorCode::Container,
        ExtosError::RosettaPlugin { .. } => ErrorCode::RosettaPlugin,
        ExtosError::Serialization(_) => ErrorCode::Serialization,
    };
    PbError { code: code as i32, message: err.to_string() }
}

/// Build the crate's structured malformed-input error (same house style as
/// `caps::validate_soname`: `ConfigParse` with a naming `path`, `line = 0`).
fn config_parse_error(path: &str, message: impl Into<String>) -> ExtosError {
    ExtosError::ConfigParse {
        path: path.to_string(),
        line: 0,
        message: message.into(),
    }
}

/// Domain ref row + resolved object hash → wire `RefEntry`.
///
/// `object_hash` stays `None` for a dangling ref (explicit presence: the wire
/// distinguishes "unresolved" from the empty string).
fn ref_entry_to_proto(entry: &cas::RefEntry, object_hash: Option<String>) -> pb::RefEntry {
    pb::RefEntry {
        origin: entry.origin.clone(),
        name: entry.name.clone(),
        version: entry.version.clone(),
        object_hash,
    }
}

/// Reverse of `ref_entry_to_proto`, for the round-trip tests only — no
/// handler reconstructs a domain ref from the wire today.
#[cfg(test)]
fn ref_entry_from_proto(msg: &pb::RefEntry) -> cas::RefEntry {
    cas::RefEntry {
        origin: msg.origin.clone(),
        name: msg.name.clone(),
        version: msg.version.clone(),
    }
}

/// Domain capability set → wire `Capabilities` (list order preserved).
fn capabilities_to_proto(caps: &DomainCapabilities) -> pb::Capabilities {
    pb::Capabilities {
        binaries: caps.binaries.clone(),
        libraries: caps.libraries.clone(),
        virtual_caps: caps.virtual_caps.clone(),
        resources: caps.resources.clone(),
    }
}

/// Reverse of `capabilities_to_proto`, for the round-trip tests only.
#[cfg(test)]
fn capabilities_from_proto(msg: &pb::Capabilities) -> DomainCapabilities {
    DomainCapabilities {
        binaries: msg.binaries.clone(),
        libraries: msg.libraries.clone(),
        virtual_caps: msg.virtual_caps.clone(),
        resources: msg.resources.clone(),
    }
}

/// Capability provider → wire `SonameProvider` (best-first order preserved).
fn provider_to_proto(provider: &CapabilityProvider) -> pb::SonameProvider {
    pb::SonameProvider {
        origin: provider.origin.clone(),
        name: provider.name.clone(),
        version: provider.version.clone(),
        ref_version: provider.ref_version.clone(),
        object_hash: provider.object.clone(),
        provides: provider.provides.clone(),
    }
}

/// Reverse of `provider_to_proto`, for the round-trip tests only.
#[cfg(test)]
fn provider_from_proto(msg: &pb::SonameProvider) -> CapabilityProvider {
    CapabilityProvider {
        origin: msg.origin.clone(),
        name: msg.name.clone(),
        version: msg.version.clone(),
        ref_version: msg.ref_version.clone(),
        object: msg.object_hash.clone(),
        provides: msg.provides.clone(),
    }
}

/// Domain file hit → wire `FileHit`.
///
/// The file-search path does not resolve objects (CLI parity: `pkt -F` prints
/// ref + path only), so the embedded ref's `object_hash` stays unset.
fn file_hit_to_proto(hit: &cas::FileHit) -> pb::FileHit {
    pb::FileHit {
        ref_entry: Some(ref_entry_to_proto(&hit._ref, None)),
        path: hit.path.clone(),
    }
}

/// Fill the ingest half of a `SyncResponse` from an `IngestResult`.
fn fill_sync_from_ingest(resp: &mut pb::SyncResponse, result: &ingest::IngestResult) {
    resp.hash = result.hash.clone();
    resp.origin = result.origin.clone();
    resp.name = result.name.clone();
    resp.version = result.version.clone();
    resp.capabilities = Some(capabilities_to_proto(&result.capabilities));
    resp.rosetta_translated = result.rosetta_translated;
    resp.sanitized_bits = result.sanitized_bits as u64;
}

/// `IngestResult` → wire `IngestResponse` (flat mirror of the schema).
fn ingest_result_to_response(result: &ingest::IngestResult) -> pb::IngestResponse {
    pb::IngestResponse {
        hash: result.hash.clone(),
        origin: result.origin.clone(),
        name: result.name.clone(),
        version: result.version.clone(),
        capabilities: Some(capabilities_to_proto(&result.capabilities)),
        rosetta_translated: result.rosetta_translated,
        sanitized_bits: result.sanitized_bits as u64,
        error: None,
    }
}

// ─── In-module tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Open a throwaway CAS repository in a tmpdir.
    fn tmp_repo() -> (tempfile::TempDir, CasRepository) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let repo =
            CasRepository::open(dir.path().join("repository"), HashAlgorithm::Blake3)
                .expect("open tmpdir CAS");
        (dir, repo)
    }

    /// Server under test with an empty tmpdir repository.
    fn test_service() -> (tempfile::TempDir, PktServiceImpl) {
        let (dir, repo) = tmp_repo();
        let svc = PktServiceImpl {
            repo,
            rosetta: Arc::new(RosettaRegistry::discover()),
        };
        (dir, svc)
    }

    /// Native `.pkt.tar.xz` fixture synthesized with `tar` (the
    /// `tests/ingest_local.rs` pattern — no binary blobs committed).
    fn native_fixture(dir: &Path, name: &str) -> PathBuf {
        let src = dir.join("fixture_src");
        fs::create_dir_all(src.join("metadata")).expect("metadata dir");
        fs::create_dir_all(src.join("content/usr/bin")).expect("content dir");
        fs::write(
            src.join("metadata/manifest.nix"),
            format!(
                r#"{{
  identity = {{
    origin = "scratch";
    name = "{name}";
    version = "1.2.3";
  }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "{name}" ]; }};
  requires = [];
}}"#
            ),
        )
        .expect("manifest");
        fs::write(src.join("content/usr/bin/sh"), "#!/bin/sh\necho hi\n")
            .expect("payload");
        let archive = dir.join(format!("{name}-1.2.3.pkt.tar.xz"));
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
        assert!(status.success(), "tar fixture failed");
        archive
    }

    #[test]
    fn default_socket_matches_daemons_table() {
        let pinned = libextos::daemons::DEFAULT_SOCKETS
            .iter()
            .find(|(daemon, _, _)| *daemon == "pkt")
            .map(|(_, path, _)| *path)
            .expect("daemons table pins the pkt control socket");
        assert_eq!(DEFAULT_SOCKET, pinned, "§15 socket constant drifted");
    }

    #[test]
    fn default_socket_group_matches_daemons_table() {
        // PLAN 8.1.5: the daemon's group source of truth is the §15 table.
        let pinned = libextos::daemons::DEFAULT_SOCKETS
            .iter()
            .find(|(daemon, _, _)| *daemon == "pkt")
            .map(|(_, _, group)| *group)
            .expect("daemons table pins the pkt control group");
        assert_eq!(libextos::socket::default_group("pkt"), Some(pinned));
        // The no-flag resolution carries that default into the server.
        assert_eq!(
            libextos::socket::resolve_socket_group("pkt", None),
            ResolvedSocketGroup::Default(pinned.to_string())
        );
    }

    #[test]
    fn bind_control_socket_applies_default_group_and_keeps_mode() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("grouped.sock");
        let _listener = bind_control_socket(&socket).expect("bind with default group");
        let meta = fs::metadata(&socket).expect("socket stat");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE, "§15 socket mode must survive 8.1.5");
        // The §15 default for pkt is `wheel`; this host's user is a member,
        // so the honest apply path runs for real. On a host where the group
        // is absent (or the user is not a member) the shared policy degrades
        // to a logged skip — bind_control_socket never fails for the
        // default, which this Ok(…) already pins.
        if let Ok(wheel_gid) = libextos::socket::group_gid("wheel") {
            if meta.gid() == wheel_gid {
                return; // applied for real
            }
        }
        println!("HONEST SKIP: default group not applied on this host (EPERM/absent)");
    }

    #[test]
    fn explicit_unknown_group_is_a_fatal_typed_serve_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("fatal.sock");
        let explicit = ResolvedSocketGroup::Explicit("extos-no-such-group-xyz".to_string());
        match bind_control_socket_with_group(&socket, &explicit) {
            Err(ServeError::SocketGroup { path, source }) => {
                assert_eq!(path, socket);
                assert!(matches!(
                    source,
                    libextos::socket::SocketGroupError::UnknownGroup { .. }
                ));
            }
            other => panic!("expected fatal SocketGroup, got {other:?}"),
        }
    }

    #[test]
    fn bind_control_socket_with_group_none_disables_the_chown() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("ungrouped.sock");
        // The chown-free baseline gid: a plain file created by this process.
        let baseline = dir.path().join("baseline");
        fs::write(&baseline, b"").expect("baseline file");
        let own_gid = fs::metadata(&baseline).expect("stat").gid();
        let _listener =
            bind_control_socket_with_group(&socket, &ResolvedSocketGroup::Disabled)
                .expect("bind with disabled group");
        let meta = fs::metadata(&socket).expect("socket stat");
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        assert_eq!(meta.gid(), own_gid, "--group none must leave the gid alone");
    }

    #[test]
    fn extos_error_maps_onto_distinct_codes_one_to_one() {
        let cases: Vec<(ExtosError, ErrorCode)> = vec![
            (ExtosError::Io(io::Error::other("boom")), ErrorCode::Io),
            (
                config_parse_error("cfg.nix", "bad"),
                ErrorCode::ConfigParse,
            ),
            (
                ExtosError::CasIntegrity { expected: "a".into(), actual: "b".into() },
                ErrorCode::CasIntegrity,
            ),
            (
                ExtosError::PackageNotFound {
                    origin: "o".into(),
                    name: "n".into(),
                    version: "v".into(),
                },
                ErrorCode::PackageNotFound,
            ),
            (
                ExtosError::DependencyUnresolvable("dep".into()),
                ErrorCode::DependencyUnresolvable,
            ),
            (
                ExtosError::Collision {
                    path: "/p".into(),
                    claimant_a: "a".into(),
                    claimant_b: "b".into(),
                },
                ErrorCode::Collision,
            ),
            (ExtosError::Weave("w".into()), ErrorCode::Weave),
            (ExtosError::Snapshot("s".into()), ErrorCode::Snapshot),
            (ExtosError::Container("c".into()), ErrorCode::Container),
            (
                ExtosError::RosettaPlugin { plugin: "p".into(), message: "m".into() },
                ErrorCode::RosettaPlugin,
            ),
            (ExtosError::Serialization("x".into()), ErrorCode::Serialization),
        ];
        // The exhaustive match in `domain_error` enforces completeness at
        // compile time; this pins the count and the 1:1 mapping at runtime.
        assert_eq!(
            cases.len(),
            11,
            "every ExtosError variant must appear exactly once"
        );
        let mut codes = Vec::new();
        for (err, expected) in &cases {
            let wire = domain_error(err);
            assert_eq!(wire.code, *expected as i32, "{err:?}");
            assert_eq!(wire.message, err.to_string(), "message = Display");
            codes.push(wire.code);
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 11, "codes must be pairwise distinct");
    }

    #[test]
    fn ref_entry_round_trips_with_object_hash_absence() {
        let entry = cas::RefEntry {
            origin: "archlinux".into(),
            name: "openssl".into(),
            version: "3.3.1".into(),
        };
        for object_hash in [None, Some(String::new()), Some("BLAKE3-deadbeef".into())] {
            let wire = ref_entry_to_proto(&entry, object_hash.clone());
            assert_eq!(
                wire.object_hash, object_hash,
                "absent vs empty object hash must be preserved"
            );
            assert_eq!(ref_entry_from_proto(&wire), entry);
        }
    }

    #[test]
    fn capabilities_round_trip_in_manifest_order() {
        let caps = DomainCapabilities {
            binaries: vec!["htop".into()],
            libraries: vec!["libssl.so.3".into(), "libcrypto.so.3".into()],
            virtual_caps: vec![],
            resources: vec!["/usr/share/applications/htop.desktop".into()],
        };
        let wire = capabilities_to_proto(&caps);
        // `manifest::Capabilities` carries no `PartialEq`; compare field-wise.
        let back = capabilities_from_proto(&wire);
        assert_eq!(back.binaries, caps.binaries);
        assert_eq!(back.libraries, caps.libraries);
        assert_eq!(back.virtual_caps, caps.virtual_caps);
        assert_eq!(back.resources, caps.resources, "order preserved");
    }

    #[test]
    fn provider_round_trips_with_optional_object() {
        let mut provider = CapabilityProvider::new(
            "scratch",
            "native-hello",
            "2.0.0",
            None,
            vec!["libc.so.6".into(), "libm.so.6".into()],
        )
        .with_ref_version("2.0.0-1");
        for object in [None, Some(String::from("BLAKE3-x"))] {
            provider.object = object.clone();
            let wire = provider_to_proto(&provider);
            assert_eq!(wire.object_hash, object, "absent vs empty preserved");
            assert_eq!(provider_from_proto(&wire), provider);
        }
    }

    #[test]
    fn file_hit_maps_ref_and_leading_slash_path() {
        let hit = cas::FileHit {
            _ref: cas::RefEntry {
                origin: "debian".into(),
                name: "libc6".into(),
                version: "2.39".into(),
            },
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
        };
        let wire = file_hit_to_proto(&hit);
        assert_eq!(wire.path, hit.path);
        assert_eq!(ref_entry_from_proto(wire.ref_entry.as_ref().unwrap()), hit._ref);
        // The file-search path does not resolve objects (CLI parity).
        assert_eq!(wire.ref_entry.unwrap().object_hash, None);
    }

    #[test]
    fn sync_rejects_incomplete_identity_as_config_parse() {
        let (_dir, svc) = test_service();
        let resp = svc.sync_blocking(pb::SyncRequest::default());
        let err = resp.error.expect("empty identity is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
        assert!(resp.archive_path.is_empty());
    }

    #[test]
    fn sync_download_only_reports_unconfigured_mirror_as_domain_error() {
        let (_dir, svc) = test_service();
        let resp = svc.sync_blocking(pb::SyncRequest {
            // An origin whose `EXTOS_MIRRORS_*` variable no test environment
            // configures — exercises the unconfigured-mirror domain error.
            origin: "extos-unconfigured-mirror-origin".into(),
            name: "absent-pkg".into(),
            version: "1.0".into(),
            download_only: true,
        });
        let err = resp.error.expect("unconfigured mirror is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
        assert!(resp.archive_path.is_empty(), "nothing was downloaded");
        // Download-only: the ingest half stays unset.
        assert!(resp.hash.is_empty());
        assert_eq!(resp.sanitized_bits, 0);
        assert!(resp.capabilities.is_none());
    }

    #[test]
    fn query_empty_repository_lists_nothing_and_validates_filter() {
        let (_dir, svc) = test_service();
        let resp = svc.query_blocking(pb::QueryRequest { origin: None });
        assert!(resp.error.is_none(), "an empty CAS is a success, not an error");
        assert!(resp.refs.is_empty());

        let resp = svc.query_blocking(pb::QueryRequest {
            origin: Some("scratch".into()),
        });
        assert!(resp.error.is_none());
        assert!(resp.refs.is_empty());

        let resp = svc.query_blocking(pb::QueryRequest {
            origin: Some(String::new()),
        });
        let err = resp.error.expect("empty origin filter is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
    }

    #[test]
    fn soname_malformed_key_is_config_parse_not_empty_list() {
        let (_dir, svc) = test_service();
        let resp = svc.soname_blocking(pb::SonameRequest { soname: "a/b".into() });
        let err = resp.error.expect("malformed SONAME is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
        assert!(resp.providers.is_empty());
        // Population summary still rides along (best-effort payload).
        assert_eq!(resp.refs_scanned, 0);
    }

    #[test]
    fn ingest_native_fixture_round_trips_through_query() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let repo = CasRepository::open(
            dir.path().join("repository"),
            HashAlgorithm::Blake3,
        )
        .expect("open tmpdir CAS");
        let svc = PktServiceImpl {
            repo,
            rosetta: Arc::new(RosettaRegistry::discover()),
        };
        let archive = native_fixture(dir.path(), "native-hello");
        let resp = svc.ingest_blocking(pb::IngestRequest {
            archive_path: archive.display().to_string(),
            origin: None,
            rosetta: false,
        });
        assert!(resp.error.is_none(), "{:?}", resp.error);
        assert_eq!(resp.origin, "scratch");
        assert_eq!(resp.name, "native-hello");
        assert_eq!(resp.version, "1.2.3");
        assert!(resp.hash.starts_with("BLAKE3-"), "{}", resp.hash);
        assert_eq!(resp.sanitized_bits, 0);
        assert!(!resp.rosetta_translated);

        let query = svc.query_blocking(pb::QueryRequest { origin: None });
        assert!(query.error.is_none());
        let row = query
            .refs
            .iter()
            .find(|r| r.name == "native-hello")
            .expect("ingested ref visible through Query");
        assert_eq!(row.object_hash.as_deref(), Some(resp.hash.as_str()));
    }

    #[test]
    fn bind_control_socket_applies_design_mode_and_rejects_rebind() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("pkt.sock");
        let _listener = bind_control_socket(&socket).expect("first bind");
        let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE, "§15 socket mode must be applied");
        assert!(
            matches!(bind_control_socket(&socket), Err(ServeError::Bind { .. })),
            "binding a taken socket is a typed error"
        );
    }

    /// Drive the real serve loop on a tmpdir socket with an explicit
    /// `--group wheel` (PLAN 8.1.5): the mode stays 0660, the typed
    /// apply/skip path runs without failing the serve, and the listener
    /// accepts a client.
    #[tokio::test(flavor = "multi_thread")]
    async fn serve_with_group_wheel_keeps_mode_and_serves() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let repo = CasRepository::open(dir.path().join("repository"), HashAlgorithm::Blake3)
            .expect("tmpdir CAS");
        let socket = dir.path().join("wheel.sock");
        let socket_path = socket.clone();
        let task = tokio::spawn(async move {
            run_with_group(
                repo,
                Arc::new(RosettaRegistry::discover()),
                &socket_path,
                socket::resolve_socket_group("pkt", Some("wheel")),
            )
            .await
        });

        // Bounded wait for the bound socket, then assert the §15 hygiene.
        let mut bound = false;
        for _ in 0..500 {
            if socket.exists() {
                bound = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(bound, "the control socket never appeared");

        let meta = fs::metadata(&socket).expect("socket stat");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SOCKET_MODE,
            "§15 socket mode must stay 0660 with --group wheel"
        );
        match libextos::socket::group_gid("wheel") {
            Ok(wheel_gid) if meta.gid() == wheel_gid => {
                println!("PROVEN --group wheel: socket gid == wheel gid ({wheel_gid})");
            }
            _ => println!(
                "HONEST SKIP: --group wheel degraded to the per-host skip (group absent \
                 or daemon user not a member); the serve kept running either way"
            ),
        }

        // The listener is live: a raw UDS client connects.
        let _client = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("client connect after group wiring");
        task.abort();
    }
}
