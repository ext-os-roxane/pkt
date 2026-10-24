use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, Args};

use libextos::caps::CapabilityIndex;
use libextos::cas::CasRepository;
use libextos::extract::ArchiveKind;
use libextos::ingest;
use libextos::rosetta::registry::RosettaRegistry;
use libextos::types::HashAlgorithm;

mod server;

/// pkt — ExtOS Package & Repository Engine (Pacman-style)
///
/// Manages the Content-Addressable Storage repository,
/// fetches and translates packages from upstream distributions,
/// and coordinates the P2P Swarm Network.
#[derive(Parser)]
#[command(name = "pkt", version, about, long_about = None)]
struct Cli {
    /// Path to the CAS repository root
    #[arg(long, default_value = "/repository", env = "EXTOS_REPOSITORY")]
    repository: PathBuf,

    /// Hash algorithm for CAS objects
    #[arg(long, default_value = "blake3")]
    hash_algo: String,

    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Synchronize packages (-S)
    #[command(name = "-S", alias = "sync")]
    Sync(SyncArgs),

    /// Query the package database (-Q)
    #[command(name = "-Q", alias = "query")]
    Query(QueryArgs),

    /// Remove package(s) from the system (-R)
    #[command(name = "-R", alias = "remove")]
    Remove(RemoveArgs),

    /// Upgrade or add package(s) from local files (-U)
    #[command(name = "-U", alias = "upgrade")]
    Upgrade(UpgradeArgs),

    /// Check the files database (-F); `--soname` queries the capability index
    #[command(name = "-F", alias = "files")]
    Files(FilesArgs),

    /// Modify the local package database (-D)
    #[command(name = "-D", alias = "database")]
    Database {
        /// Run garbage collection
        #[arg(short = 'g', long)]
        gc: bool,
    },

    // --- ExtOS Specialized Commands ---

    /// Repack a CAS object into a legacy format (.deb, .pkg.tar.zst, .apk)
    Repack {
        /// CAS hash of the object to repack
        hash: String,
        /// Target format
        #[arg(long)]
        format: String,
    },
    /// Publish local objects to the P2P Swarm
    Publish {
        /// Origin to publish
        origin: String,
    },
    /// Build a package from source inside a clean container
    Build {
        /// Path to build configuration
        config: String,
    },
    /// Verify integrity of CAS objects
    Verify {
        /// Optional: specific hash to verify (otherwise verify all)
        hash: Option<String>,
    },

    /// Serve the pkt control plane over a Unix domain socket (PLAN 8.1.3)
    Serve {
        /// Path to the gRPC control socket. Overrides `EXTOS_PKT_SOCKET`;
        /// defaults to the ARCHITECTURE §15 path (`server::DEFAULT_SOCKET`).
        #[arg(long, env = "EXTOS_PKT_SOCKET")]
        socket: Option<PathBuf>,
        /// Control-socket group override (PLAN 8.1.5). Defaults to the §15
        /// daemon group (`wheel`, from `libextos::daemons::DEFAULT_SOCKETS`);
        /// `none` (or an empty value) disables the chown entirely.
        #[arg(long)]
        group: Option<String>,
    },
}

#[derive(Args)]
struct SyncArgs {
    /// Download fresh package databases from the server (-y)
    #[arg(short = 'y', long)]
    refresh: bool,

    /// Search for packages matching strings (-s)
    #[arg(short = 's', long)]
    search: Option<String>,

    /// View package information (-i)
    #[arg(short = 'i', long)]
    info: bool,

    /// Download only, do not install (-w)
    #[arg(short = 'w', long)]
    downloadonly: bool,

    /// Upgrade all out-of-date packages (-u)
    #[arg(short = 'u', long)]
    sysupgrade: bool,

    /// Packages to install
    packages: Vec<String>,
}

#[derive(Args)]
struct QueryArgs {
    /// View package information (-i)
    #[arg(short = 'i', long)]
    info: bool,

    /// List all files owned by a package (-l)
    #[arg(short = 'l', long)   ]
    list: bool,

    /// Search locally-installed packages for matching strings (-s)
    #[arg(short = 's', long)]
    search: Option<String>,

    /// List every ref row (`origin/name version -> hash`), including all versions
    #[arg(long)]
    all_refs: bool,

    /// Packages to query
    packages: Vec<String>,
}

#[derive(Args)]
struct RemoveArgs {
    /// Remove dependencies not required by other packages (-s)
    #[arg(short = 's', long)]
    recursive: bool,

    /// Packages to remove
    packages: Vec<String>,
}

#[derive(Args)]
struct FilesArgs {
    /// File path or glob to search for in the CAS file database (-F).
    ///
    /// Matching rules live in [`libextos::cas::matches_query`]; a plain string is
    /// a case-sensitive substring, `/x` is anchored, `*`/`?` glob one segment.
    query: Option<String>,

    /// Query the SONAME capability index for providers instead (PLAN 5.2.4).
    ///
    /// Kept as an explicit flag because `-F <query>` is the Phase-2 file search
    /// (`src/cas.rs::search_files`); overloading the positional would silently
    /// change the meaning of existing invocations.
    #[arg(long, visible_alias = "providers")]
    soname: Option<String>,
}

#[derive(Args)]
struct UpgradeArgs {
    /// Origin namespace (default: auto-detect from archive type)
    #[arg(short = 'o', long)]
    origin: Option<String>,

    /// Paths to package files
    files: Vec<String>,
}

/// Origin assumed for a bare package name (`pkt -S htop=3.3.0-1`).
const DEFAULT_SYNC_ORIGIN: &str = "archlinux";

fn parse_hash_algo(s: &str) -> HashAlgorithm {
    match s {
        "sha256" | "SHA256" => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Blake3,
    }
}

/// Abbreviate a CAS hash for terminal display (never panics on short input).
fn short_hash(hash: &str) -> &str {
    let end = std::cmp::min(20, hash.len());
    &hash[..end]
}

/// Parse a `-S` package spec: `[origin/]name[=version]`.
///
/// A bare name is attributed to [`DEFAULT_SYNC_ORIGIN`]. The version is
/// mandatory because mirror index resolution does not exist yet — the download
/// URL is derived from `<name>-<version>` (see `ingest::package_filename`).
fn parse_sync_spec(spec: &str) -> anyhow::Result<(String, String, String)> {
    let (locator, version) = match spec.split_once('=') {
        Some((locator, version)) => (locator.trim(), Some(version.trim())),
        None => (spec.trim(), None),
    };

    let (origin, name) = match locator.split_once('/') {
        Some((origin, name)) => {
            if origin.is_empty() || name.is_empty() || name.contains('/') {
                anyhow::bail!(
                    "invalid package spec '{spec}': expected `[origin/]name[=version]`"
                );
            }
            (origin.to_string(), name.to_string())
        }
        None => {
            if locator.is_empty() {
                anyhow::bail!("invalid package spec '{spec}': package name is empty");
            }
            (DEFAULT_SYNC_ORIGIN.to_string(), locator.to_string())
        }
    };

    let version = version.filter(|v| !v.is_empty()).ok_or_else(|| {
        anyhow::anyhow!(
            "package '{origin}/{name}' needs an explicit version, e.g. \
             `{origin}/{name}=1.2.3-1` (mirror index resolution is not implemented)"
        )
    })?;

    Ok((origin, name, version.to_string()))
}

/// Download one package from its configured mirrors, then ingest it into the CAS.
///
/// With `download_only` the archive is left in `<repository>/cache/` and the
/// ingest/commit steps are skipped (pacman's `-S -w`).
fn sync_one_package(
    repo: &CasRepository,
    cache_dir: &Path,
    spec: &str,
    rosetta: &RosettaRegistry,
    download_only: bool,
) -> anyhow::Result<()> {
    let (origin, name, version) = parse_sync_spec(spec)?;

    let archive = ingest::download_from_mirror_to(&origin, &name, &version, cache_dir)
        .map_err(|err| {
            anyhow::anyhow!(
                "cannot fetch {origin}/{name} {version}: {err}\n\
                 hint: set {} to one or more comma-separated mirror base URLs",
                ingest::mirror_env_var(&origin)
            )
        })?;

    let bytes = std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    println!("↓ {} ({} bytes)", archive.display(), bytes);

    if download_only {
        return Ok(());
    }

    let result =
        ingest::ingest_local_archive_with_rosetta(repo, &archive, &origin, Some(rosetta))?;
    let tag = if result.rosetta_translated {
        " [rosetta]"
    } else {
        ""
    };
    println!(
        "✓ {}/{} {} → {}{}",
        result.origin,
        result.name,
        result.version,
        short_hash(&result.hash),
        tag
    );
    print_capabilities(&result.capabilities);
    Ok(())
}

/// Print the auto-discovered ELF capabilities of an ingested package.
fn print_capabilities(capabilities: &libextos::manifest::Capabilities) {
    if !capabilities.binaries.is_empty() {
        println!("  binaries: {}", capabilities.binaries.join(", "));
    }
    if !capabilities.libraries.is_empty() {
        println!("  libraries: {}", capabilities.libraries.join(", "));
    }
}

/// Plain synchronous entry point.
///
/// The download/ingest stack is built on `reqwest::blocking` (see
/// `libextos::ingest`). Running it from inside a Tokio runtime panics with
/// "Cannot drop a runtime in a context where blocking is not allowed", so `pkt`
/// must NOT install an async runtime here.
///
/// The one sanctioned exception is `pkt serve` (PLAN 8.1.3, `mod server`): it
/// builds its own explicit multi-thread Tokio runtime and bridges every
/// blocking domain call through `tokio::task::spawn_blocking`, whose worker
/// threads permit blocking drops — the CLI's sync main is otherwise unchanged.
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let algo = parse_hash_algo(&cli.hash_algo);

    // Initialize Rosetta plugin registry (M4)
    let rosetta = RosettaRegistry::discover();
    if rosetta.plugin_count() > 0 {
        tracing::info!(
            "Rosetta: {} plugin(s) loaded [{}]",
            rosetta.plugin_count(),
            rosetta.list_origins().join(", ")
        );
    }

    match cli.operation {
        Operation::Sync(args) => {
            if args.refresh {
                tracing::info!("Syncing databases...");
                // TODO(M3.6): Pull upstream Tier 2 databases
            }
            if let Some(query) = args.search {
                tracing::info!("Searching for: {}", query);
                let repo = CasRepository::open(&cli.repository, algo)?;
                // Search across all origins
                let origins = repo.list_origins()?;
                let mut found = false;
                for origin in &origins {
                    let pkgs = repo.list_packages(origin)?;
                    for pkg in &pkgs {
                        if pkg.contains(&query) {
                            let versions = repo.list_versions(origin, pkg)?;
                            println!("{}/{} [{}]", origin, pkg, versions.join(", "));
                            found = true;
                        }
                    }
                }
                if !found {
                    println!("No packages found matching '{}'", query);
                }
            } else if args.info {
                let repo = CasRepository::open(&cli.repository, algo)?;
                for pkg_name in &args.packages {
                    // Try to find the package across origins
                    let origins = repo.list_origins()?;
                    for origin in &origins {
                        if let Ok(hash) = repo.resolve_ref(origin, pkg_name, "current") {
                            let versions = repo.list_versions(origin, pkg_name)?;
                            println!("Name        : {}", pkg_name);
                            println!("Origin      : {}", origin);
                            println!("Hash        : {}", hash);
                            println!("Versions    : {}", versions.join(", "));
                            if let Ok(manifest) = repo.read_manifest(&hash) {
                                println!("Manifest    :\n{}", manifest);
                            }
                            println!();
                        }
                    }
                }
            } else if !args.packages.is_empty() {
                let repo = CasRepository::open(&cli.repository, algo)?;
                let cache_dir = repo.root.join("cache");
                tracing::info!("Installing: {:?}", args.packages);
                let mut failures = 0usize;
                for spec in &args.packages {
                    if let Err(err) =
                        sync_one_package(&repo, &cache_dir, spec, &rosetta, args.downloadonly)
                    {
                        eprintln!("error: {err}");
                        failures += 1;
                    }
                }
                if failures > 0 {
                    anyhow::bail!("{failures} package(s) failed to sync");
                }
            }
            Ok(())
        }
        Operation::Query(args) => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            if args.all_refs {
                let rows = repo.list_refs()?;
                if rows.is_empty() {
                    println!("No refs in repository.");
                }
                for row in rows {
                    match repo.resolve_ref(&row.origin, &row.name, &row.version) {
                        Ok(hash) => println!("{} → {}", row.label(), short_hash(&hash)),
                        Err(_) => println!("{} → (dangling)", row.label()),
                    }
                }
            } else if args.packages.is_empty() {
                // List all installed packages
                let origins = repo.list_origins()?;
                for origin in &origins {
                    if origin == "virtual" {
                        continue;
                    }
                    let pkgs = repo.list_packages(origin)?;
                    for pkg in &pkgs {
                        if let Ok(hash) = repo.resolve_ref(origin, &pkg, "current") {
                            let versions = repo.list_versions(origin, &pkg)?;
                            let current = versions.last().cloned().unwrap_or_default();
                            println!("{}/{} {} [{}]", origin, pkg, current, short_hash(&hash));
                        }
                    }
                }
            } else {
                for pkg_name in &args.packages {
                    let origins = repo.list_origins()?;
                    let mut found = false;
                    for origin in &origins {
                        if let Ok(hash) = repo.resolve_ref(origin, pkg_name, "current") {
                            found = true;
                            if args.info {
                                println!("Name        : {}", pkg_name);
                                println!("Origin      : {}", origin);
                                println!("Hash        : {}", hash);
                                if let Ok(manifest) = repo.read_manifest(&hash) {
                                    println!("{}", manifest);
                                }
                            } else if args.list {
                                let content_dir = repo.retrieve(&hash)?;
                                list_files_recursive(&content_dir, &content_dir)?;
                            } else {
                                let versions = repo.list_versions(origin, pkg_name)?;
                                println!("{}/{} {}", origin, pkg_name, versions.join(", "));
                            }
                        }
                    }
                    if !found {
                        eprintln!("error: package '{}' was not found", pkg_name);
                    }
                }
            }
            Ok(())
        }
        Operation::Remove(args) => {
            if args.packages.is_empty() {
                anyhow::bail!(
                    "no packages specified (usage: pkt -R <package> [<package>...])"
                );
            }
            let repo = CasRepository::open(&cli.repository, algo)?;
            // Snapshot the ref table once: removal must be driven by the refs
            // listing, not by directory guesses (PLAN 2.2.3).
            let rows = repo.list_refs()?;
            let mut missing: Vec<&str> = Vec::new();
            let mut removed_total = 0usize;

            for spec in &args.packages {
                let (origin_filter, name) = match spec.split_once('/') {
                    Some((origin, name)) if !origin.is_empty() && !name.is_empty() => {
                        (Some(origin), name)
                    }
                    _ => (None, spec.as_str()),
                };

                // Every (origin, name) pair the ref table knows for this spec.
                let mut targets: Vec<(String, String)> = Vec::new();
                for row in &rows {
                    if row.name != name {
                        continue;
                    }
                    if origin_filter.is_some_and(|origin| origin != row.origin) {
                        continue;
                    }
                    let pair = (row.origin.clone(), row.name.clone());
                    if !targets.contains(&pair) {
                        targets.push(pair);
                    }
                }

                if targets.is_empty() {
                    eprintln!("error: package '{spec}' was not found");
                    missing.push(spec);
                    continue;
                }

                for (origin, pkg) in targets {
                    tracing::info!("Removing: {}/{}", origin, pkg);
                    let versions = repo.list_versions(&origin, &pkg)?;
                    for version in &versions {
                        println!("Removed {}/{}/{}", origin, pkg, version);
                    }
                    // Drop the whole ref directory: all versions plus `current`.
                    let ref_dir = repo.root.join("refs").join(&origin).join(&pkg);
                    std::fs::remove_dir_all(&ref_dir)?;
                    println!(
                        "{}/{}: removed {} version(s)",
                        origin,
                        pkg,
                        versions.len()
                    );
                    removed_total += versions.len();
                }
            }

            if args.recursive {
                tracing::info!("Running GC to remove orphaned objects...");
                let purged = repo.garbage_collect()?;
                if !purged.is_empty() {
                    println!("GC: purged {} orphaned objects", purged.len());
                }
            }

            if !missing.is_empty() {
                anyhow::bail!(
                    "{} package(s) not found: {}",
                    missing.len(),
                    missing.join(", ")
                );
            }
            tracing::info!("Removed {} version ref(s) in total", removed_total);
            Ok(())
        }
        Operation::Upgrade(args) => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            for file_path in &args.files {
                let path = Path::new(file_path);
                if !path.exists() {
                    eprintln!("error: file not found: {}", file_path);
                    continue;
                }

                let kind = ArchiveKind::detect(path);
                let is_native = kind == Some(ArchiveKind::PktTarXz);

                if is_native {
                    // Native ExtOS package — trust embedded manifest
                    tracing::info!("Ingesting native package: {}", file_path);
                    let result = ingest::ingest_native_package(&repo, path)?;
                    println!(
                        "✓ {}/{} {} → {}",
                        result.origin,
                        result.name,
                        result.version,
                        short_hash(&result.hash)
                    );
                } else {
                    // Upstream package — use Rosetta plugin dispatch
                    let origin = args
                        .origin
                        .as_deref()
                        .unwrap_or_else(|| {
                            kind.map(ingest::default_origin_for_archive)
                                .unwrap_or("scratch")
                        });
                    tracing::info!("Ingesting {} package: {}", origin, file_path);
                    let result = ingest::ingest_local_archive_with_rosetta(
                        &repo, path, origin, Some(&rosetta),
                    )?;
                    let tag = if result.rosetta_translated { " [rosetta]" } else { "" };
                    println!(
                        "✓ {}/{} {} → {}{}",
                        result.origin,
                        result.name,
                        result.version,
                        short_hash(&result.hash),
                        tag
                    );
                    print_capabilities(&result.capabilities);
                }
            }
            Ok(())
        }
        Operation::Files(args) => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            match (args.query.as_deref(), args.soname.as_deref()) {
                (None, None) => anyhow::bail!(
                    "no query specified (usage: pkt -F <file-query> | pkt -F --soname <soname>)"
                ),
                (Some(_), Some(_)) => anyhow::bail!(
                    "choose either a file query or --soname, not both \
                     (usage: pkt -F <file-query> | pkt -F --soname <soname>)"
                ),
                (None, Some(soname)) => print_capability_providers(&repo, soname)?,
                (Some(query), None) => {
                    tracing::info!("Searching for file: {}", query);
                    match repo.search_files(query) {
                        Ok(hits) => {
                            for hit in hits {
                                println!(
                                    "{}/{} {} {}",
                                    hit._ref.origin, hit._ref.name, hit._ref.version, hit.path
                                );
                            }
                        }
                        Err(err) => {
                            // Legacy fallback: the ref-driven scan could not read a
                            // content tree, so walk `current` trees directly. Bounded
                            // to this failure path — the normal route never scans.
                            tracing::warn!(
                                "CAS file scan failed ({err}); falling back to tree scan"
                            );
                            let origins = repo.list_origins()?;
                            for origin in &origins {
                                let pkgs = repo.list_packages(origin)?;
                                for pkg in &pkgs {
                                    if let Ok(hash) = repo.resolve_ref(origin, &pkg, "current") {
                                        let content_dir = repo.retrieve(&hash)?;
                                        if find_file_in_tree(&content_dir, query)? {
                                            println!(
                                                "{}/{} owns a file matching '{}'",
                                                origin, pkg, query
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        Operation::Database { gc } => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            if gc {
                tracing::info!("Running garbage collection...");
                let purged = repo.garbage_collect()?;
                if purged.is_empty() {
                    println!("No orphaned objects found.");
                } else {
                    println!("Purged {} objects:", purged.len());
                    for hash in &purged {
                        println!("  - {}", short_hash(hash));
                    }
                }
            }
            Ok(())
        }
        Operation::Repack { hash, format } => {
            tracing::info!("Repacking {} to {}", hash, format);
            todo!("M14.4: Repacker")
        }
        Operation::Publish { origin } => {
            tracing::info!("Publishing origin: {}", origin);
            todo!("M14: Swarm publish")
        }
        Operation::Build { config } => {
            tracing::info!("Building from: {}", config);
            todo!("M21.2: Builder")
        }
        Operation::Verify { hash } => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            match hash {
                Some(h) => {
                    let ok = repo.verify(&h)?;
                    if ok {
                        println!("✓ {} integrity verified", h);
                    } else {
                        eprintln!("✗ {} FAILED integrity check", h);
                        std::process::exit(1);
                    }
                }
                None => {
                    tracing::info!("Verifying all objects...");
                    let objects_dir = repo.root.join("objects");
                    if objects_dir.exists() {
                        let mut total = 0;
                        let mut passed = 0;
                        for entry in std::fs::read_dir(&objects_dir)? {
                            let entry = entry?;
                            let hash = entry.file_name().to_string_lossy().to_string();
                            total += 1;
                            if repo.verify(&hash)? {
                                passed += 1;
                            } else {
                                eprintln!("✗ {} FAILED", hash);
                            }
                        }
                        println!("{}/{} objects passed integrity check", passed, total);
                    }
                }
            }
            Ok(())
        }
        Operation::Serve { socket, group } => {
            let socket = socket.unwrap_or_else(|| PathBuf::from(server::DEFAULT_SOCKET));
            tracing::info!("Serving pkt control plane on {}", socket.display());
            match group.as_deref() {
                // The §15 default (`wheel`) applies when no flag was given.
                Some(flag) => {
                    server::serve_with_group(&cli.repository, algo, &socket, rosetta, Some(flag))?
                }
                None => server::serve(&cli.repository, algo, &socket, rosetta)?,
            };
            Ok(())
        }
    }
}

/// Print the providers of one SONAME from the CAS capability index (PLAN 5.2.4).
///
/// The whole repository is indexed on demand (PLAN 5.2.2) — no daemon, no cache,
/// no network. Rows the population had to skip are reported on stderr so a
/// short provider list is never mistaken for "nobody provides this". A miss
/// prints `no providers for <soname>` and exits 0, matching the quiet-miss
/// behaviour of the file search (`-F <query>`) and of `-Q --all-refs`; only a
/// malformed SONAME or an unreadable CAS is an error (exit 1).
fn print_capability_providers(repo: &CasRepository, soname: &str) -> anyhow::Result<()> {
    let populated = CapabilityIndex::populate(repo)?;
    for warning in &populated.summary.warnings {
        eprintln!("warning: skipped {warning}");
    }

    // `query` validates the SONAME (path separators, NUL, control characters)
    // before any lookup: a malformed key is a typed error, not an empty result.
    let providers = populated.index.query(soname)?;
    if providers.is_empty() {
        println!("no providers for {soname}");
        return Ok(());
    }

    println!("{soname}:");
    for provider in providers {
        match &provider.object {
            Some(hash) => println!(
                "  {} {} → {}",
                provider.label(),
                provider.version,
                short_hash(hash)
            ),
            None => println!("  {} {}", provider.label(), provider.version),
        }
    }
    println!("{} provider(s) for {}", providers.len(), soname);
    println!(
        "indexed {} SONAME(s) across {} ref(s) ({} warning(s))",
        populated.summary.sonames,
        populated.summary.refs_scanned,
        populated.summary.warnings.len()
    );
    Ok(())
}

/// Recursively list files in a directory tree.
fn list_files_recursive(base: &Path, dir: &Path) -> anyhow::Result<()> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                list_files_recursive(base, &path)?;
            } else {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                println!("/{}", rel.display());
            }
        }
    }
    Ok(())
}

/// Search for a filename pattern in a directory tree.
fn find_file_in_tree(dir: &Path, query: &str) -> anyhow::Result<bool> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(query) {
                return Ok(true);
            }
            if path.is_dir() && find_file_in_tree(&path, query)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
