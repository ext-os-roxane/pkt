use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, Args};

use libextos::cas::CasRepository;
use libextos::extract::ArchiveKind;
use libextos::ingest;
use libextos::rosetta::registry::RosettaRegistry;
use libextos::types::HashAlgorithm;

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

    /// Check the files database (-F)
    #[command(name = "-F", alias = "files")]
    Files {
        /// Search for a file
        query: String,
    },

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
struct UpgradeArgs {
    /// Origin namespace (default: auto-detect from archive type)
    #[arg(short = 'o', long)]
    origin: Option<String>,

    /// Paths to package files
    files: Vec<String>,
}

fn parse_hash_algo(s: &str) -> HashAlgorithm {
    match s {
        "sha256" | "SHA256" => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Blake3,
    }
}

/// Auto-detect origin from archive kind.
fn detect_origin(kind: ArchiveKind) -> &'static str {
    match kind {
        ArchiveKind::PkgTarZst | ArchiveKind::PkgTarXz => "archlinux",
        ArchiveKind::Deb => "debian",
        ArchiveKind::Apk => "alpine",
        ArchiveKind::PktTarXz => "scratch",
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
                tracing::info!("Installing: {:?}", args.packages);
                todo!("M3.6/M4: Remote sync + fetch + ingest pipeline")
            }
            Ok(())
        }
        Operation::Query(args) => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            if args.packages.is_empty() {
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
                            println!("{}/{} {} [{}]", origin, pkg, current, &hash[..16]);
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
            let repo = CasRepository::open(&cli.repository, algo)?;
            for pkg_name in &args.packages {
                tracing::info!("Removing: {}", pkg_name);
                // Find and remove all refs for this package
                let origins = repo.list_origins()?;
                for origin in &origins {
                    let versions = repo.list_versions(origin, pkg_name)?;
                    if !versions.is_empty() {
                        let ref_dir = repo.root.join("refs").join(origin).join(pkg_name);
                        std::fs::remove_dir_all(&ref_dir)?;
                        println!("Removed {}/{} ({} versions)", origin, pkg_name, versions.len());
                    }
                }
            }
            if args.recursive {
                tracing::info!("Running GC to remove orphaned objects...");
                let purged = repo.gc()?;
                if !purged.is_empty() {
                    println!("GC: purged {} orphaned objects", purged.len());
                }
            }
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
                        &result.hash[..20]
                    );
                } else {
                    // Upstream package — use Rosetta plugin dispatch
                    let origin = args.origin.as_deref().unwrap_or_else(|| {
                        kind.map(detect_origin).unwrap_or("scratch")
                    });
                    tracing::info!("Ingesting {} package: {}", origin, file_path);
                    let result = ingest::ingest_package_with_rosetta(
                        &repo, path, origin, Some(&rosetta),
                    )?;
                    let tag = if result.rosetta_translated { " [rosetta]" } else { "" };
                    println!(
                        "✓ {}/{} {} → {}{}",
                        result.origin,
                        result.name,
                        result.version,
                        &result.hash[..20],
                        tag
                    );
                    if !result.capabilities.binaries.is_empty() {
                        println!(
                            "  binaries: {}",
                            result.capabilities.binaries.join(", ")
                        );
                    }
                    if !result.capabilities.libraries.is_empty() {
                        println!(
                            "  libraries: {}",
                            result.capabilities.libraries.join(", ")
                        );
                    }
                }
            }
            Ok(())
        }
        Operation::Files { query } => {
            let repo = CasRepository::open(&cli.repository, algo)?;
            tracing::info!("Searching for file: {}", query);
            let origins = repo.list_origins()?;
            for origin in &origins {
                let pkgs = repo.list_packages(origin)?;
                for pkg in &pkgs {
                    if let Ok(hash) = repo.resolve_ref(origin, &pkg, "current") {
                        let content_dir = repo.retrieve(&hash)?;
                        if find_file_in_tree(&content_dir, &query)? {
                            println!("{}/{} owns a file matching '{}'", origin, pkg, query);
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
                let purged = repo.gc()?;
                if purged.is_empty() {
                    println!("No orphaned objects found.");
                } else {
                    println!("Purged {} objects:", purged.len());
                    for hash in &purged {
                        println!("  - {}", &hash[..std::cmp::min(20, hash.len())]);
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
    }
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
