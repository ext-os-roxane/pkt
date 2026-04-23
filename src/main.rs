use clap::{Parser, Subcommand};

/// pkt — ExtOS Package & Repository Engine
///
/// Manages the Content-Addressable Storage repository,
/// fetches and translates packages from upstream distributions,
/// and coordinates the P2P Swarm Network.
#[derive(Parser)]
#[command(name = "pkt", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Update local cache of upstream package databases
    Sync,
    /// Search for packages by name or capability
    Search {
        /// Query string (package name or `provides:libssl.so.3` syntax)
        query: String,
    },
    /// Fetch and store a package into the CAS without weaving
    Fetch {
        /// Package specifier: origin/package/version
        specifier: String,
    },
    /// Install a package (fetch + request weave from instanz)
    Install {
        /// Package specifier(s)
        packages: Vec<String>,
    },
    /// Garbage collect unreferenced CAS objects
    Gc {
        /// Number of generations to keep
        #[arg(long, default_value = "3")]
        keep_generations: u32,
    },
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync => {
            tracing::info!("pkt sync: updating upstream databases...");
            todo!("M3.6: Sync databases")
        }
        Commands::Search { query } => {
            tracing::info!("pkt search: {query}");
            todo!("M3.1: Search implementation")
        }
        Commands::Fetch { specifier } => {
            tracing::info!("pkt fetch: {specifier}");
            todo!("M3.2: Fetch and extraction pipeline")
        }
        Commands::Install { packages } => {
            tracing::info!("pkt install: {packages:?}");
            todo!("M3: Full install pipeline")
        }
        Commands::Gc { keep_generations } => {
            tracing::info!("pkt gc: keeping {keep_generations} generations");
            todo!("M2.5: Garbage collector")
        }
        Commands::Repack { hash, format } => {
            tracing::info!("pkt repack: {hash} -> {format}");
            todo!("M14.4: Repacker")
        }
        Commands::Publish { origin } => {
            tracing::info!("pkt publish: {origin}");
            todo!("M14: P2P Swarm publish")
        }
        Commands::Build { config } => {
            tracing::info!("pkt build: {config}");
            todo!("M21.2: Build-on-self pipeline")
        }
        Commands::Verify { hash } => {
            tracing::info!("pkt verify: {hash:?}");
            todo!("M2.1: CAS integrity verification")
        }
    }
}
