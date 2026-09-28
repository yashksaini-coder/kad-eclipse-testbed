use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use kad_eclipse_testbed::{
    attack::TargetedIdGenerator,
    metrics::ScenarioMetrics,
    policy::DiversityPolicy,
    testbed::{RunConfig, Scenario},
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "kad-eclipse-testbed",
    about = "Eclipse-attack testbed and subnet-diversity filter for rust-libp2p Kademlia",
    version,
    after_help = "EXAMPLES:\n  \
        # How cheap is a targeted identity? Standalone, no network.\n  \
        kad-eclipse-testbed grind --trials 1000000 --keep 20\n\n  \
        # Run the full scenario matrix and write metrics as JSON.\n  \
        kad-eclipse-testbed run --scenario all --output docs/results/matrix.json\n\n  \
        # The /16-vs-/24 subnet-prefix sweep (see docs/methodology.md).\n  \
        kad-eclipse-testbed run --scenario diversity --prefix-v4 16\n\n\
        Run `<command> --help` for the flags of a specific subcommand."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Grind peer IDs toward a target key and report how cheap it is.
    ///
    /// Runs standalone — no network, no swarm. This is the subcommand that
    /// demonstrates the premise before any of the defence work matters.
    Grind(GrindArgs),

    /// Run the testbed scenarios and emit metrics.
    Run(RunArgs),
}

#[derive(Args)]
struct GrindArgs {
    /// Target DHT key to cluster around.
    #[arg(long, default_value = "kad-eclipse-testbed/demo-target")]
    target: String,

    /// Keypair generation trials.
    #[arg(long, default_value_t = 100_000)]
    trials: usize,

    /// How many of the closest identities to keep (default = libp2p's k).
    #[arg(long, default_value_t = 20)]
    keep: usize,
}

#[derive(Args)]
struct RunArgs {
    /// Honest nodes in the simulated network.
    #[arg(long, default_value_t = 50)]
    honest_peers: usize,

    /// Attacker identities ground toward the target and seated.
    #[arg(long, default_value_t = 30)]
    attacker_peers: usize,

    /// Keypair grind trials the attacker spends producing those identities.
    #[arg(long, default_value_t = 100_000)]
    trials: usize,

    /// Lookups to issue per scenario when measuring success rate.
    #[arg(long, default_value_t = 200)]
    lookups: usize,

    /// baseline | disjoint | diversity | hardened | hardened-churn | all
    #[arg(long, default_value = "all")]
    scenario: String,

    /// IPv4 grouping prefix. go-libp2p uses 16; py-libp2p #1399 uses 24.
    /// Sweeping this is the point.
    #[arg(long, default_value_t = 24)]
    prefix_v4: u8,

    /// IPv6 grouping prefix. 48 = site delegation boundary. Do not set 64.
    #[arg(long, default_value_t = 48)]
    prefix_v6: u8,

    /// Max peers per subnet within one k-bucket (py-libp2p MAX_PEERS_PER_SUBNET). 0 disables.
    #[arg(long, default_value_t = 2)]
    max_per_subnet: usize,

    /// Max peers per subnet across the whole routing table. 0 disables.
    #[arg(long, default_value_t = 6)]
    max_per_subnet_table_wide: usize,

    /// Write metrics as JSON here instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    match Cli::parse().command {
        Command::Grind(args) => grind(args),
        Command::Run(args) => run(args).await,
    }
}

fn grind(args: GrindArgs) -> anyhow::Result<()> {
    let generator = TargetedIdGenerator::for_key(args.target.clone()).best_n(args.keep);
    let result = generator.generate(args.trials);

    println!("target        : {}", args.target);
    println!("trials        : {}", result.trials);
    println!("elapsed       : {:.3?}", result.elapsed);
    println!("rate          : {:.0} keypairs/sec", result.rate());
    println!("kept          : {}", result.identities.len());
    if let Some(cpl) = result.best_cpl() {
        println!("best CPL      : {cpl} bits shared with target");
    }
    println!();
    for (i, id) in result.identities.iter().take(5).enumerate() {
        println!("  #{i}  {}  ilog2(d)={:?}", id.peer_id, id.distance.ilog2());
    }
    if result.identities.len() > 5 {
        println!("  … {} more", result.identities.len() - 5);
    }
    Ok(())
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let scenarios: Vec<Scenario> = if args.scenario == "all" {
        Scenario::ALL.to_vec()
    } else {
        vec![args
            .scenario
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?]
    };

    let policy = DiversityPolicy {
        prefix_len_v4: args.prefix_v4,
        prefix_len_v6: args.prefix_v6,
        max_per_subnet_per_bucket: args.max_per_subnet,
        max_per_subnet_table_wide: args.max_per_subnet_table_wide,
    };

    if args.prefix_v6 >= 64 {
        tracing::warn!(
            prefix_v6 = args.prefix_v6,
            "a /64 or longer IPv6 cap is close to no cap: one /56 delegation \
             yields 256 distinct /64s and a /48 yields 65,536"
        );
    }

    let mut all: Vec<ScenarioMetrics> = Vec::new();
    for scenario in scenarios {
        tracing::info!(scenario = scenario.name(), "starting");
        let config = RunConfig {
            scenario,
            honest_peers: args.honest_peers,
            attacker_peers: args.attacker_peers,
            trials: args.trials,
            lookups: args.lookups,
            policy,
        };
        all.push(kad_eclipse_testbed::testbed::run(config).await?);
    }

    let json = serde_json::to_string_pretty(&all)?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, json)?;
            tracing::info!(path = %path.display(), "metrics written");
        }
        None => println!("{json}"),
    }
    Ok(())
}
