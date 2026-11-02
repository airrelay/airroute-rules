use clap::Parser;
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "AirRoute outbound-only DNS/TLS and traceroute worker"
)]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    once: bool,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airroute_rules=info".into()),
        )
        .init();
    let c = Cli::parse();
    airroute_rules::measure::run(airroute_rules::measure::load(&c.config)?, c.once).await
}
