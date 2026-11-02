use airroute_rules::{
    build, globalping, server,
    store::{Node, Store},
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "AirRoute rules controller with embedded Web Console")]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,
    #[arg(long, global = true, default_value = "data")]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Build {
        #[arg(long)]
        offline: bool,
    },
    Validate {
        #[arg(default_value = "dist")]
        output: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: std::net::SocketAddr,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        quic_bind: Option<std::net::SocketAddr>,
        #[arg(long, default_value_t = 24)]
        interval_hours: u64,
    },
    Status,
    NodeAdd {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        region: String,
        #[arg(long, default_value_t = 0)]
        asn: u32,
        #[arg(long, env = "AIRROUTE_NODE_TOKEN", hide_env_values = true)]
        token: String,
    },
    Observe {
        #[arg(long)]
        target: String,
        #[arg(long, value_delimiter = ',')]
        regions: Vec<String>,
        #[arg(long, default_value = "operator requested resolver comparison")]
        reason: String,
        #[arg(long)]
        refresh: bool,
    },
    Tick,
    Discover,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "airroute_rules=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Cli::parse();
    let root = args.root.canonicalize()?;
    let data = if args.data.is_absolute() {
        args.data
    } else {
        root.join(args.data)
    };
    let result = match args.command {
        Command::Build { offline } => {
            let value =
                tokio::task::spawn_blocking(move || build::run(&root, &data, offline)).await??;
            Some(value)
        }
        Command::Validate { output } => Some(build::validate(&output, &root)?),
        Command::Serve {
            bind,
            offline,
            interval_hours,
            quic_bind,
        } => {
            server::serve(root, data, bind, offline, interval_hours, quic_bind).await?;
            None
        }
        Command::Status => Some(Store::open(&data)?.overview()?),
        Command::NodeAdd {
            id,
            name,
            region,
            asn,
            token,
        } => {
            let id = id.unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4().simple()));
            Store::open(&data)?.register_named_node(
                &Node {
                    id: id.clone(),
                    region,
                    asn,
                    capabilities: vec!["dns".into(), "traceroute".into()],
                },
                &token,
                name.as_deref(),
            )?;
            Some(serde_json::json!({"registered":true,"id":id}))
        }
        Command::Observe {
            target,
            regions,
            reason,
            refresh,
        } => Some(
            serde_json::json!({"case":Store::open(&data)?.request_observation(&target,&regions,&reason,refresh)?}),
        ),
        Command::Discover => Some(
            airroute_rules::discovery::tick(
                &Store::open(&data)?,
                &airroute_rules::discovery::load(&root)?,
            )
            .await?,
        ),
        Command::Tick => {
            let store = Store::open(&data)?;
            airroute_rules::receipt::configure_country_regions(&store, &root)?;
            airroute_rules::jobs_v3::requalify_legacy(&store)?;
            airroute_rules::build_delta::sync_current(&store, 128)?;
            airroute_rules::work::refresh(&store)?;
            Some(
                globalping::tick(
                    &store,
                    &globalping::load(&root.join("config/globalping.toml"))?,
                )
                .await?,
            )
        }
    };
    if let Some(value) = result {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}
