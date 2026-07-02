// A small CLI tool that browses for DNS-SD services (clap CLI, env_logger, Ctrl-C).

use std::num::NonZeroU32;

use clap::Parser;
use log::{error, info};

use mdns_sd_discovery::{BrowseEvent, ServiceBrowserBuilder, ServiceResolverBuilder};

/// Browse for DNS-SD services and print them as they come and go.
///
/// With no `--type`, *all* service types on the network are discovered.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Restrict to a single service type, e.g. `_http._tcp` or `_ssh._tcp`.
    /// Omit to browse every service type on the network.
    #[arg(short = 't', long = "type", value_name = "SERVICE_TYPE")]
    service_type: Option<String>,

    /// Domain to browse (defaults to the default browse domain, usually `local`).
    #[arg(short, long)]
    domain: Option<String>,

    /// Interface index to browse on (defaults to all interfaces).
    #[arg(short, long, value_name = "INDEX")]
    interface: Option<NonZeroU32>,

    /// Instead of browsing, resolve a single instance by name once and exit.
    /// Requires `--type`; useful as a liveness probe. Reports success or
    /// `ResolveFailed` (within `--timeout`) if the instance no longer responds.
    #[arg(short = 'r', long = "resolve", value_name = "NAME")]
    resolve: Option<String>,

    /// Timeout in seconds for `--resolve` (defaults to the platform default).
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// Enable trace-level logging (default is debug).
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(if args.verbose {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Debug
        })
        .parse_default_env()
        .init();

    if let Some(name) = &args.resolve {
        resolve_once(&args, name).await;
        return;
    }

    let mut builder = ServiceBrowserBuilder::new();
    if let Some(service_type) = &args.service_type {
        builder.service_type(service_type);
    }
    if let Some(domain) = &args.domain {
        builder.domain(domain);
    }
    if let Some(index) = args.interface {
        builder.interface_index(index);
    }

    let mut browser = builder.browse().await.expect("failed to start browsing");

    match &args.service_type {
        Some(t) => info!("browsing for {t} services (press Ctrl-C to stop)..."),
        None => info!("browsing for all service types (press Ctrl-C to stop)..."),
    }

    loop {
        tokio::select! {
            event = browser.recv() => match event {
                Some(Ok(BrowseEvent::Found(svc))) => {
                    println!(
                        "+ [{}] {:?}  {}:{}  {:?}",
                        svc.service_type, svc.name, svc.host_name, svc.port, svc.addresses
                    );
                    for txt in &svc.txt_records {
                        match &txt.value {
                            Some(v) => println!("    {} = {}", txt.key, String::from_utf8_lossy(v)),
                            None => println!("    {}", txt.key),
                        }
                    }
                }
                Some(Ok(BrowseEvent::Removed(svc))) => {
                    println!("- [{}] {:?}", svc.service_type, svc.name);
                }
                Some(Err(err)) => {
                    error!("browse error: {err}");
                }
                None => {
                    info!("browse ended");
                    break;
                }
            },
            _ = tokio::signal::ctrl_c() => {
                info!("stopping...");
                break;
            }
        }
    }

    // Dropping `browser` here stops the underlying native browse operation.
}

/// Resolves a single instance once and prints the outcome (a liveness probe).
async fn resolve_once(args: &Args, name: &str) {
    let Some(service_type) = &args.service_type else {
        error!("--resolve requires --type SERVICE_TYPE");
        return;
    };
    let domain = args.domain.as_deref().unwrap_or("local");

    let mut builder = ServiceResolverBuilder::new(name, service_type, domain);
    if let Some(index) = args.interface {
        builder.interface_index(index);
    }
    if let Some(secs) = args.timeout {
        builder.timeout(std::time::Duration::from_secs(secs));
    }

    info!("resolving {name:?} ({service_type} in {domain})...");
    match builder.resolve().await {
        Ok(svc) => {
            println!(
                "+ [{}] {:?}  {}:{}  {:?}",
                svc.service_type, svc.name, svc.host_name, svc.port, svc.addresses
            );
            for txt in &svc.txt_records {
                match &txt.value {
                    Some(v) => println!("    {} = {}", txt.key, String::from_utf8_lossy(v)),
                    None => println!("    {}", txt.key),
                }
            }
        }
        Err(err) => error!("resolve failed: {err}"),
    }
}
