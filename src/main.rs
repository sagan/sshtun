mod config;
mod hooks;
mod monitor;
mod ssh;
mod tunnels;

use clap::Parser;
use config::{CliArgs, ResolvedConfig};
use ssh::SshConnection;
use std::time::Duration;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use tunnels::TunnelManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    let config = ResolvedConfig::from_args(args)?;

    info!("Starting sshtun for target: {} ({}:{})", config.host, config.hostname, config.port);
    if let Some(ref tun) = config.tun_forward {
        info!("TUN tunnel requested: local '{}' <-> remote '{}'", tun.local_tun, tun.remote_tun);
    }
    info!("Local forwards: {}", config.local_forwards.len());
    info!("Remote forwards: {}", config.remote_forwards.len());
    info!("Dynamic forwards: {}", config.dynamic_forwards.len());

    loop {
        info!("Attempting SSH connection to {}:{}...", config.hostname, config.port);

        match SshConnection::connect(&config.hostname, config.port, &config.user, &config.identity_files).await {
            Ok(mut ssh_conn) => {
                info!("SSH connection established successfully to {}:{}", config.hostname, config.port);

                // Start tunnels
                let mut tunnel_mgr = match TunnelManager::start(&mut ssh_conn.handle, &config, ssh_conn.forwarded_tcp_rx).await {
                    Ok(mgr) => mgr,
                    Err(e) => {
                        error!("Failed to start tunnels: {}. Retrying in {}s...", e, config.reconnect_interval);
                        sleep(Duration::from_secs(config.reconnect_interval)).await;
                        continue;
                    }
                };

                // Run post-up hooks (includes local & remote TUN IP config if specified)
                if let Err(e) = hooks::run_post_up_hooks(&ssh_conn.handle, &config).await {
                    error!("Post-up hook execution encountered error: {}", e);
                }

                // Spawn link monitor
                let handle_clone = ssh_conn.handle.clone();
                let config_clone = config.clone();
                let mut monitor_handle = tokio::spawn(async move {
                    monitor::run_link_monitor(handle_clone, config_clone).await
                });

                info!("sshtun active and operational. Press Ctrl+C to terminate.");

                tokio::select! {
                    res = &mut monitor_handle => {
                        match res {
                            Ok(Ok(_)) => info!("Monitor finished normally."),
                            Ok(Err(e)) => error!("Link monitor reported error: {}", e),
                            Err(e) => error!("Monitor task panicked: {}", e),
                        }
                    }
                    _ = signal::ctrl_c() => {
                        info!("Received Ctrl+C / SIGINT signal. Terminating sshtun...");
                        tunnel_mgr.abort_all();
                        return Ok(());
                    }
                }

                info!("Connection lost. Cleaning up active tunnels...");
                tunnel_mgr.abort_all();
            }
            Err(e) => {
                error!("SSH connection error: {}", e);
            }
        }

        info!("Waiting {}s before reconnecting...", config.reconnect_interval);
        sleep(Duration::from_secs(config.reconnect_interval)).await;
    }
}
