mod config;
mod hooks;
mod monitor;
mod ssh;
mod tunnels;

use clap::Parser;
use config::{CliArgs, ResolvedConfig};
use russh::client::Handle;
use ssh::{ClientHandler, SshConnection};
use std::time::Duration;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use tunnels::TunnelManager;

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => "Ctrl+C / SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        "Ctrl+C / SIGINT"
    }
}

async fn handle_termination(
    handle: &Handle<ClientHandler>,
    config: &ResolvedConfig,
    monitor_handle: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    tunnel_mgr: &mut TunnelManager,
    signal_name: &str,
) {
    info!("Received {} signal. Terminating sshtun...", signal_name);
    monitor_handle.abort();
    tunnel_mgr.abort_all();

    if let Some(ref tun) = config.tun_forward {
        if tun.auto_id.is_some() {
            info!("Cleaning up remote server rules... (Press Ctrl+C again to force exit)");
            let cleanup_config = config.clone();
            tokio::select! {
                res = tokio::time::timeout(
                    Duration::from_secs(4),
                    hooks::run_cleanup_hooks(handle, &cleanup_config)
                ) => {
                    if res.is_err() {
                        warn!("Remote cleanup timed out after 4 seconds.");
                    }
                }
                _ = signal::ctrl_c() => {
                    warn!("Second Ctrl+C received. Force exiting immediately.");
                    std::process::exit(130);
                }
            }

            let _ = tokio::process::Command::new("ip")
                .args(&["link", "delete", &tun.local_tun])
                .status()
                .await;
        }
    }
}

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
    if !config.jump_hosts.is_empty() {
        info!("Jump hosts configured: {}", config.jump_hosts.len());
        for (i, j) in config.jump_hosts.iter().enumerate() {
            info!("  Jump host [{}]: {} ({}:{} as user '{}')", i + 1, j.host, j.hostname, j.port, j.user);
        }
    }
    if let Some(ref tun) = config.tun_forward {
        info!("TUN tunnel requested: local '{}' <-> remote '{}'", tun.local_tun, tun.remote_tun);
    }
    info!("Local forwards: {}", config.local_forwards.len());
    info!("Remote forwards: {}", config.remote_forwards.len());
    info!("Dynamic forwards: {}", config.dynamic_forwards.len());
    if let Some(mark) = config.fwmark {
        info!("SSH socket fwmark configured: {:#x} ({})", mark, mark);
    }

    loop {
        info!("Attempting SSH connection to {}:{}...", config.hostname, config.port);

        match SshConnection::connect(&config).await {
            Ok(mut ssh_conn) => {
                info!("SSH connection established successfully to {}:{}", config.hostname, config.port);

                // Run pre-tunnel cleanup on remote server for auto TUN if configured, to clear any
                // stale interface or firewall/routing rules left from previous broken connections.
                if let Some(ref tun) = config.tun_forward {
                    if tun.auto_id.is_some() {
                        let cleanup_handle = ssh_conn.handle.clone();
                        let cleanup_config = config.clone();
                        let _ = tokio::time::timeout(
                            Duration::from_secs(4),
                            hooks::run_cleanup_hooks(&cleanup_handle, &cleanup_config),
                        )
                        .await;
                    }
                }

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
                    Some(reason) = tunnel_mgr.exit_rx.recv() => {
                        error!("Tunnel worker terminated: {}. Triggering reconnection...", reason);
                    }
                    sig_name = wait_for_shutdown_signal() => {
                        handle_termination(&ssh_conn.handle, &config, &mut monitor_handle, &mut tunnel_mgr, sig_name).await;
                        return Ok(());
                    }
                }

                info!("Connection lost. Cleaning up active tunnels...");
                monitor_handle.abort();
                tunnel_mgr.abort_all();

                if let Some(ref tun) = config.tun_forward {
                    if tun.auto_id.is_some() {
                        let cleanup_handle = ssh_conn.handle.clone();
                        let cleanup_config = config.clone();
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            hooks::run_cleanup_hooks(&cleanup_handle, &cleanup_config)
                        ).await;

                        let _ = tokio::process::Command::new("ip")
                            .args(&["link", "delete", &tun.local_tun])
                            .status()
                            .await;
                    }
                }
            }
            Err(e) => {
                error!("SSH connection error: {}", e);
            }
        }

        info!("Waiting {}s before reconnecting...", config.reconnect_interval);
        sleep(Duration::from_secs(config.reconnect_interval)).await;
    }
}
