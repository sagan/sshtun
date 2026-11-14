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

async fn run_connection_worker(
    config: ResolvedConfig,
    prefix: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    info!("{prefix}Starting sshtun for target: {} ({}:{})", config.host, config.hostname, config.port);
    if !config.jump_hosts.is_empty() {
        info!("{prefix}Jump hosts configured: {}", config.jump_hosts.len());
        for (i, j) in config.jump_hosts.iter().enumerate() {
            info!("{prefix}  Jump host [{}]: {} ({}:{} as user '{}')", i + 1, j.host, j.hostname, j.port, j.user);
        }
    }
    if let Some(ref tun) = config.tun_forward {
        info!("{prefix}TUN tunnel requested: local '{}' <-> remote '{}'", tun.local_tun, tun.remote_tun);
    }
    info!("{prefix}Local forwards: {}", config.local_forwards.len());
    info!("{prefix}Remote forwards: {}", config.remote_forwards.len());
    info!("{prefix}Dynamic forwards: {}", config.dynamic_forwards.len());
    if let Some(mark) = config.fwmark {
        info!("{prefix}SSH socket fwmark configured: {:#x} ({})", mark, mark);
    }

    loop {
        info!("{prefix}Attempting SSH connection to {}:{}...", config.hostname, config.port);

        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("{prefix}Shutdown received, terminating connection worker.");
                return;
            }
            conn_res = SshConnection::connect(&config) => {
                match conn_res {
                    Ok(ssh_conn) => {
                        info!("{prefix}SSH connection established successfully to {}:{}", config.hostname, config.port);

                        // Run pre-tunnel cleanup on remote server for auto TUN if configured
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
                        let mut tunnel_mgr = match TunnelManager::start(&ssh_conn.handle, &config, ssh_conn.forwarded_tcp_rx).await {
                            Ok(mgr) => mgr,
                            Err(e) => {
                                error!("{prefix}Failed to start tunnels: {}. Retrying in {}s...", e, config.reconnect_interval);
                                tokio::select! {
                                    _ = shutdown_rx.changed() => return,
                                    _ = sleep(Duration::from_secs(config.reconnect_interval)) => continue,
                                }
                            }
                        };

                        // Run post-up hooks
                        if let Err(e) = hooks::run_post_up_hooks(&ssh_conn.handle, &config).await {
                            error!("{prefix}Post-up hook execution encountered error: {}", e);
                        }

                        // Spawn link monitor
                        let handle_clone = ssh_conn.handle.clone();
                        let config_clone = config.clone();
                        let mut monitor_handle = tokio::spawn(async move {
                            monitor::run_link_monitor(handle_clone, config_clone).await
                        });

                        info!("{prefix}sshtun active and operational.");

                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                info!("{prefix}Shutdown received. Cleaning up active connection...");
                                monitor_handle.abort();
                                tunnel_mgr.abort_all();

                                if let Some(ref tun) = config.tun_forward {
                                    if tun.auto_id.is_some() {
                                        info!("{prefix}Cleaning up remote server rules...");
                                        let cleanup_handle = ssh_conn.handle.clone();
                                        let cleanup_config = config.clone();
                                        let _ = tokio::time::timeout(
                                            Duration::from_secs(4),
                                            hooks::run_cleanup_hooks(&cleanup_handle, &cleanup_config)
                                        ).await;

                                        let _ = tokio::process::Command::new("ip")
                                            .args(&["link", "delete", &tun.local_tun])
                                            .status()
                                            .await;
                                    }
                                }
                                return;
                            }
                            res = &mut monitor_handle => {
                                match res {
                                    Ok(Ok(_)) => info!("{prefix}Monitor finished normally."),
                                    Ok(Err(e)) => error!("{prefix}Link monitor reported error: {}", e),
                                    Err(e) => error!("{prefix}Monitor task panicked: {}", e),
                                }
                            }
                            Some(reason) = tunnel_mgr.exit_rx.recv() => {
                                error!("{prefix}Tunnel worker terminated: {}. Triggering reconnection...", reason);
                            }
                        }

                        info!("{prefix}Connection lost. Cleaning up active tunnels...");
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
                        error!("{prefix}SSH connection error: {}", e);
                    }
                }
            }
        }

        info!("{prefix}Waiting {}s before reconnecting...", config.reconnect_interval);
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("{prefix}Shutdown received while waiting to reconnect.");
                return;
            }
            _ = sleep(Duration::from_secs(config.reconnect_interval)) => {}
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

    let (configs, is_multi) = if let Some(ref config_path) = args.config {
        let parsed = ResolvedConfig::from_config_file(config_path)?;
        info!("Loaded {} SSH connection configuration(s) from '{}'", parsed.len(), config_path.display());
        let multi = parsed.len() > 1;
        (parsed, multi)
    } else {
        (vec![ResolvedConfig::from_args(args)?], false)
    };

    let total = configs.len();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut join_set = tokio::task::JoinSet::new();

    for (idx, config) in configs.into_iter().enumerate() {
        let prefix = if is_multi {
            format!("[{}/{}: {}] ", idx + 1, total, config.host)
        } else {
            String::new()
        };
        let rx = shutdown_rx.clone();
        join_set.spawn(async move {
            run_connection_worker(config, prefix, rx).await;
        });
    }

    let signal_name = wait_for_shutdown_signal().await;
    info!("Received {} signal. Terminating sshtun...", signal_name);
    let _ = shutdown_tx.send(true);

    info!("Waiting for active connection(s) to shut down... (Press Ctrl+C again to force exit)");
    tokio::select! {
        _ = async {
            while let Some(res) = join_set.join_next().await {
                if let Err(e) = res {
                    warn!("Connection worker task ended with error: {}", e);
                }
            }
        } => {
            info!("All sshtun connections terminated cleanly.");
        }
        _ = sleep(Duration::from_secs(5)) => {
            warn!("Shutdown cleanup timed out after 5 seconds. Force exiting.");
        }
        _ = signal::ctrl_c() => {
            warn!("Second Ctrl+C received. Force exiting immediately.");
            std::process::exit(130);
        }
    }

    Ok(())
}
