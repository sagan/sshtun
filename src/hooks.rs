use crate::config::ResolvedConfig;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use tokio::io::AsyncReadExt;
use tokio::process::Command as LocalCommand;
use tracing::{error, info, warn};

pub async fn run_local_post_up(cmd: &str) -> anyhow::Result<()> {
    info!("Running local post-up command: '{}'", cmd);
    let status = LocalCommand::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .await?;

    if status.success() {
        info!("Local post-up command completed successfully");
    } else {
        warn!("Local post-up command failed with exit status: {}", status);
    }
    Ok(())
}

pub async fn run_remote_command(
    handle: &Handle<ClientHandler>,
    cmd: &str,
) -> anyhow::Result<String> {
    info!("Executing remote command via SSH: '{}'", cmd);
    let channel = handle
        .channel_open_session()

        .await
        .map_err(|e| anyhow::anyhow!("Failed to open remote session channel: {}", e))?;

    channel
        .exec(true, cmd)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to exec remote command '{}': {}", cmd, e))?;

    let mut stream = channel.into_stream();
    let mut output = String::new();
    let _ = stream.read_to_string(&mut output).await;

    Ok(output)
}

pub async fn run_post_up_hooks(
    handle: &Handle<ClientHandler>,
    config: &ResolvedConfig,
) -> anyhow::Result<()> {
    if let Some(ref tun) = config.tun_forward {
        if let Some(id) = tun.auto_id {
            if let (Some(ref remote_ip), Some(ref local_ip)) = (&config.remote_tun_addr, &config.local_tun_addr) {
                let fwmark = (id as u32) << 16;
                let tun_dev = format!("tun{}", id);
                let remote_ip_clean = remote_ip.trim_end_matches("/32");
                let local_ip_clean = local_ip.trim_end_matches("/32");

                let auto_setup_cmd = format!(
                    "for i in $(seq 1 30); do if ip link show dev {tun_dev} >/dev/null 2>&1; then break; fi; sleep 0.1; done; \
                     sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true; \
                     ip addr add {remote_ip}/32 peer {local_ip} dev {tun_dev} 2>/dev/null || true; \
                     ip link set dev {tun_dev} up 2>/dev/null || true; \
                     nft 'add table inet sshtun{id}; delete table inet sshtun{id}; table inet sshtun{id} {{ chain prerouting {{ type filter hook prerouting priority mangle; policy accept; iifname \"{tun_dev}\" ct state new ct mark set {fwmark}; iifname != \"{tun_dev}\" ct mark {fwmark} meta mark set ct mark; }}; chain output {{ type route hook output priority mangle; policy accept; ct mark {fwmark} meta mark set ct mark; }}; chain postrouting {{ type nat hook postrouting priority srcnat; policy accept; oifname != \"{tun_dev}\" ip saddr {local_ip} masquerade; }}; }}'; \
                     ip rule del fwmark {fwmark}/0xffff0000 lookup {id} 2>/dev/null || true; \
                     ip rule add fwmark {fwmark}/0xffff0000 lookup {id} prio 10000; \
                     ip route replace default dev {tun_dev} table {id}",
                    tun_dev = tun_dev,
                    id = id,
                    fwmark = fwmark,
                    remote_ip = remote_ip_clean,
                    local_ip = local_ip_clean,
                );

                info!("Configuring auto TUN routing and firewall rules on remote server ({tun_dev})...");
                match run_remote_command(handle, &auto_setup_cmd).await {
                    Ok(out) => {
                        let trimmed = out.trim();
                        if !trimmed.is_empty() {
                            info!("Remote TUN auto setup output: {}", trimmed);
                        } else {
                            info!("Remote TUN auto setup completed successfully");
                        }
                    }
                    Err(e) => {
                        error!("Failed to configure auto TUN rules on remote server: {}", e);
                    }
                }
            }
        } else if let (Some(ref remote_ip), Some(ref local_ip)) = (&config.remote_tun_addr, &config.local_tun_addr) {
            let remote_tun_name = if tun.remote_tun != "any" {
                if tun.remote_tun.starts_with("tun") {
                    tun.remote_tun.clone()
                } else {
                    format!("tun{}", tun.remote_tun)
                }
            } else {
                "tun0".to_string()
            };

            let auto_remote_cmd = format!(
                "ip addr add {}/32 peer {} dev {} 2>/dev/null || true; ip link set {} up",
                remote_ip.trim_end_matches("/32"),
                local_ip.trim_end_matches("/32"),
                remote_tun_name,
                remote_tun_name
            );
            info!("Configuring remote TUN interface via SSH: {}", auto_remote_cmd);
            match run_remote_command(handle, &auto_remote_cmd).await {
                Ok(out) => {
                    info!("Remote TUN IP setup output: {}", out.trim());
                }
                Err(e) => {
                    error!("Failed to configure remote TUN interface IP: {}", e);
                }
            }
        }
    }

    // Run explicit remote-post-up if provided
    if let Some(ref remote_cmd) = config.remote_post_up {
        match run_remote_command(handle, remote_cmd).await {
            Ok(out) => {
                info!("Remote post-up output: {}", out.trim());
            }
            Err(e) => {
                error!("Failed to execute remote post-up hook: {}", e);
            }
        }
    }

    // Run explicit local-post-up if provided
    if let Some(ref local_cmd) = config.local_post_up {
        if let Err(e) = run_local_post_up(local_cmd).await {
            error!("Local post-up hook error: {}", e);
        }
    }

    Ok(())
}

pub async fn run_cleanup_hooks(
    handle: &Handle<ClientHandler>,
    config: &ResolvedConfig,
) -> anyhow::Result<()> {
    if let Some(ref tun) = config.tun_forward {
        if let Some(id) = tun.auto_id {
            let fwmark = (id as u32) << 16;
            let tun_dev = format!("tun{}", id);
            let cleanup_cmd = format!(
                "nft 'add table inet sshtun{id}; delete table inet sshtun{id}' 2>/dev/null || true; \
                 ip rule del fwmark {fwmark}/0xffff0000 lookup {id} 2>/dev/null || true; \
                 ip route del default dev {tun_dev} table {id} 2>/dev/null || true; \
                 ip link set dev {tun_dev} down 2>/dev/null || true",
                id = id,
                fwmark = fwmark,
                tun_dev = tun_dev,
            );
            info!("Cleaning up auto-configured remote TUN rules on server ({tun_dev})...");
            match run_remote_command(handle, &cleanup_cmd).await {
                Ok(out) => {
                    let trimmed = out.trim();
                    if !trimmed.is_empty() {
                        info!("Remote cleanup output: {}", trimmed);
                    } else {
                        info!("Remote cleanup completed successfully");
                    }
                }
                Err(e) => {
                    warn!("Remote cleanup error (best effort): {}", e);
                }
            }
        }
    }
    Ok(())
}
