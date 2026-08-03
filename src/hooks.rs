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
    // Automatic remote TUN IP configuration if remote_tun_addr and local_tun_addr are specified
    if let (Some(ref remote_ip), Some(ref local_ip)) = (&config.remote_tun_addr, &config.local_tun_addr) {
        let remote_tun_name = match config.tun_forward {
            Some(ref t) if t.remote_tun != "any" => {
                if t.remote_tun.starts_with("tun") {
                    t.remote_tun.clone()
                } else {
                    format!("tun{}", t.remote_tun)
                }
            }
            _ => "tun0".to_string(),
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
