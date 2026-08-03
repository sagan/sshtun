use crate::config::TunForwardSpec;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_tun::TunBuilder;
use tracing::{error, info, warn};


pub async fn run_tun_forward(
    handle: Arc<Handle<ClientHandler>>,
    spec: TunForwardSpec,
    local_tun_addr: Option<String>,
    remote_tun_addr: Option<String>,
) -> anyhow::Result<()> {
    let dev_name = if spec.local_tun == "any" {
        "tun0".to_string()
    } else if spec.local_tun.starts_with("tun") {
        spec.local_tun.clone()
    } else {
        format!("tun{}", spec.local_tun)
    };

    info!("Creating local TUN device '{}'...", dev_name);

    let tun = TunBuilder::new()
        .name(&dev_name)
        .tap(false)
        .packet_info(false)
        .up()
        .try_build()
        .map_err(|e| anyhow::anyhow!("Failed to create local TUN device '{}': {}", dev_name, e))?;


    let actual_dev_name = tun.name().to_string();
    info!("Local TUN device '{}' created successfully", actual_dev_name);

    // Configure local TUN IP address if provided
    if let (Some(local_ip), Some(remote_ip)) = (local_tun_addr.as_ref(), remote_tun_addr.as_ref()) {
        info!(
            "Configuring local TUN device {} with address {} peer {}",
            actual_dev_name, local_ip, remote_ip
        );
        let status = Command::new("ip")
            .args(&[
                "addr",
                "add",
                &format!("{}/32", local_ip.trim_end_matches("/32")),
                "peer",
                remote_ip.trim_end_matches("/32"),
                "dev",
                &actual_dev_name,
            ])
            .status()
            .await;

        match status {
            Ok(s) if s.success() => {
                info!("Configured IP address on local TUN device {}", actual_dev_name);
            }
            Ok(s) => {
                warn!("ip addr command returned exit status: {}", s);
            }
            Err(e) => {
                error!("Failed to execute ip addr command for local TUN: {}", e);
            }
        }

        let _ = Command::new("ip")
            .args(&["link", "set", &actual_dev_name, "up"])
            .status()
            .await;
    }

    // Determine remote tun device number
    let remote_tun_num: u32 = if spec.remote_tun == "any" {
        0x7fffffff // SSH_TUNID_ANY
    } else {
        spec.remote_tun
            .trim_start_matches("tun")
            .parse::<u32>()
            .unwrap_or(0x7fffffff)
    };

    info!("Opening SSH TUN channel (tun@openssh.com) for remote tun {}...", spec.remote_tun);
    let channel = handle
        .channel_open_tun(1, remote_tun_num)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open tun@openssh.com SSH channel: {}", e))?;

    info!("SSH TUN channel established successfully");

    let stream = channel.into_stream();
    let (mut channel_read, mut channel_write) = tokio::io::split(stream);
    let (mut tun_read, mut tun_write) = tokio::io::split(tun);

    // Task 1: Local TUN -> SSH Channel
    let tun_to_ssh = tokio::spawn(async move {
        let mut packet_buf = vec![0u8; 4096];
        loop {
            // Leave space for 4-byte OpenSSH family header at index 0..4
            let n = match tun_read.read(&mut packet_buf[4..]).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    error!("Error reading from TUN device: {}", e);
                    break;
                }
            };

            let version = packet_buf[4] >> 4;
            let family: u32 = match version {
                4 => 2,  // AF_INET for IPv4
                6 => 10, // AF_INET6 for IPv6
                _ => 2,  // Default AF_INET
            };

            packet_buf[0..4].copy_from_slice(&family.to_be_bytes());

            if let Err(e) = channel_write.write_all(&packet_buf[..4 + n]).await {
                error!("Error writing packet to SSH TUN channel: {}", e);
                break;
            }
        }
    });

    // Task 2: SSH Channel -> Local TUN
    let ssh_to_tun = tokio::spawn(async move {
        let mut frame_buf = vec![0u8; 4096];
        loop {
            let n = match channel_read.read(&mut frame_buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    error!("Error reading from SSH TUN channel: {}", e);
                    break;
                }
            };

            if n <= 4 {
                continue; // Packet header only or too short
            }

            // Strip 4-byte OpenSSH family header and write IP packet payload to TUN device
            let payload = &frame_buf[4..n];
            if let Err(e) = tun_write.write_all(payload).await {
                error!("Error writing packet to local TUN device: {}", e);
                break;
            }
        }
    });

    let _ = tokio::join!(tun_to_ssh, ssh_to_tun);
    Ok(())
}
