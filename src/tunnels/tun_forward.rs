use crate::config::TunForwardSpec;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_tun::TunBuilder;
use tracing::{error, info, warn};

pub struct TunSession {
    pub tun: tokio_tun::Tun,
    pub channel: russh::Channel<russh::client::Msg>,
}

pub async fn setup_tun_forward(
    handle: Arc<Handle<ClientHandler>>,
    spec: &TunForwardSpec,
    local_tun_addr: Option<&str>,
    remote_tun_addr: Option<&str>,
    local_tun_addr6: Option<&str>,
    remote_tun_addr6: Option<&str>,
) -> anyhow::Result<(TunSession, String)> {
    let dev_name = if spec.local_tun == "any" {
        "tun0".to_string()
    } else if spec.local_tun.starts_with("tun") {
        spec.local_tun.clone()
    } else {
        format!("tun{}", spec.local_tun)
    };

    info!("Creating local TUN device '{}'...", dev_name);

    let tun = match TunBuilder::new()
        .name(&dev_name)
        .tap(false)
        .packet_info(false)
        .up()
        .try_build()
    {
        Ok(t) => t,
        Err(orig_err) => {
            warn!(
                "Failed to create local TUN device '{}': {}. Attempting cleanup and retry...",
                dev_name, orig_err
            );
            let _ = Command::new("ip").args(&["link", "delete", &dev_name]).status().await;
            TunBuilder::new()
                .name(&dev_name)
                .tap(false)
                .packet_info(false)
                .up()
                .try_build()
                .map_err(|e| anyhow::anyhow!("Failed to create local TUN device '{}': {}", dev_name, e))?
        }
    };

    let actual_dev_name = tun.name().to_string();
    info!("Local TUN device '{}' created successfully", actual_dev_name);

    // Configure local TUN IPv4 address if provided
    if let (Some(local_ip), Some(remote_ip)) = (local_tun_addr, remote_tun_addr) {
        info!(
            "Configuring local TUN device {} with address {} peer {}",
            actual_dev_name, local_ip, remote_ip
        );
        let status = Command::new("ip")
            .args(&[
                "addr",
                "replace",
                &format!("{}/32", local_ip.trim_end_matches("/32")),
                "peer",
                remote_ip.trim_end_matches("/32"),
                "dev",
                &actual_dev_name,
            ])
            .status()
            .await;

        let status = match status {
            Ok(s) if s.success() => Ok(s),
            _ => {
                Command::new("ip")
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
                    .await
            }
        };

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

    // Configure local TUN IPv6 address if provided
    if let (Some(local_ip6), Some(remote_ip6)) = (local_tun_addr6, remote_tun_addr6) {
        info!(
            "Configuring local TUN device {} with IPv6 address {} peer {}",
            actual_dev_name, local_ip6, remote_ip6
        );
        let local_clean = local_ip6.trim_end_matches("/127").trim_end_matches("/128");
        let remote_clean = remote_ip6.trim_end_matches("/127").trim_end_matches("/128");
        let status = Command::new("ip")
            .args(&[
                "addr",
                "replace",
                &format!("{}/127", local_clean),
                "peer",
                remote_clean,
                "dev",
                &actual_dev_name,
            ])
            .status()
            .await;

        let status = match status {
            Ok(s) if s.success() => Ok(s),
            _ => {
                Command::new("ip")
                    .args(&[
                        "addr",
                        "add",
                        &format!("{}/127", local_clean),
                        "peer",
                        remote_clean,
                        "dev",
                        &actual_dev_name,
                    ])
                    .status()
                    .await
            }
        };

        match status {
            Ok(s) if s.success() => {
                info!("Configured IPv6 address on local TUN device {}", actual_dev_name);
            }
            Ok(s) => {
                warn!("ip addr command returned exit status for IPv6: {}", s);
            }
            Err(e) => {
                error!("Failed to execute ip addr command for local TUN IPv6: {}", e);
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
    let mut channel = None;
    let mut last_err = None;
    for attempt in 1..=5 {
        match handle.channel_open_tun(1, remote_tun_num).await {
            Ok(ch) => {
                info!("SSH TUN channel established successfully (remote tun {})", spec.remote_tun);
                channel = Some(ch);
                break;
            }
            Err(e) => {
                warn!(
                    "Failed to open SSH TUN channel on attempt {}/5 (remote tun {}): {}. Retrying in 1s...",
                    attempt, spec.remote_tun, e
                );
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }

    let channel = channel.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to open tun@openssh.com SSH channel after 5 attempts: {:?}",
            last_err
        )
    })?;

    Ok((TunSession { tun, channel }, actual_dev_name))
}

pub async fn run_tun_forward_loop(session: TunSession) -> anyhow::Result<()> {
    let stream = session.channel.into_stream();
    let (mut channel_read, mut channel_write) = tokio::io::split(stream);
    let (mut tun_read, mut tun_write) = tokio::io::split(session.tun);

    // Task 1: Local TUN -> SSH Channel
    let mut tun_to_ssh = tokio::spawn(async move {
        let mut packet_buf = vec![0u8; 65536];
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
    let mut ssh_to_tun = tokio::spawn(async move {
        let mut frame_buf = vec![0u8; 65536];
        loop {
            let n = match channel_read.read(&mut frame_buf).await {
                Ok(0) => {
                    warn!("SSH TUN channel closed by remote (EOF)");
                    break;
                }
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

    tokio::select! {
        res = &mut tun_to_ssh => {
            ssh_to_tun.abort();
            match res {
                Ok(_) => warn!("TUN to SSH forwarding task completed"),
                Err(e) => error!("TUN to SSH forwarding task panicked: {}", e),
            }
        }
        res = &mut ssh_to_tun => {
            tun_to_ssh.abort();
            match res {
                Ok(_) => warn!("SSH to TUN forwarding task completed"),
                Err(e) => error!("SSH to TUN forwarding task panicked: {}", e),
            }
        }
    }

    Err(anyhow::anyhow!("TUN forwarding session terminated"))
}
