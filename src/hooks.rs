use crate::config::ResolvedConfig;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use tokio::io::AsyncReadExt;
use tokio::process::Command as LocalCommand;
use tracing::{error, info, warn};

pub async fn run_local_post_up(cmd: &str) -> anyhow::Result<()> {
    info!("Running local post-up command: '{}'", cmd);
    let status = LocalCommand::new("sh").arg("-c").arg(cmd).status().await?;

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
    let _ = stream.close().await;

    Ok(output)
}

pub async fn run_post_up_hooks(
    handle: &Handle<ClientHandler>,
    config: &ResolvedConfig,
) -> anyhow::Result<()> {
    if let Some(ref tun) = config.tun_forward {
        if let Some(id) = tun.auto_id {
            if let (Some(ref remote_ip), Some(ref local_ip)) =
                (&config.remote_tun_addr, &config.local_tun_addr)
            {
                let fwmark = (id as u32) << 16;
                let tun_dev = format!("tun2222{}", id);
                let remote_ip_clean = remote_ip.trim_end_matches("/32");
                let local_ip_clean = local_ip.trim_end_matches("/32");

                let auto_setup_cmd = build_auto_setup_cmd(
                    config,
                    id,
                    &tun_dev,
                    fwmark,
                    remote_ip_clean,
                    local_ip_clean,
                );

                let fw_desc = if config.use_iptables { "iptables" } else { "nftables" };
                info!("Configuring auto TUN routing and {fw_desc} firewall rules on remote server ({tun_dev})...");
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
        } else if let (Some(ref remote_ip), Some(ref local_ip)) =
            (&config.remote_tun_addr, &config.local_tun_addr)
        {
            let remote_tun_name = if tun.remote_tun != "any" {
                if tun.remote_tun.starts_with("tun") {
                    tun.remote_tun.clone()
                } else {
                    format!("tun{}", tun.remote_tun)
                }
            } else {
                "tun0".to_string()
            };

            let ipv6_addr_cmd = if let (Some(ref remote_ip6), Some(ref local_ip6)) =
                (&config.remote_tun_addr6, &config.local_tun_addr6)
            {
                let remote_clean = remote_ip6.trim_end_matches("/127").trim_end_matches("/128");
                let local_clean = local_ip6.trim_end_matches("/127").trim_end_matches("/128");
                format!(
                    "; ip addr replace {}/127 peer {} dev {} 2>/dev/null || ip addr add {}/127 peer {} dev {} 2>/dev/null || true",
                    remote_clean, local_clean, remote_tun_name, remote_clean, local_clean, remote_tun_name
                )
            } else {
                String::new()
            };

            let auto_remote_cmd = format!(
                "ip addr replace {}/32 peer {} dev {} 2>/dev/null || ip addr add {}/32 peer {} dev {} 2>/dev/null || true{}; ip link set {} up",
                remote_ip.trim_end_matches("/32"),
                local_ip.trim_end_matches("/32"),
                remote_tun_name,
                remote_ip.trim_end_matches("/32"),
                local_ip.trim_end_matches("/32"),
                remote_tun_name,
                ipv6_addr_cmd,
                remote_tun_name
            );
            info!(
                "Configuring remote TUN interface via SSH: {}",
                auto_remote_cmd
            );
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

    // Determine local and remote TUN interface names if TUN is configured
    let (local_tun_name, remote_tun_name) = match config.tun_forward {
        Some(ref tun) => {
            let local_name = if tun.local_tun == "any" {
                "tun0".to_string()
            } else if tun.local_tun.starts_with("tun") {
                tun.local_tun.clone()
            } else {
                format!("tun{}", tun.local_tun)
            };
            let remote_name = if tun.remote_tun == "any" {
                "tun0".to_string()
            } else if tun.remote_tun.starts_with("tun") {
                tun.remote_tun.clone()
            } else {
                format!("tun{}", tun.remote_tun)
            };
            (Some(local_name), Some(remote_name))
        }
        None => (None, None),
    };

    // Run explicit remote-post-up if provided
    if let Some(ref remote_cmd) = config.remote_post_up {
        let cmd_expanded = expand_hook_cmd(remote_cmd, remote_tun_name.as_deref());
        match run_remote_command(handle, &cmd_expanded).await {
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
        let cmd_expanded = expand_hook_cmd(local_cmd, local_tun_name.as_deref());
        if let Err(e) = run_local_post_up(&cmd_expanded).await {
            error!("Local post-up hook error: {}", e);
        }
    }

    Ok(())
}

pub fn expand_hook_cmd(cmd: &str, iface: Option<&str>) -> String {
    if let Some(name) = iface {
        cmd.replace("%i", name)
    } else {
        cmd.to_string()
    }
}

pub async fn run_cleanup_hooks(
    handle: &Handle<ClientHandler>,
    config: &ResolvedConfig,
) -> anyhow::Result<()> {
    if let Some(ref tun) = config.tun_forward {
        if let Some(id) = tun.auto_id {
            let fwmark = (id as u32) << 16;
            let tun_dev = format!("tun2222{}", id);
            let cleanup_cmd = build_auto_cleanup_cmd(config, id, &tun_dev, fwmark);
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

pub fn build_auto_setup_cmd(
    config: &ResolvedConfig,
    id: u16,
    tun_dev: &str,
    fwmark: u32,
    remote_ip_clean: &str,
    local_ip_clean: &str,
) -> String {
    let mut ipv6_cmds = String::new();
    let mut nft_v6_masq = String::new();
    let mut iptables_v6_rules = String::new();

    if let (Some(ref remote_ip6), Some(ref local_ip6)) =
        (&config.remote_tun_addr6, &config.local_tun_addr6)
    {
        let remote_ip6_clean = remote_ip6.trim_end_matches("/127").trim_end_matches("/128");
        let local_ip6_clean = local_ip6.trim_end_matches("/127").trim_end_matches("/128");
        ipv6_cmds = format!(
            "sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true; \
             ip addr replace {remote_ip6}/127 peer {local_ip6} dev {tun_dev} 2>/dev/null || ip addr add {remote_ip6}/127 peer {local_ip6} dev {tun_dev} 2>/dev/null || true; \
             ip -6 rule del fwmark {fwmark}/0xffff0000 lookup 2222{id} 2>/dev/null || true; \
             ip -6 rule add fwmark {fwmark}/0xffff0000 lookup 2222{id} prio 5; \
             ip -6 route replace default dev {tun_dev} table 2222{id}; ",
            remote_ip6 = remote_ip6_clean,
            local_ip6 = local_ip6_clean,
            tun_dev = tun_dev,
            fwmark = fwmark,
            id = id,
        );
        nft_v6_masq = format!(
            "oifname != \"{tun_dev}\" ip6 saddr {local_ip6} masquerade; ",
            tun_dev = tun_dev,
            local_ip6 = local_ip6_clean,
        );
        iptables_v6_rules = format!(
            "ip6tables -t mangle -D PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
             ip6tables -t mangle -F sshtun_pre_{id} 2>/dev/null || true; \
             ip6tables -t mangle -X sshtun_pre_{id} 2>/dev/null || true; \
             ip6tables -t mangle -N sshtun_pre_{id} 2>/dev/null || true; \
             ip6tables -t mangle -A sshtun_pre_{id} -i {tun_dev} -m conntrack --ctstate NEW -j CONNMARK --set-mark {fwmark}/0xffff0000 2>/dev/null || true; \
             ip6tables -t mangle -A sshtun_pre_{id} ! -i {tun_dev} -m connmark --mark {fwmark}/0xffff0000 -j CONNMARK --restore-mark --mask 0xffff0000 2>/dev/null || true; \
             ip6tables -t mangle -A PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
             ip6tables -t mangle -D OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
             ip6tables -t mangle -F sshtun_out_{id} 2>/dev/null || true; \
             ip6tables -t mangle -X sshtun_out_{id} 2>/dev/null || true; \
             ip6tables -t mangle -N sshtun_out_{id} 2>/dev/null || true; \
             ip6tables -t mangle -A sshtun_out_{id} -m connmark --mark {fwmark}/0xffff0000 -j CONNMARK --restore-mark --mask 0xffff0000 2>/dev/null || true; \
             ip6tables -t mangle -A OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
             ip6tables -t nat -D POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; \
             ip6tables -t nat -F sshtun_post_{id} 2>/dev/null || true; \
             ip6tables -t nat -X sshtun_post_{id} 2>/dev/null || true; \
             ip6tables -t nat -N sshtun_post_{id} 2>/dev/null || true; \
             ip6tables -t nat -A sshtun_post_{id} ! -o {tun_dev} -s {local_ip6} -j MASQUERADE 2>/dev/null || true; \
             ip6tables -t nat -A POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; ",
            id = id,
            tun_dev = tun_dev,
            fwmark = fwmark,
            local_ip6 = local_ip6_clean,
        );
    }

    let fw_setup = if config.use_iptables {
        format!(
            "iptables -t mangle -D PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
             iptables -t mangle -F sshtun_pre_{id} 2>/dev/null || true; \
             iptables -t mangle -X sshtun_pre_{id} 2>/dev/null || true; \
             iptables -t mangle -N sshtun_pre_{id} 2>/dev/null || true; \
             iptables -t mangle -A sshtun_pre_{id} -i {tun_dev} -m conntrack --ctstate NEW -j CONNMARK --set-mark {fwmark}/0xffff0000 2>/dev/null || true; \
             iptables -t mangle -A sshtun_pre_{id} ! -i {tun_dev} -m connmark --mark {fwmark}/0xffff0000 -j CONNMARK --restore-mark --mask 0xffff0000 2>/dev/null || true; \
             iptables -t mangle -A PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
             iptables -t mangle -D OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
             iptables -t mangle -F sshtun_out_{id} 2>/dev/null || true; \
             iptables -t mangle -X sshtun_out_{id} 2>/dev/null || true; \
             iptables -t mangle -N sshtun_out_{id} 2>/dev/null || true; \
             iptables -t mangle -A sshtun_out_{id} -m connmark --mark {fwmark}/0xffff0000 -j CONNMARK --restore-mark --mask 0xffff0000 2>/dev/null || true; \
             iptables -t mangle -A OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
             iptables -t nat -D POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; \
             iptables -t nat -F sshtun_post_{id} 2>/dev/null || true; \
             iptables -t nat -X sshtun_post_{id} 2>/dev/null || true; \
             iptables -t nat -N sshtun_post_{id} 2>/dev/null || true; \
             iptables -t nat -A sshtun_post_{id} ! -o {tun_dev} -s {local_ip} -j MASQUERADE 2>/dev/null || true; \
             iptables -t nat -A POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; \
             {iptables_v6_rules}",
            id = id,
            tun_dev = tun_dev,
            fwmark = fwmark,
            local_ip = local_ip_clean,
            iptables_v6_rules = iptables_v6_rules,
        )
    } else {
        format!(
            "nft 'add table inet sshtun{id}; delete table inet sshtun{id}; table inet sshtun{id} {{ chain prerouting {{ type filter hook prerouting priority mangle; policy accept; iifname \"{tun_dev}\" ct state new ct mark set {fwmark}; iifname != \"{tun_dev}\" ct mark {fwmark} meta mark set ct mark; }}; chain output {{ type route hook output priority mangle; policy accept; ct mark {fwmark} meta mark set ct mark; }}; chain postrouting {{ type nat hook postrouting priority srcnat; policy accept; oifname != \"{tun_dev}\" ip saddr {local_ip} masquerade; {nft_v6_masq}}}; }}'; ",
            id = id,
            tun_dev = tun_dev,
            fwmark = fwmark,
            local_ip = local_ip_clean,
            nft_v6_masq = nft_v6_masq,
        )
    };

    format!(
        "for i in $(seq 1 50); do if ip link show dev {tun_dev} >/dev/null 2>&1; then break; fi; sleep 0.1; done; \
         sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true; \
         ip addr replace {remote_ip}/32 peer {local_ip} dev {tun_dev} 2>/dev/null || ip addr add {remote_ip}/32 peer {local_ip} dev {tun_dev} 2>/dev/null || true; \
         ip link set dev {tun_dev} up 2>/dev/null || true; \
         {ipv6_cmds}\
         {fw_setup}\
         ip rule del fwmark {fwmark}/0xffff0000 lookup 2222{id} 2>/dev/null || true; \
         ip rule add fwmark {fwmark}/0xffff0000 lookup 2222{id} prio 5; \
         ip route replace default dev {tun_dev} table 2222{id}",
        tun_dev = tun_dev,
        id = id,
        fwmark = fwmark,
        remote_ip = remote_ip_clean,
        local_ip = local_ip_clean,
        ipv6_cmds = ipv6_cmds,
        fw_setup = fw_setup,
    )
}

pub fn build_auto_cleanup_cmd(
    config: &ResolvedConfig,
    id: u16,
    tun_dev: &str,
    fwmark: u32,
) -> String {
    let iptables_cleanup = format!(
        "iptables -t mangle -D PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
         iptables -t mangle -F sshtun_pre_{id} 2>/dev/null || true; \
         iptables -t mangle -X sshtun_pre_{id} 2>/dev/null || true; \
         iptables -t mangle -D OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
         iptables -t mangle -F sshtun_out_{id} 2>/dev/null || true; \
         iptables -t mangle -X sshtun_out_{id} 2>/dev/null || true; \
         iptables -t nat -D POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; \
         iptables -t nat -F sshtun_post_{id} 2>/dev/null || true; \
         iptables -t nat -X sshtun_post_{id} 2>/dev/null || true; \
         ip6tables -t mangle -D PREROUTING -j sshtun_pre_{id} 2>/dev/null || true; \
         ip6tables -t mangle -F sshtun_pre_{id} 2>/dev/null || true; \
         ip6tables -t mangle -X sshtun_pre_{id} 2>/dev/null || true; \
         ip6tables -t mangle -D OUTPUT -j sshtun_out_{id} 2>/dev/null || true; \
         ip6tables -t mangle -F sshtun_out_{id} 2>/dev/null || true; \
         ip6tables -t mangle -X sshtun_out_{id} 2>/dev/null || true; \
         ip6tables -t nat -D POSTROUTING -j sshtun_post_{id} 2>/dev/null || true; \
         ip6tables -t nat -F sshtun_post_{id} 2>/dev/null || true; \
         ip6tables -t nat -X sshtun_post_{id} 2>/dev/null || true; ",
        id = id,
    );

    let fw_cleanup = if config.use_iptables {
        iptables_cleanup
    } else {
        format!("nft 'add table inet sshtun{id}; delete table inet sshtun{id}' 2>/dev/null || true; ", id = id)
    };

    format!(
        "{fw_cleanup}\
         ip rule del fwmark {fwmark}/0xffff0000 lookup 2222{id} 2>/dev/null || true; \
         ip rule del fwmark {fwmark}/0xffff0000 lookup {id} 2>/dev/null || true; \
         ip -6 rule del fwmark {fwmark}/0xffff0000 lookup 2222{id} 2>/dev/null || true; \
         ip -6 rule del fwmark {fwmark}/0xffff0000 lookup {id} 2>/dev/null || true; \
         ip route del default dev {tun_dev} table 2222{id} 2>/dev/null || true; \
         ip route del default dev {tun_dev} table {id} 2>/dev/null || true; \
         ip -6 route del default dev {tun_dev} table 2222{id} 2>/dev/null || true; \
         ip -6 route del default dev {tun_dev} table {id} 2>/dev/null || true; \
         ip link set dev {tun_dev} down 2>/dev/null || true; \
         ip link delete dev {tun_dev} 2>/dev/null || true",
        fw_cleanup = fw_cleanup,
        id = id,
        fwmark = fwmark,
        tun_dev = tun_dev,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use clap::Parser;

    #[test]
    fn test_expand_hook_cmd() {
        let cmd = "ip route add 10.3.1.0/24 dev %i table 5";
        assert_eq!(
            expand_hook_cmd(cmd, Some("tun28799")),
            "ip route add 10.3.1.0/24 dev tun28799 table 5"
        );

        let multi = "ip link set %i up && ip route add 10.0.0.0/8 dev %i";
        assert_eq!(
            expand_hook_cmd(multi, Some("tun0")),
            "ip link set tun0 up && ip route add 10.0.0.0/8 dev tun0"
        );

        assert_eq!(
            expand_hook_cmd(cmd, None),
            "ip route add 10.3.1.0/24 dev %i table 5"
        );
    }

    #[test]
    fn test_build_auto_setup_cmd_nftables_vs_iptables() {
        let args_nft = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto"]).unwrap();
        let config_nft = ResolvedConfig::from_args(args_nft).unwrap();
        let cmd_nft = build_auto_setup_cmd(&config_nft, 1234, "tun22221234", 1234 << 16, "169.254.1.2", "169.254.1.1");

        assert!(cmd_nft.contains("nft 'add table inet sshtun1234;"));
        assert!(!cmd_nft.contains("iptables"));
        assert!(!cmd_nft.contains("ip6tables"));

        let args_ip = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto", "--use-iptables"]).unwrap();
        let config_ip = ResolvedConfig::from_args(args_ip).unwrap();
        let cmd_ip = build_auto_setup_cmd(&config_ip, 1234, "tun22221234", 1234 << 16, "169.254.1.2", "169.254.1.1");

        assert!(!cmd_ip.contains("nft"));
        assert!(cmd_ip.contains("iptables -t mangle -A sshtun_pre_1234 -i tun22221234 -m conntrack --ctstate NEW -j CONNMARK --set-mark"));
        assert!(cmd_ip.contains("iptables -t nat -A sshtun_post_1234 ! -o tun22221234 -s 169.254.1.1 -j MASQUERADE"));
        assert!(cmd_ip.contains("ip6tables -t mangle -A sshtun_pre_1234"));
        assert!(cmd_ip.contains("ip6tables -t nat -A sshtun_post_1234"));
    }

    #[test]
    fn test_build_auto_setup_cmd_iptables_ipv4_only() {
        let args_ip = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto", "--use-iptables"]).unwrap();
        let mut config_ip = ResolvedConfig::from_args(args_ip).unwrap();
        config_ip.local_tun_addr6 = None;
        config_ip.remote_tun_addr6 = None;

        let cmd_ip = build_auto_setup_cmd(&config_ip, 5678, "tun22225678", 5678 << 16, "169.254.1.2", "169.254.1.1");
        assert!(!cmd_ip.contains("nft"));
        assert!(cmd_ip.contains("iptables -t mangle -A sshtun_pre_5678"));
        assert!(cmd_ip.contains("iptables -t nat -A sshtun_post_5678"));
        assert!(!cmd_ip.contains("ip6tables"));
    }

    #[test]
    fn test_build_auto_cleanup_cmd_nftables_vs_iptables() {
        let args_nft = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto"]).unwrap();
        let config_nft = ResolvedConfig::from_args(args_nft).unwrap();
        let cleanup_nft = build_auto_cleanup_cmd(&config_nft, 1234, "tun22221234", 1234 << 16);

        assert!(cleanup_nft.contains("nft 'add table inet sshtun1234; delete table inet sshtun1234'"));
        assert!(!cleanup_nft.contains("iptables"));

        let args_ip = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto", "--use-iptables"]).unwrap();
        let config_ip = ResolvedConfig::from_args(args_ip).unwrap();
        let cleanup_ip = build_auto_cleanup_cmd(&config_ip, 1234, "tun22221234", 1234 << 16);

        assert!(!cleanup_ip.contains("nft"));
        assert!(cleanup_ip.contains("iptables -t mangle -D PREROUTING -j sshtun_pre_1234"));
        assert!(cleanup_ip.contains("iptables -t nat -X sshtun_post_1234"));
        assert!(cleanup_ip.contains("ip6tables -t mangle -D PREROUTING -j sshtun_pre_1234"));
        assert!(cleanup_ip.contains("ip6tables -t nat -X sshtun_post_1234"));
    }
}
