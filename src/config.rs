use clap::Parser;
use std::path::PathBuf;
use anyhow::{anyhow, Result};
use ssh2_config::SshConfig;
use std::fs::File;
use std::io::BufReader;

#[derive(Parser, Debug, Clone)]
#[command(name = "sshtun", author, version, about = "Pure Rust SSH tunnel manager with TUN support and auto-reconnect")]
pub struct CliArgs {
    /// Remote host or SSH alias, optionally with user/port: [user@]host[:port]
    pub destination: String,

    /// SSH server port override
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    /// Identity key file(s)
    #[arg(short = 'i', long = "identity")]
    pub identity: Vec<PathBuf>,

    /// Local port forwarding: [bind_address:]port:host:hostport
    #[arg(short = 'L', long = "local-forward")]
    pub local_forwards: Vec<String>,

    /// Remote port forwarding: [bind_address:]port:host:hostport
    #[arg(short = 'R', long = "remote-forward")]
    pub remote_forwards: Vec<String>,

    /// Dynamic SOCKS5 port forwarding: [bind_address:]port
    #[arg(short = 'D', long = "dynamic-forward")]
    pub dynamic_forwards: Vec<String>,

    /// TUN device tunnel: local_tun[:remote_tun] (e.g. 0:0, any:any, tun0:tun1)
    #[arg(short = 'w', long = "tun-forward")]
    pub tun_forward: Option<String>,

    /// Local TUN IP address (e.g. 192.168.100.1 or 192.168.100.1/32)
    #[arg(long = "local-tun-addr")]
    pub local_tun_addr: Option<String>,

    /// Remote TUN IP address (e.g. 192.168.100.2 or 192.168.100.2/32)
    #[arg(long = "remote-tun-addr")]
    pub remote_tun_addr: Option<String>,

    /// Shell command executed locally after tunnel is established
    #[arg(long = "local-post-up")]
    pub local_post_up: Option<String>,

    /// Shell command executed on remote server after tunnel is established
    #[arg(long = "remote-post-up")]
    pub remote_post_up: Option<String>,

    /// Do not execute remote shell command (tunnel mode)
    #[arg(short = 'N', long = "no-shell", default_value_t = true)]
    pub no_shell: bool,

    /// Seconds to wait before reconnecting on disconnect
    #[arg(long = "reconnect-interval", default_value_t = 5)]
    pub reconnect_interval: u64,

    /// Seconds between link keepalive ping checks
    #[arg(long = "keepalive-interval", default_value_t = 10)]
    pub keepalive_interval: u64,

    /// Max failed keepalive pings before declaring link dead
    #[arg(long = "keepalive-max", default_value_t = 3)]
    pub keepalive_max: u32,

    /// Verbose logging output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunForwardSpec {
    pub local_tun: String,
    pub remote_tun: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub host: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub local_forwards: Vec<LocalForwardSpec>,
    pub remote_forwards: Vec<RemoteForwardSpec>,
    pub dynamic_forwards: Vec<DynamicForwardSpec>,
    pub tun_forward: Option<TunForwardSpec>,
    pub local_tun_addr: Option<String>,
    pub remote_tun_addr: Option<String>,
    pub local_post_up: Option<String>,
    pub remote_post_up: Option<String>,
    pub reconnect_interval: u64,
    pub keepalive_interval: u64,
    pub keepalive_max: u32,
}

pub fn parse_local_forward(spec: &str) -> Result<LocalForwardSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => Ok(LocalForwardSpec {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: parts[0].parse()?,
            target_host: parts[1].to_string(),
            target_port: parts[2].parse()?,
        }),
        4 => Ok(LocalForwardSpec {
            bind_addr: parts[0].to_string(),
            bind_port: parts[1].parse()?,
            target_host: parts[2].to_string(),
            target_port: parts[3].parse()?,
        }),
        _ => Err(anyhow!("Invalid local forward spec '{}', expected [bind_addr:]port:host:hostport", spec)),
    }
}

pub fn parse_remote_forward(spec: &str) -> Result<RemoteForwardSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => Ok(RemoteForwardSpec {
            bind_addr: "0.0.0.0".to_string(),
            bind_port: parts[0].parse()?,
            target_host: parts[1].to_string(),
            target_port: parts[2].parse()?,
        }),
        4 => Ok(RemoteForwardSpec {
            bind_addr: parts[0].to_string(),
            bind_port: parts[1].parse()?,
            target_host: parts[2].to_string(),
            target_port: parts[3].parse()?,
        }),
        _ => Err(anyhow!("Invalid remote forward spec '{}', expected [bind_addr:]port:host:hostport", spec)),
    }
}

pub fn parse_dynamic_forward(spec: &str) -> Result<DynamicForwardSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        1 => Ok(DynamicForwardSpec {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: parts[0].parse()?,
        }),
        2 => Ok(DynamicForwardSpec {
            bind_addr: parts[0].to_string(),
            bind_port: parts[1].parse()?,
        }),
        _ => Err(anyhow!("Invalid dynamic forward spec '{}', expected [bind_addr:]port", spec)),
    }
}

pub fn parse_tun_forward(spec: &str) -> Result<TunForwardSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        1 => Ok(TunForwardSpec {
            local_tun: parts[0].to_string(),
            remote_tun: parts[0].to_string(),
        }),
        2 => Ok(TunForwardSpec {
            local_tun: parts[0].to_string(),
            remote_tun: parts[1].to_string(),
        }),
        _ => Err(anyhow!("Invalid TUN spec '{}', expected local_tun[:remote_tun]", spec)),
    }
}

impl ResolvedConfig {
    pub fn from_args(args: CliArgs) -> Result<Self> {
        let mut target_user = None;
        let mut target_host = args.destination.clone();
        let mut target_port = args.port;

        // Parse user@host:port format if present
        if let Some(at_idx) = target_host.find('@') {
            target_user = Some(target_host[..at_idx].to_string());
            target_host = target_host[at_idx + 1..].to_string();
        }

        if let Some(colon_idx) = target_host.rfind(':') {
            if let Ok(p) = target_host[colon_idx + 1..].parse::<u16>() {
                if target_port.is_none() {
                    target_port = Some(p);
                }
                target_host = target_host[..colon_idx].to_string();
            }
        }

        // Try reading ~/.ssh/config
        let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let ssh_config_path = home_dir.join(".ssh").join("config");

        let mut ssh_config_entry = None;
        if ssh_config_path.exists() {
            if let Ok(file) = File::open(&ssh_config_path) {
                let mut reader = BufReader::new(file);
                if let Ok(config) = SshConfig::default().parse(&mut reader, ssh2_config::ParseRule::ALLOW_UNKNOWN_FIELDS) {
                    ssh_config_entry = Some(config.query(&target_host));
                }
            }
        }

        let hostname = ssh_config_entry
            .as_ref()
            .and_then(|e| e.host_name.clone())
            .unwrap_or_else(|| target_host.clone());

        let user = target_user
            .or_else(|| ssh_config_entry.as_ref().and_then(|e| e.user.clone()))
            .unwrap_or_else(|| {
                std::env::var("USER").unwrap_or_else(|_| "root".to_string())
            });

        let port = target_port
            .or_else(|| ssh_config_entry.as_ref().and_then(|e| e.port))
            .unwrap_or(22);

        let mut identity_files = args.identity;

        // Add identity files from ssh config if none provided via CLI
        if identity_files.is_empty() {
            if let Some(ref entry) = ssh_config_entry {
                if let Some(ref config_ids) = entry.identity_file {
                    for p in config_ids {
                        if p.exists() {
                            identity_files.push(p.clone());
                        } else if let Ok(stripped) = p.strip_prefix("~") {
                            let expanded = home_dir.join(stripped.to_string_lossy().trim_start_matches('/'));
                            if expanded.exists() {
                                identity_files.push(expanded);
                            }
                        }
                    }
                }
            }
        }

        // Add default identity files if still empty
        if identity_files.is_empty() {
            let default_keys = vec![
                home_dir.join(".ssh").join("id_ed25519"),
                home_dir.join(".ssh").join("id_rsa"),
                home_dir.join(".ssh").join("id_ecdsa"),
                home_dir.join(".ssh").join("id_dsa"),
            ];
            for k in default_keys {
                if k.exists() {
                    identity_files.push(k);
                }
            }
        }

        let mut local_forwards = Vec::new();
        for spec in &args.local_forwards {
            local_forwards.push(parse_local_forward(spec)?);
        }

        let mut remote_forwards = Vec::new();
        for spec in &args.remote_forwards {
            remote_forwards.push(parse_remote_forward(spec)?);
        }

        let mut dynamic_forwards = Vec::new();
        for spec in &args.dynamic_forwards {
            dynamic_forwards.push(parse_dynamic_forward(spec)?);
        }

        let tun_forward = match args.tun_forward {
            Some(ref spec) => Some(parse_tun_forward(spec)?),
            None => None,
        };

        Ok(ResolvedConfig {
            host: target_host,
            hostname,
            port,
            user,
            identity_files,
            local_forwards,
            remote_forwards,
            dynamic_forwards,
            tun_forward,
            local_tun_addr: args.local_tun_addr,
            remote_tun_addr: args.remote_tun_addr,
            local_post_up: args.local_post_up,
            remote_post_up: args.remote_post_up,
            reconnect_interval: args.reconnect_interval,
            keepalive_interval: args.keepalive_interval,
            keepalive_max: args.keepalive_max,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_forward() {
        let f1 = parse_local_forward("8080:10.0.0.1:80").unwrap();
        assert_eq!(
            f1,
            LocalForwardSpec {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 8080,
                target_host: "10.0.0.1".to_string(),
                target_port: 80,
            }
        );

        let f2 = parse_local_forward("0.0.0.0:8080:10.0.0.1:80").unwrap();
        assert_eq!(
            f2,
            LocalForwardSpec {
                bind_addr: "0.0.0.0".to_string(),
                bind_port: 8080,
                target_host: "10.0.0.1".to_string(),
                target_port: 80,
            }
        );
    }

    #[test]
    fn test_parse_remote_forward() {
        let r1 = parse_remote_forward("2222:127.0.0.1:22").unwrap();
        assert_eq!(
            r1,
            RemoteForwardSpec {
                bind_addr: "0.0.0.0".to_string(),
                bind_port: 2222,
                target_host: "127.0.0.1".to_string(),
                target_port: 22,
            }
        );
    }

    #[test]
    fn test_parse_dynamic_forward() {
        let d1 = parse_dynamic_forward("1080").unwrap();
        assert_eq!(
            d1,
            DynamicForwardSpec {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 1080,
            }
        );

        let d2 = parse_dynamic_forward("0.0.0.0:1080").unwrap();
        assert_eq!(
            d2,
            DynamicForwardSpec {
                bind_addr: "0.0.0.0".to_string(),
                bind_port: 1080,
            }
        );
    }

    #[test]
    fn test_parse_tun_forward() {
        let t1 = parse_tun_forward("0:0").unwrap();
        assert_eq!(
            t1,
            TunForwardSpec {
                local_tun: "0".to_string(),
                remote_tun: "0".to_string(),
            }
        );

        let t2 = parse_tun_forward("any:any").unwrap();
        assert_eq!(
            t2,
            TunForwardSpec {
                local_tun: "any".to_string(),
                remote_tun: "any".to_string(),
            }
        );
    }
}
