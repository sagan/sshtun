use clap::Parser;
use std::path::PathBuf;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::BufReader;
use sha2::{Digest, Sha256};

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

    /// TUN device tunnel: local_tun[:remote_tun] (e.g. 0:0, any:any, tun0:tun1) or "auto" / "auto:<id>"
    #[arg(short = 'w', long = "tun-forward", num_args = 0..=1, default_missing_value = "auto")]
    pub tun_forward: Option<String>,

    /// Jump host(s): [user@]host[:port][,...]
    #[arg(short = 'J', long = "jump-host", alias = "proxy-jump", value_delimiter = ',')]
    pub jump_hosts: Vec<String>,

    /// Local TUN IP address (e.g. 192.168.100.1 or 192.168.100.1/32)
    #[arg(long = "local-tun-addr")]
    pub local_tun_addr: Option<String>,

    /// Remote TUN IP address (e.g. 192.168.100.2 or 192.168.100.2/32)
    #[arg(long = "remote-tun-addr")]
    pub remote_tun_addr: Option<String>,

    /// Local TUN IPv6 address (e.g. fd00::1 or fd00::1/127)
    #[arg(long = "local-tun-addr6")]
    pub local_tun_addr6: Option<String>,

    /// Remote TUN IPv6 address (e.g. fd00::2 or fd00::2/127)
    #[arg(long = "remote-tun-addr6")]
    pub remote_tun_addr6: Option<String>,

    /// Shell command executed locally after tunnel is established (supports '%i' for TUN interface name)
    #[arg(long = "local-post-up")]
    pub local_post_up: Option<String>,

    /// Shell command executed on remote server after tunnel is established (supports '%i' for TUN interface name)
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

    /// Netfilter fwmark for created SSH socket (e.g. 0x1000 or 4096)
    #[arg(long = "fwmark", alias = "mark", value_parser = parse_fwmark)]
    pub fwmark: Option<u32>,

    /// Use iptables instead of nftables for remote server firewall rules
    #[arg(long = "use-iptables")]
    pub use_iptables: bool,

    /// Verbose logging output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConnectionConfig {
    pub host: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
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
    pub auto_id: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub host: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub jump_hosts: Vec<HostConnectionConfig>,
    pub local_forwards: Vec<LocalForwardSpec>,
    pub remote_forwards: Vec<RemoteForwardSpec>,
    pub dynamic_forwards: Vec<DynamicForwardSpec>,
    pub tun_forward: Option<TunForwardSpec>,
    pub local_tun_addr: Option<String>,
    pub remote_tun_addr: Option<String>,
    pub local_tun_addr6: Option<String>,
    pub remote_tun_addr6: Option<String>,
    pub local_post_up: Option<String>,
    pub remote_post_up: Option<String>,
    pub reconnect_interval: u64,
    pub keepalive_interval: u64,
    pub keepalive_max: u32,
    pub fwmark: Option<u32>,
    pub use_iptables: bool,
}

pub fn parse_fwmark(s: &str) -> std::result::Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("Invalid hex fwmark '{}': {}", s, e))
    } else {
        s.parse::<u32>().map_err(|e| format!("Invalid fwmark '{}': {}", s, e))
    }
}

fn parse_host_port_pair(s: &str, default_host: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        Ok((h.to_string(), p.parse()?))
    } else {
        Ok((default_host.to_string(), s.parse()?))
    }
}

fn parse_target_pair(s: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = s.rsplit_once(':') {
        Ok((h.to_string(), p.parse()?))
    } else {
        Err(anyhow!("Target must be in host:port format, got '{}'", s))
    }
}

pub fn parse_local_forward(spec: &str) -> Result<LocalForwardSpec> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    if tokens.len() == 1 {
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
    } else if tokens.len() == 2 {
        let (bind_addr, bind_port) = parse_host_port_pair(tokens[0], "127.0.0.1")?;
        let (target_host, target_port) = parse_target_pair(tokens[1])?;
        Ok(LocalForwardSpec {
            bind_addr,
            bind_port,
            target_host,
            target_port,
        })
    } else if tokens.len() == 3 {
        Ok(LocalForwardSpec {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: tokens[0].parse()?,
            target_host: tokens[1].to_string(),
            target_port: tokens[2].parse()?,
        })
    } else if tokens.len() == 4 {
        Ok(LocalForwardSpec {
            bind_addr: tokens[0].to_string(),
            bind_port: tokens[1].parse()?,
            target_host: tokens[2].to_string(),
            target_port: tokens[3].parse()?,
        })
    } else {
        Err(anyhow!("Invalid local forward spec '{}'", spec))
    }
}

pub fn parse_remote_forward(spec: &str) -> Result<RemoteForwardSpec> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    if tokens.len() == 1 {
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
    } else if tokens.len() == 2 {
        let (bind_addr, bind_port) = parse_host_port_pair(tokens[0], "0.0.0.0")?;
        let (target_host, target_port) = parse_target_pair(tokens[1])?;
        Ok(RemoteForwardSpec {
            bind_addr,
            bind_port,
            target_host,
            target_port,
        })
    } else if tokens.len() == 3 {
        Ok(RemoteForwardSpec {
            bind_addr: "0.0.0.0".to_string(),
            bind_port: tokens[0].parse()?,
            target_host: tokens[1].to_string(),
            target_port: tokens[2].parse()?,
        })
    } else if tokens.len() == 4 {
        Ok(RemoteForwardSpec {
            bind_addr: tokens[0].to_string(),
            bind_port: tokens[1].parse()?,
            target_host: tokens[2].to_string(),
            target_port: tokens[3].parse()?,
        })
    } else {
        Err(anyhow!("Invalid remote forward spec '{}'", spec))
    }
}

pub fn parse_dynamic_forward(spec: &str) -> Result<DynamicForwardSpec> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    if tokens.len() == 1 {
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
    } else if tokens.len() == 2 {
        Ok(DynamicForwardSpec {
            bind_addr: tokens[0].to_string(),
            bind_port: tokens[1].parse()?,
        })
    } else {
        Err(anyhow!("Invalid dynamic forward spec '{}'", spec))
    }
}

pub fn parse_tun_forward(spec: &str) -> Result<TunForwardSpec> {
    let trimmed = spec.trim();
    if trimmed == "auto" {
        return Ok(TunForwardSpec {
            local_tun: "auto".to_string(),
            remote_tun: "auto".to_string(),
            auto_id: None,
        });
    }
    if let Some(id_str) = trimmed.strip_prefix("auto:") {
        let id = id_str
            .trim()
            .parse::<u16>()
            .map_err(|e| anyhow!("Invalid auto TUN id '{}': {}", id_str, e))?;
        return Ok(TunForwardSpec {
            local_tun: format!("tun2222{}", id),
            remote_tun: format!("tun2222{}", id),
            auto_id: Some(id),
        });
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() == 1 {
        let parts: Vec<&str> = trimmed.split(':').collect();
        match parts.len() {
            1 => Ok(TunForwardSpec {
                local_tun: parts[0].to_string(),
                remote_tun: parts[0].to_string(),
                auto_id: None,
            }),
            2 => Ok(TunForwardSpec {
                local_tun: parts[0].to_string(),
                remote_tun: parts[1].to_string(),
                auto_id: None,
            }),
            _ => Err(anyhow!("Invalid TUN spec '{}', expected local_tun[:remote_tun] or 'auto'", spec)),
        }
    } else if tokens.len() == 2 {
        Ok(TunForwardSpec {
            local_tun: tokens[0].to_string(),
            remote_tun: tokens[1].to_string(),
            auto_id: None,
        })
    } else {
        Err(anyhow!("Invalid TUN spec '{}'", spec))
    }
}

fn get_local_device_info() -> String {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(host) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(host) = std::env::var("HOSTNAME") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::env::var("USER").unwrap_or_else(|_| "localhost".to_string())
}

fn get_local_network_info() -> String {
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                let iface = fields[0];
                let gateway = fields[2];
                let mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                return format!("{}:{}:{}", iface, gateway, mac);
            }
        }
    }
    String::new()
}

pub fn generate_auto_tun_id(host: &str, port: u16) -> (u16, String, String) {
    let device_info = get_local_device_info();
    let network_info = get_local_network_info();

    let mut hasher = Sha256::new();
    hasher.update(host.as_bytes());
    hasher.update(b":");
    hasher.update(port.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(device_info.as_bytes());
    hasher.update(b"|");
    hasher.update(network_info.as_bytes());
    let hash = hasher.finalize();

    let raw_id = u16::from_be_bytes([hash[0], hash[1]]);
    // Safe link-local bounds (RFC 3927: 169.254.0.0/16 excluding 0.x and 255.x)
    // 254 * 127 = 32258 disjoint pairs
    let pair_idx = (raw_id as u32) % (254 * 127);
    let x = ((pair_idx / 127) + 1) as u16; // 1..=254
    let y = (((pair_idx % 127) * 2) + 1) as u16; // 1, 3, 5, ..., 253 (odd)
    let id = (x << 8) | y; // 16-bit number: lower bits of local IP will be exactly id

    let local_ip = format!("169.254.{}.{}", id >> 8, id & 0xff);
    let remote_ip = format!("169.254.{}.{}", (id + 1) >> 8, (id + 1) & 0xff);

    (id, local_ip, remote_ip)
}

pub fn derive_auto_tun_ipv6(id: u16) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(id.to_be_bytes());
    let hash = hasher.finalize();

    let mut local_bytes = [0u8; 16];
    local_bytes[0] = 0xfd; // IPv6 ULA fd00::/8 prefix
    local_bytes[1..15].copy_from_slice(&hash[0..14]); // 112 bits from hash
    local_bytes[15] = hash[14] & 0xfe; // high 7 bits from hash (112 + 7 = 119 subnet bits); bit 0 is 0 for local

    let mut remote_bytes = local_bytes;
    remote_bytes[15] |= 1; // bit 0 is 1 for remote

    (
        std::net::Ipv6Addr::from(local_bytes).to_string(),
        std::net::Ipv6Addr::from(remote_bytes).to_string(),
    )
}

#[derive(Debug, Default, Clone)]
pub struct ExtractedSshConfig {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub dynamic_forwards: Vec<String>,
    pub tun_forward: Option<String>,
    pub proxy_jump: Option<String>,
}

pub fn parse_ssh_config_file_rec(
    path: &std::path::Path,
    target_host: &str,
    extracted: &mut ExtractedSshConfig,
    visited_files: &mut std::collections::HashSet<PathBuf>,
) {
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };
    if !visited_files.insert(canonical) {
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(file);
    let mut in_matching_section = true;

    for line in std::io::BufRead::lines(reader).flatten() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line_content = if let Some(idx) = trimmed.find('#') {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        let mut parts = Vec::new();
        if let Some((key, val)) = line_content.split_once('=') {
            parts.push(key.trim());
            for p in val.split_whitespace() {
                parts.push(p.trim());
            }
        } else {
            for p in line_content.split_whitespace() {
                parts.push(p.trim());
            }
        }

        if parts.is_empty() {
            continue;
        }

        let key = parts[0].to_lowercase();
        let args = &parts[1..];

        if key == "host" {
            if args.is_empty() {
                in_matching_section = false;
            } else {
                let mut matched = false;
                let mut negated_match = false;
                for pat in args {
                    let (pattern, is_neg) = if let Some(stripped) = pat.strip_prefix('!') {
                        (stripped, true)
                    } else {
                        (*pat, false)
                    };
                    let is_match = ssh2_config::HostClause::new(pattern.to_string(), false).intersects(target_host);
                    if is_match {
                        if is_neg {
                            negated_match = true;
                            break;
                        } else {
                            matched = true;
                        }
                    }
                }
                in_matching_section = matched && !negated_match;
            }
            continue;
        }

        if key == "match" {
            in_matching_section = parse_match_directive(args, target_host);
            continue;
        }

        if !in_matching_section {
            continue;
        }

        match key.as_str() {
            "hostname" => {
                if extracted.hostname.is_none() && !args.is_empty() {
                    extracted.hostname = Some(args[0].to_string());
                }
            }
            "user" => {
                if extracted.user.is_none() && !args.is_empty() {
                    extracted.user = Some(args[0].to_string());
                }
            }
            "port" => {
                if extracted.port.is_none() && !args.is_empty() {
                    if let Ok(p) = args[0].parse::<u16>() {
                        extracted.port = Some(p);
                    }
                }
            }
            "identityfile" => {
                if !args.is_empty() {
                    let home = dirs::home_dir();
                    for arg in args {
                        let path_str = arg.trim_matches('"');
                        let path_buf = if path_str.starts_with("~/") {
                            if let Some(ref h) = home {
                                h.join(&path_str[2..])
                            } else {
                                PathBuf::from(path_str)
                            }
                        } else {
                            PathBuf::from(path_str)
                        };
                        extracted.identity_files.push(path_buf);
                    }
                }
            }
            "localforward" => {
                if !args.is_empty() {
                    extracted.local_forwards.push(args.join(" "));
                }
            }
            "remoteforward" => {
                if !args.is_empty() {
                    extracted.remote_forwards.push(args.join(" "));
                }
            }
            "dynamicforward" => {
                if !args.is_empty() {
                    extracted.dynamic_forwards.push(args.join(" "));
                }
            }
            "tunneldevice" | "tunnel" => {
                if extracted.tun_forward.is_none() && !args.is_empty() {
                    extracted.tun_forward = Some(args.join(" "));
                }
            }
            "proxyjump" => {
                if extracted.proxy_jump.is_none() && !args.is_empty() {
                    extracted.proxy_jump = Some(args.join(" "));
                }
            }
            "include" => {
                for arg in args {
                    let pattern = arg.trim_matches('"');
                    let expanded_pattern = if pattern.starts_with("~/") {
                        if let Some(ref h) = dirs::home_dir() {
                            h.join(&pattern[2..]).to_string_lossy().to_string()
                        } else {
                            pattern.to_string()
                        }
                    } else if !pattern.starts_with('/') {
                        if let Some(ref h) = dirs::home_dir() {
                            h.join(".ssh").join(pattern).to_string_lossy().to_string()
                        } else {
                            pattern.to_string()
                        }
                    } else {
                        pattern.to_string()
                    };

                    if let Ok(entries) = glob::glob(&expanded_pattern) {
                        for entry in entries {
                            if let Ok(entry_path) = entry {
                                parse_ssh_config_file_rec(&entry_path, target_host, extracted, visited_files);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_match_directive(args: &[&str], target_host: &str) -> bool {
    let mut i = 0;
    let mut matched = true;
    while i < args.len() {
        let criteria = args[i].to_lowercase();
        if criteria == "host" && i + 1 < args.len() {
            let pat = args[i + 1];
            let is_match = ssh2_config::HostClause::new(pat.to_string(), false).intersects(target_host);
            if !is_match {
                matched = false;
            }
            i += 2;
        } else if criteria == "all" {
            i += 1;
        } else {
            i += 1;
        }
    }
    matched
}

pub fn parse_destination_spec(spec: &str, cli_port: Option<u16>) -> (Option<String>, String, Option<u16>) {
    let mut s = spec.trim();
    if let Some(stripped) = s.strip_prefix("ssh://") {
        s = stripped;
    }
    s = s.trim_end_matches('/');

    let mut user = None;
    if let Some(at_idx) = s.find('@') {
        user = Some(s[..at_idx].to_string());
        s = &s[at_idx + 1..];
    }

    let mut port = cli_port;
    let host = if s.starts_with('[') {
        if let Some(close_bracket) = s.find(']') {
            let host_part = &s[1..close_bracket];
            let after_bracket = &s[close_bracket + 1..];
            if let Some(p_str) = after_bracket.strip_prefix(':') {
                if let Ok(p) = p_str.parse::<u16>() {
                    if port.is_none() {
                        port = Some(p);
                    }
                }
            }
            host_part.to_string()
        } else {
            s.to_string()
        }
    } else if s.matches(':').count() == 1 {
        let colon_idx = s.rfind(':').unwrap();
        if let Ok(p) = s[colon_idx + 1..].parse::<u16>() {
            if port.is_none() {
                port = Some(p);
            }
            s[..colon_idx].to_string()
        } else {
            s.to_string()
        }
    } else {
        s.to_string()
    };

    (user, host, port)
}

pub fn parse_proxy_jump_values(val: &str) -> Vec<String> {
    let trimmed = val.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    let mut results = Vec::new();
    for comma_part in trimmed.split(',') {
        for token in comma_part.split_whitespace() {
            let t = token.trim().trim_matches('"').trim_matches('\'');
            if !t.is_empty() && !t.eq_ignore_ascii_case("none") {
                results.push(t.to_string());
            }
        }
    }
    results
}

pub fn resolve_host_config_full(
    spec: &str,
    cli_port: Option<u16>,
    cli_identities: &[PathBuf],
    config_path: Option<&std::path::Path>,
) -> Result<(HostConnectionConfig, ExtractedSshConfig)> {
    let (target_user, target_host, target_port) = parse_destination_spec(spec, cli_port);

    let home_dir = dirs::home_dir();
    let mut extracted = ExtractedSshConfig::default();

    let default_config_path = home_dir.as_ref().map(|h| h.join(".ssh").join("config"));
    let ssh_config_path = config_path.or(default_config_path.as_deref());

    if let Some(path) = ssh_config_path {
        let mut visited = std::collections::HashSet::new();
        parse_ssh_config_file_rec(path, &target_host, &mut extracted, &mut visited);
    }

    let hostname = extracted.hostname.clone().unwrap_or_else(|| target_host.clone());

    let user = target_user
        .or(extracted.user.clone())
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));

    let port = target_port.or(extracted.port).unwrap_or(22);

    let mut identity_files = Vec::new();
    for p in cli_identities {
        identity_files.push(p.clone());
    }

    if identity_files.is_empty() {
        for p in &extracted.identity_files {
            if p.exists() {
                identity_files.push(p.clone());
            } else if let Ok(stripped) = p.strip_prefix("~") {
                if let Some(ref home) = home_dir {
                    let expanded = home.join(stripped.to_string_lossy().trim_start_matches('/'));
                    if expanded.exists() {
                        identity_files.push(expanded);
                    }
                }
            }
        }
    }

    if identity_files.is_empty() {
        if let Some(ref home) = home_dir {
            let default_keys = vec![
                home.join(".ssh").join("id_ed25519"),
                home.join(".ssh").join("id_rsa"),
                home.join(".ssh").join("id_ecdsa"),
                home.join(".ssh").join("id_dsa"),
            ];
            for k in default_keys {
                if k.exists() {
                    identity_files.push(k);
                }
            }
        }
    }

    Ok((
        HostConnectionConfig {
            host: target_host,
            hostname,
            port,
            user,
            identity_files,
        },
        extracted,
    ))
}

#[allow(dead_code)]
pub fn resolve_host_config(
    spec: &str,
    cli_port: Option<u16>,
    cli_identities: &[PathBuf],
) -> Result<HostConnectionConfig> {
    resolve_host_config_full(spec, cli_port, cli_identities, None).map(|(host, _)| host)
}

fn resolve_jump_host_chain(
    specs: &[String],
    config_path: Option<&std::path::Path>,
    visited_hosts: &mut std::collections::HashSet<String>,
    depth: usize,
) -> Result<Vec<HostConnectionConfig>> {
    if depth > 16 {
        return Err(anyhow!("ProxyJump loop or maximum jump limit exceeded"));
    }

    let mut jump_hosts = Vec::new();

    for spec in specs {
        let (_, host_name, _) = parse_destination_spec(spec, None);
        if visited_hosts.contains(&host_name) {
            return Err(anyhow!("ProxyJump loop detected involving host: {}", host_name));
        }

        visited_hosts.insert(host_name.clone());

        let (jump_conn, jump_extracted) = resolve_host_config_full(spec, None, &[], config_path)?;

        if jump_conn.hostname != host_name && visited_hosts.contains(&jump_conn.hostname) {
            return Err(anyhow!("ProxyJump loop detected involving host: {}", jump_conn.hostname));
        }
        if jump_conn.hostname != host_name {
            visited_hosts.insert(jump_conn.hostname.clone());
        }

        // If this jump host also specifies ProxyJump in ssh config, recursively resolve it first!
        if let Some(ref pj) = jump_extracted.proxy_jump {
            let recursive_specs = parse_proxy_jump_values(pj);
            if !recursive_specs.is_empty() {
                let sub_chain = resolve_jump_host_chain(&recursive_specs, config_path, visited_hosts, depth + 1)?;
                jump_hosts.extend(sub_chain);
            }
        }

        jump_hosts.push(jump_conn);
    }

    Ok(jump_hosts)
}

impl ResolvedConfig {
    pub fn from_args(args: CliArgs) -> Result<Self> {
        Self::from_args_with_config_path(args, None)
    }

    pub fn from_args_with_config_path(args: CliArgs, config_path: Option<&std::path::Path>) -> Result<Self> {
        let (target_config, extracted) = resolve_host_config_full(
            &args.destination,
            args.port,
            &args.identity,
            config_path,
        )?;

        // Determine jump hosts
        let mut jump_specs = Vec::new();
        let is_cli_none = args.jump_hosts.len() == 1 && args.jump_hosts[0].trim().eq_ignore_ascii_case("none");

        if is_cli_none {
            // Explicitly disabled via CLI flag -J none
        } else if !args.jump_hosts.is_empty() {
            for j in &args.jump_hosts {
                let parsed = parse_proxy_jump_values(j);
                jump_specs.extend(parsed);
            }
        } else if let Some(ref proxy_jump) = extracted.proxy_jump {
            let parsed = parse_proxy_jump_values(proxy_jump);
            jump_specs.extend(parsed);
        }

        let mut visited_hosts = std::collections::HashSet::new();
        visited_hosts.insert(target_config.host.clone());
        if target_config.hostname != target_config.host {
            visited_hosts.insert(target_config.hostname.clone());
        }

        let jump_hosts = resolve_jump_host_chain(&jump_specs, config_path, &mut visited_hosts, 0)?;

        // Merge local forwards (config first, then CLI flags)
        let mut local_forwards = Vec::new();
        for spec in &extracted.local_forwards {
            local_forwards.push(parse_local_forward(spec)?);
        }
        for spec in &args.local_forwards {
            local_forwards.push(parse_local_forward(spec)?);
        }

        // Merge remote forwards (config first, then CLI flags)
        let mut remote_forwards = Vec::new();
        for spec in &extracted.remote_forwards {
            remote_forwards.push(parse_remote_forward(spec)?);
        }
        for spec in &args.remote_forwards {
            remote_forwards.push(parse_remote_forward(spec)?);
        }

        // Merge dynamic forwards (config first, then CLI flags)
        let mut dynamic_forwards = Vec::new();
        for spec in &extracted.dynamic_forwards {
            dynamic_forwards.push(parse_dynamic_forward(spec)?);
        }
        for spec in &args.dynamic_forwards {
            dynamic_forwards.push(parse_dynamic_forward(spec)?);
        }

        // TUN forward (CLI flag overrides config)
        let mut tun_forward = if let Some(ref spec) = args.tun_forward {
            Some(parse_tun_forward(spec)?)
        } else if let Some(ref spec) = extracted.tun_forward {
            Some(parse_tun_forward(spec)?)
        } else {
            None
        };

        let mut local_tun_addr = args.local_tun_addr;
        let mut remote_tun_addr = args.remote_tun_addr;
        let mut local_tun_addr6 = args.local_tun_addr6;
        let mut remote_tun_addr6 = args.remote_tun_addr6;

        if let Some(ref mut tun) = tun_forward {
            if tun.local_tun == "auto" || tun.remote_tun == "auto" {
                let (id, auto_local_ip, auto_remote_ip) = generate_auto_tun_id(&target_config.host, target_config.port);
                tun.local_tun = format!("tun2222{}", id);
                tun.remote_tun = format!("tun2222{}", id);
                tun.auto_id = Some(id);

                if local_tun_addr.is_none() {
                    local_tun_addr = Some(auto_local_ip);
                }
                if remote_tun_addr.is_none() {
                    remote_tun_addr = Some(auto_remote_ip);
                }
                if local_tun_addr6.is_none() || remote_tun_addr6.is_none() {
                    let (auto_local_ip6, auto_remote_ip6) = derive_auto_tun_ipv6(id);
                    if local_tun_addr6.is_none() {
                        local_tun_addr6 = Some(auto_local_ip6);
                    }
                    if remote_tun_addr6.is_none() {
                        remote_tun_addr6 = Some(auto_remote_ip6);
                    }
                }
            } else if let Some(id) = tun.auto_id {
                if local_tun_addr.is_none() {
                    local_tun_addr = Some(format!("169.254.{}.{}", id >> 8, id & 0xff));
                }
                if remote_tun_addr.is_none() {
                    remote_tun_addr = Some(format!("169.254.{}.{}", (id + 1) >> 8, (id + 1) & 0xff));
                }
                if local_tun_addr6.is_none() || remote_tun_addr6.is_none() {
                    let (auto_local_ip6, auto_remote_ip6) = derive_auto_tun_ipv6(id);
                    if local_tun_addr6.is_none() {
                        local_tun_addr6 = Some(auto_local_ip6);
                    }
                    if remote_tun_addr6.is_none() {
                        remote_tun_addr6 = Some(auto_remote_ip6);
                    }
                }
            }
        }

        Ok(ResolvedConfig {
            host: target_config.host,
            hostname: target_config.hostname,
            port: target_config.port,
            user: target_config.user,
            identity_files: target_config.identity_files,
            jump_hosts,
            local_forwards,
            remote_forwards,
            dynamic_forwards,
            tun_forward,
            local_tun_addr,
            remote_tun_addr,
            local_tun_addr6,
            remote_tun_addr6,
            local_post_up: args.local_post_up,
            remote_post_up: args.remote_post_up,
            reconnect_interval: args.reconnect_interval,
            keepalive_interval: args.keepalive_interval,
            keepalive_max: args.keepalive_max,
            fwmark: args.fwmark,
            use_iptables: args.use_iptables,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_fwmark() {
        assert_eq!(parse_fwmark("0").unwrap(), 0);
        assert_eq!(parse_fwmark("42").unwrap(), 42);
        assert_eq!(parse_fwmark("4294967295").unwrap(), u32::MAX);
        assert_eq!(parse_fwmark("0x0").unwrap(), 0);
        assert_eq!(parse_fwmark("0x10").unwrap(), 16);
        assert_eq!(parse_fwmark("0x1000").unwrap(), 4096);
        assert_eq!(parse_fwmark("0Xabcd").unwrap(), 0xabcd);
        assert_eq!(parse_fwmark("  0xffffffff  ").unwrap(), u32::MAX);

        assert!(parse_fwmark("").is_err());
        assert!(parse_fwmark("invalid").is_err());
        assert!(parse_fwmark("0xG").is_err());
        assert!(parse_fwmark("-1").is_err());
        assert!(parse_fwmark("4294967296").is_err());
    }

    #[test]
    fn test_cli_args_fwmark() {
        // Without flag
        let args = CliArgs::try_parse_from(["sshtun", "myserver"]).unwrap();
        assert_eq!(args.fwmark, None);

        // With decimal --fwmark
        let args = CliArgs::try_parse_from(["sshtun", "myserver", "--fwmark", "100"]).unwrap();
        assert_eq!(args.fwmark, Some(100));

        // With hex --fwmark
        let args = CliArgs::try_parse_from(["sshtun", "myserver", "--fwmark", "0x1000"]).unwrap();
        assert_eq!(args.fwmark, Some(0x1000));

        // With alias --mark
        let args = CliArgs::try_parse_from(["sshtun", "myserver", "--mark", "0x20"]).unwrap();
        assert_eq!(args.fwmark, Some(0x20));

        // ResolvedConfig propagates fwmark
        let resolved = ResolvedConfig::from_args(args).unwrap();
        assert_eq!(resolved.fwmark, Some(0x20));
    }

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

        let f3 = parse_local_forward("8080 10.0.0.1:80").unwrap();
        assert_eq!(
            f3,
            LocalForwardSpec {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 8080,
                target_host: "10.0.0.1".to_string(),
                target_port: 80,
            }
        );

        let f4 = parse_local_forward("0.0.0.0:8080 10.0.0.1:80").unwrap();
        assert_eq!(
            f4,
            LocalForwardSpec {
                bind_addr: "0.0.0.0".to_string(),
                bind_port: 8080,
                target_host: "10.0.0.1".to_string(),
                target_port: 80,
            }
        );

        let f5 = parse_local_forward("0.0.0.0 8080 10.0.0.1 80").unwrap();
        assert_eq!(
            f5,
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

        let r2 = parse_remote_forward("2222 127.0.0.1:22").unwrap();
        assert_eq!(
            r2,
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

        let d3 = parse_dynamic_forward("0.0.0.0 1080").unwrap();
        assert_eq!(
            d3,
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
                auto_id: None,
            }
        );

        let t2 = parse_tun_forward("any:any").unwrap();
        assert_eq!(
            t2,
            TunForwardSpec {
                local_tun: "any".to_string(),
                remote_tun: "any".to_string(),
                auto_id: None,
            }
        );

        let t3 = parse_tun_forward("tun0 tun1").unwrap();
        assert_eq!(
            t3,
            TunForwardSpec {
                local_tun: "tun0".to_string(),
                remote_tun: "tun1".to_string(),
                auto_id: None,
            }
        );

        let t4 = parse_tun_forward("auto").unwrap();
        assert_eq!(
            t4,
            TunForwardSpec {
                local_tun: "auto".to_string(),
                remote_tun: "auto".to_string(),
                auto_id: None,
            }
        );

        let t5 = parse_tun_forward("auto:1024").unwrap();
        assert_eq!(
            t5,
            TunForwardSpec {
                local_tun: "tun22221024".to_string(),
                remote_tun: "tun22221024".to_string(),
                auto_id: Some(1024),
            }
        );
    }

    #[test]
    fn test_auto_tun_id_and_ip() {
        let (id1, local_ip1, remote_ip1) = generate_auto_tun_id("example.com", 22);
        let (id2, local_ip2, remote_ip2) = generate_auto_tun_id("example.com", 22);
        assert_eq!(id1, id2);
        assert_eq!(local_ip1, local_ip2);
        assert_eq!(remote_ip1, remote_ip2);

        // Check bounds & lower 16 bits match
        assert!(id1 >= 256 && id1 <= 65278);
        let local_lower = (local_ip1.split('.').nth(2).unwrap().parse::<u16>().unwrap() << 8)
            | local_ip1.split('.').nth(3).unwrap().parse::<u16>().unwrap();
        let remote_lower = (remote_ip1.split('.').nth(2).unwrap().parse::<u16>().unwrap() << 8)
            | remote_ip1.split('.').nth(3).unwrap().parse::<u16>().unwrap();
        assert_eq!(local_lower, id1);
        assert_eq!(remote_lower, id1 + 1);

        // Check IPv6 derivation
        let (loc_v6, rem_v6) = derive_auto_tun_ipv6(id1);
        let loc_addr: std::net::Ipv6Addr = loc_v6.parse().unwrap();
        let rem_addr: std::net::Ipv6Addr = rem_v6.parse().unwrap();
        let loc_oct = loc_addr.octets();
        let rem_oct = rem_addr.octets();
        assert_eq!(loc_oct[0], 0xfd);
        assert_eq!(rem_oct[0], 0xfd);
        // Same /127 subnet: first 15 bytes match
        assert_eq!(loc_oct[0..15], rem_oct[0..15]);
        // Top 7 bits of byte 15 match (total 119 subnet bits derived from id)
        assert_eq!(loc_oct[15] & 0xfe, rem_oct[15] & 0xfe);
        // Last bit: 0 for local, 1 for remote
        assert_eq!(loc_oct[15] & 1, 0);
        assert_eq!(rem_oct[15] & 1, 1);
    }

    #[test]
    fn test_parse_ssh_config_file_rec() {
        let config_text = r#"
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    LocalForward 8080 10.0.0.1:80
    LocalForward 9090 10.0.0.2:80
    RemoteForward 3333 127.0.0.1:3306
    DynamicForward 1080
    TunnelDevice 0:0
    ProxyJump jump1.example.com:2222, jump2.example.com
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_text).unwrap();

        let mut extracted = ExtractedSshConfig::default();
        let mut visited = std::collections::HashSet::new();
        parse_ssh_config_file_rec(temp_file.path(), "myserver", &mut extracted, &mut visited);

        assert_eq!(extracted.hostname, Some("192.168.1.100".to_string()));
        assert_eq!(extracted.user, Some("admin".to_string()));
        assert_eq!(extracted.port, Some(2222));
        assert_eq!(extracted.local_forwards, vec!["8080 10.0.0.1:80", "9090 10.0.0.2:80"]);
        assert_eq!(extracted.remote_forwards, vec!["3333 127.0.0.1:3306"]);
        assert_eq!(extracted.dynamic_forwards, vec!["1080"]);
        assert_eq!(extracted.tun_forward, Some("0:0".to_string()));
        assert_eq!(extracted.proxy_jump, Some("jump1.example.com:2222, jump2.example.com".to_string()));
    }

    #[test]
    fn test_cli_args_tun_auto() {
        // -w without value should default to "auto"
        let args1 = CliArgs::try_parse_from(["sshtun", "myserver", "-w"]).unwrap();
        assert_eq!(args1.tun_forward, Some("auto".to_string()));

        // -w with explicit auto
        let args2 = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto"]).unwrap();
        assert_eq!(args2.tun_forward, Some("auto".to_string()));

        // -w with custom spec
        let args3 = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "0:0"]).unwrap();
        assert_eq!(args3.tun_forward, Some("0:0".to_string()));

        // without -w
        let args4 = CliArgs::try_parse_from(["sshtun", "myserver"]).unwrap();
        assert_eq!(args4.tun_forward, None);

        // ResolvedConfig with auto
        let resolved = ResolvedConfig::from_args(args1).unwrap();
        let tun = resolved.tun_forward.unwrap();
        assert!(tun.auto_id.is_some());
        let id = tun.auto_id.unwrap();
        assert_eq!(tun.local_tun, format!("tun2222{}", id));
        assert_eq!(tun.remote_tun, format!("tun2222{}", id));
        assert!(resolved.local_tun_addr.is_some());
        assert!(resolved.remote_tun_addr.is_some());
        assert!(resolved.local_tun_addr6.is_some());
        assert!(resolved.remote_tun_addr6.is_some());
        let (resolved_loc_v6, resolved_rem_v6) = derive_auto_tun_ipv6(id);
        assert_eq!(resolved.local_tun_addr6, Some(resolved_loc_v6));
        assert_eq!(resolved.remote_tun_addr6, Some(resolved_rem_v6));

        // -w with explicit auto:1024
        let args_auto_id = CliArgs::try_parse_from(["sshtun", "myserver", "-w", "auto:1024"]).unwrap();
        assert_eq!(args_auto_id.tun_forward, Some("auto:1024".to_string()));
        let resolved_auto_id = ResolvedConfig::from_args(args_auto_id).unwrap();
        let tun_auto_id = resolved_auto_id.tun_forward.unwrap();
        assert_eq!(tun_auto_id.auto_id, Some(1024));
        assert_eq!(tun_auto_id.local_tun, "tun22221024");
        assert_eq!(tun_auto_id.remote_tun, "tun22221024");
        assert_eq!(resolved_auto_id.local_tun_addr, Some("169.254.4.0".to_string()));
        assert_eq!(resolved_auto_id.remote_tun_addr, Some("169.254.4.1".to_string()));
        let (id1024_loc_v6, id1024_rem_v6) = derive_auto_tun_ipv6(1024);
        assert_eq!(resolved_auto_id.local_tun_addr6, Some(id1024_loc_v6));
        assert_eq!(resolved_auto_id.remote_tun_addr6, Some(id1024_rem_v6));
    }

    #[test]
    fn test_derive_auto_tun_ipv6_properties() {
        for test_id in [0, 1, 42, 1024, 65535] {
            let (loc_s, rem_s) = derive_auto_tun_ipv6(test_id);
            let loc: std::net::Ipv6Addr = loc_s.parse().unwrap();
            let rem: std::net::Ipv6Addr = rem_s.parse().unwrap();

            let loc_oct = loc.octets();
            let rem_oct = rem.octets();

            // Range: fd00::/8
            assert_eq!(loc_oct[0], 0xfd);
            assert_eq!(rem_oct[0], 0xfd);

            // Subnet: /127
            // First 14 bytes (112 bits) of subnet derived from id hash match
            assert_eq!(loc_oct[0..15], rem_oct[0..15]);
            // Byte 15 top 7 bits match (112 + 7 = 119 bits derived from id hash)
            assert_eq!(loc_oct[15] & 0xfe, rem_oct[15] & 0xfe);

            // Last bit: 0 for local, 1 for remote
            assert_eq!(loc_oct[15] & 1, 0);
            assert_eq!(rem_oct[15] & 1, 1);
        }

        // Distinct IDs produce distinct subnets
        let (loc1, _) = derive_auto_tun_ipv6(1);
        let (loc2, _) = derive_auto_tun_ipv6(2);
        assert_ne!(loc1, loc2);
    }

    #[test]
    fn test_cli_args_tun_custom_ipv6() {
        let args = CliArgs::try_parse_from([
            "sshtun",
            "myserver",
            "-w",
            "0:0",
            "--local-tun-addr6",
            "fd00:1234::1",
            "--remote-tun-addr6",
            "fd00:1234::2",
        ])
        .unwrap();
        let resolved = ResolvedConfig::from_args(args).unwrap();
        assert_eq!(resolved.local_tun_addr6, Some("fd00:1234::1".to_string()));
        assert_eq!(resolved.remote_tun_addr6, Some("fd00:1234::2".to_string()));
    }

    #[test]
    fn test_parse_destination_spec() {
        // Basic hostname
        let (u, h, p) = parse_destination_spec("myserver", None);
        assert_eq!(u, None);
        assert_eq!(h, "myserver");
        assert_eq!(p, None);

        // User and hostname
        let (u, h, p) = parse_destination_spec("alice@myserver", None);
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "myserver");
        assert_eq!(p, None);

        // User, hostname, and port
        let (u, h, p) = parse_destination_spec("alice@myserver:2222", None);
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "myserver");
        assert_eq!(p, Some(2222));

        // CLI port override takes precedence over spec port
        let (u, h, p) = parse_destination_spec("alice@myserver:2222", Some(3333));
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "myserver");
        assert_eq!(p, Some(3333));

        // ssh:// URI scheme
        let (u, h, p) = parse_destination_spec("ssh://myserver", None);
        assert_eq!(u, None);
        assert_eq!(h, "myserver");
        assert_eq!(p, None);

        let (u, h, p) = parse_destination_spec("ssh://alice@myserver:2222/", None);
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "myserver");
        assert_eq!(p, Some(2222));

        // Bracketed IPv6
        let (u, h, p) = parse_destination_spec("[2001:db8::1]:2222", None);
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, Some(2222));

        let (u, h, p) = parse_destination_spec("user@[2001:db8::1]:2222", None);
        assert_eq!(u, Some("user".to_string()));
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, Some(2222));

        let (u, h, p) = parse_destination_spec("[2001:db8::1]", None);
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, None);

        // Unbracketed IPv6
        let (u, h, p) = parse_destination_spec("2001:db8::1", None);
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, None);
    }

    #[test]
    fn test_parse_proxy_jump_values() {
        assert_eq!(parse_proxy_jump_values("jump1"), vec!["jump1"]);
        assert_eq!(parse_proxy_jump_values("jump1,jump2"), vec!["jump1", "jump2"]);
        assert_eq!(parse_proxy_jump_values("jump1, jump2, jump3"), vec!["jump1", "jump2", "jump3"]);
        assert_eq!(parse_proxy_jump_values("jump1 jump2"), vec!["jump1", "jump2"]);
        assert_eq!(parse_proxy_jump_values("\"jump1, jump2\""), vec!["jump1", "jump2"]);
        assert_eq!(parse_proxy_jump_values("none"), Vec::<String>::new());
        assert_eq!(parse_proxy_jump_values("NONE"), Vec::<String>::new());
        assert_eq!(parse_proxy_jump_values("\"none\""), Vec::<String>::new());
        assert_eq!(parse_proxy_jump_values(""), Vec::<String>::new());
        assert_eq!(
            parse_proxy_jump_values("ssh://user@jump1:2222, jump2"),
            vec!["ssh://user@jump1:2222", "jump2"]
        );
    }

    #[test]
    fn test_proxy_jump_single_and_multi_hop_from_config() {
        let config_text = r#"
Host jump1
    HostName 192.168.1.101
    User jumpuser1
    Port 2201

Host jump2
    HostName 192.168.1.102
    User jumpuser2
    Port 2202

Host target
    HostName 10.0.0.50
    User targetuser
    Port 22
    ProxyJump jump1, jump2
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_text).unwrap();

        let args = CliArgs::try_parse_from(["sshtun", "target"]).unwrap();
        let resolved = ResolvedConfig::from_args_with_config_path(args, Some(temp_file.path())).unwrap();

        assert_eq!(resolved.host, "target");
        assert_eq!(resolved.hostname, "10.0.0.50");
        assert_eq!(resolved.user, "targetuser");
        assert_eq!(resolved.port, 22);
        assert_eq!(resolved.jump_hosts.len(), 2);

        assert_eq!(resolved.jump_hosts[0].host, "jump1");
        assert_eq!(resolved.jump_hosts[0].hostname, "192.168.1.101");
        assert_eq!(resolved.jump_hosts[0].user, "jumpuser1");
        assert_eq!(resolved.jump_hosts[0].port, 2201);

        assert_eq!(resolved.jump_hosts[1].host, "jump2");
        assert_eq!(resolved.jump_hosts[1].hostname, "192.168.1.102");
        assert_eq!(resolved.jump_hosts[1].user, "jumpuser2");
        assert_eq!(resolved.jump_hosts[1].port, 2202);
    }

    #[test]
    fn test_proxy_jump_chained_recursive() {
        let config_text = r#"
Host jump-first
    HostName 203.0.113.1
    User user1
    Port 2221

Host jump-second
    HostName 10.1.0.1
    User user2
    Port 2222
    ProxyJump jump-first

Host target
    HostName 10.2.0.1
    User targetuser
    ProxyJump jump-second
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_text).unwrap();

        let args = CliArgs::try_parse_from(["sshtun", "target"]).unwrap();
        let resolved = ResolvedConfig::from_args_with_config_path(args, Some(temp_file.path())).unwrap();

        assert_eq!(resolved.jump_hosts.len(), 2);
        // jump-first must come before jump-second in the connection chain
        assert_eq!(resolved.jump_hosts[0].host, "jump-first");
        assert_eq!(resolved.jump_hosts[0].hostname, "203.0.113.1");
        assert_eq!(resolved.jump_hosts[0].port, 2221);

        assert_eq!(resolved.jump_hosts[1].host, "jump-second");
        assert_eq!(resolved.jump_hosts[1].hostname, "10.1.0.1");
        assert_eq!(resolved.jump_hosts[1].port, 2222);
    }

    #[test]
    fn test_proxy_jump_loop_detection() {
        // Direct self-loop
        let self_loop_config = r#"
Host loophost
    HostName 1.2.3.4
    ProxyJump loophost
"#;
        let mut file1 = NamedTempFile::new().unwrap();
        write!(file1, "{}", self_loop_config).unwrap();

        let args1 = CliArgs::try_parse_from(["sshtun", "loophost"]).unwrap();
        let res1 = ResolvedConfig::from_args_with_config_path(args1, Some(file1.path()));
        assert!(res1.is_err());
        assert!(res1.unwrap_err().to_string().contains("ProxyJump loop detected"));

        // Indirect cycle: A -> B -> A
        let cycle_config = r#"
Host hostA
    HostName 1.1.1.1
    ProxyJump hostB

Host hostB
    HostName 2.2.2.2
    ProxyJump hostA
"#;
        let mut file2 = NamedTempFile::new().unwrap();
        write!(file2, "{}", cycle_config).unwrap();

        let args2 = CliArgs::try_parse_from(["sshtun", "hostA"]).unwrap();
        let res2 = ResolvedConfig::from_args_with_config_path(args2, Some(file2.path()));
        assert!(res2.is_err());
        assert!(res2.unwrap_err().to_string().contains("ProxyJump loop detected"));
    }

    #[test]
    fn test_proxy_jump_overrides_and_identities() {
        let jump_key_file = NamedTempFile::new().unwrap();
        let target_key_file = NamedTempFile::new().unwrap();

        let config_text = format!(
            r#"
Host jump-configured
    HostName 192.168.1.10
    User jumpuser
    Port 2200
    IdentityFile {}

Host target-with-none
    HostName 10.0.0.1
    ProxyJump none

Host target-with-jump
    HostName 10.0.0.2
    ProxyJump jump-configured
"#,
            jump_key_file.path().display()
        );
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", config_text).unwrap();

        // 1. ProxyJump none in config yields no jump hosts
        let args_none = CliArgs::try_parse_from(["sshtun", "target-with-none"]).unwrap();
        let res_none = ResolvedConfig::from_args_with_config_path(args_none, Some(temp_file.path())).unwrap();
        assert!(res_none.jump_hosts.is_empty());

        // 2. CLI -J none overrides config ProxyJump
        let args_cli_none = CliArgs::try_parse_from(["sshtun", "target-with-jump", "-J", "none"]).unwrap();
        let res_cli_none = ResolvedConfig::from_args_with_config_path(args_cli_none, Some(temp_file.path())).unwrap();
        assert!(res_cli_none.jump_hosts.is_empty());

        // 3. CLI -J override changes jump host
        let args_cli_override = CliArgs::try_parse_from(["sshtun", "target-with-jump", "-J", "custom-jump.example.com:2222"]).unwrap();
        let res_cli_override = ResolvedConfig::from_args_with_config_path(args_cli_override, Some(temp_file.path())).unwrap();
        assert_eq!(res_cli_override.jump_hosts.len(), 1);
        assert_eq!(res_cli_override.jump_hosts[0].host, "custom-jump.example.com");
        assert_eq!(res_cli_override.jump_hosts[0].port, 2222);

        // 4. CLI -i for target does NOT overwrite jump host's configured IdentityFile
        let args_target_key = CliArgs::try_parse_from(["sshtun", "target-with-jump", "-i", target_key_file.path().to_str().unwrap()]).unwrap();
        let res_target_key = ResolvedConfig::from_args_with_config_path(args_target_key, Some(temp_file.path())).unwrap();
        assert_eq!(res_target_key.identity_files, vec![target_key_file.path().to_path_buf()]);
        assert_eq!(res_target_key.jump_hosts.len(), 1);
        assert_eq!(res_target_key.jump_hosts[0].identity_files, vec![jump_key_file.path().to_path_buf()]);
    }

    #[test]
    fn test_cli_args_use_iptables() {
        let args_default = CliArgs::try_parse_from(["sshtun", "myserver"]).unwrap();
        assert!(!args_default.use_iptables);
        let resolved_default = ResolvedConfig::from_args(args_default).unwrap();
        assert!(!resolved_default.use_iptables);

        let args_iptables = CliArgs::try_parse_from(["sshtun", "myserver", "--use-iptables"]).unwrap();
        assert!(args_iptables.use_iptables);
        let resolved_iptables = ResolvedConfig::from_args(args_iptables).unwrap();
        assert!(resolved_iptables.use_iptables);
    }
}

