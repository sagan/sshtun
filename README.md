# sshtun

`sshtun` is a high-performance, pure-Rust SSH tunnel manager and link health supervisor designed for Linux. It maintains persistent background SSH connections with automatic reconnects and supports standard port forwarding as well as OpenSSH layer-3 TUN (`-w`) interface tunneling.

---

## Key Features

- **Pure Rust SSH Implementation**: Built natively using Tokio and `russh` without invoking the external `ssh` executable.
- **OpenSSH Configuration & Authentication**:
  - Automatically parses `~/.ssh/config` for host aliases, custom hostnames, ports, users, and identity keys.
  - Supports SSH public key authentication (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_dsa`, or custom `-i` keys).
  - Integrates with `SSH_AUTH_SOCK` (ssh-agent).
- **Comprehensive Tunnel Support**:
  - **Local Port Forwarding (`-L`)**: `[bind_address:]port:host:hostport`
  - **Remote Port Forwarding (`-R`)**: `[bind_address:]port:host:hostport`
  - **Dynamic SOCKS5 Proxy (`-D`)**: `[bind_address:]port`
  - **TUN Interface Tunneling (`-w`)**: `local_tun[:remote_tun]` (e.g. `0:0`, `any:any`, `tun0:tun1`), or `-w auto` / `-w auto:<id>` for zero-configuration automatic TUN setup.
- **Automated TUN Device & Network Setup**:
  - Automatically provisions TUN interfaces `tun2222<id>` with `-w auto` (or `-w auto:<id>`) with derived or assigned `<id>` and link-local IP addresses, configuring server nftables firewall and routing out of the box.
  - Configures point-to-point /32 IP address pairs on local TUN interfaces via `--local-tun-addr` and `--remote-tun-addr`.
  - Supports `--local-post-up <cmdline>` and `--remote-post-up <cmdline>` hook scripts with `%i` interface name placeholder (e.g. `ip route add ... dev %i`) for custom routing and firewall rules.
- **Netfilter fwmark Support**:
  - Assigns `SO_MARK` on created SSH TCP sockets with `--fwmark <mark>` (or `--mark <mark>`) to allow policy routing without routing loops.
- **Link Supervision & Auto-Reconnect**:
  - Built-in keepalive ping health monitor (`keepalive@openssh.com`).
  - Automatically tears down stale tunnels and reconnects upon link failure.

---

## Installation & Requirements

### Prerequisites
- **Operating System**: Linux (TUN device creation requires `CAP_NET_ADMIN` privileges or running as `root`).
- **Remote SSH Server**: Standard OpenSSH server (with `PermitTunnel yes` in `/etc/ssh/sshd_config` if using TUN tunnels).

### Building from Source

```bash
git clone https://github.com/user/sshtun.git
cd sshtun
cargo build --release
```

The binary will be available at `./target/release/sshtun`.

---

## Usage

```text
Pure Rust SSH tunnel manager with TUN support and auto-reconnect

Usage: sshtun [OPTIONS] <DESTINATION>

Arguments:
  <DESTINATION>  Remote host or SSH alias, optionally with user/port: [user@]host[:port]

Options:
  -p, --port <PORT>
          SSH server port override
  -i, --identity <IDENTITY>
          Identity key file(s)
  -L, --local-forward <LOCAL_FORWARDS>
          Local port forwarding: [bind_address:]port:host:hostport
  -R, --remote-forward <REMOTE_FORWARDS>
          Remote port forwarding: [bind_address:]port:host:hostport
  -D, --dynamic-forward <DYNAMIC_FORWARDS>
          Dynamic SOCKS5 port forwarding: [bind_address:]port
  -w, --tun-forward <TUN_FORWARD>
          TUN device tunnel: local_tun[:remote_tun] (e.g. 0:0, any:any, tun0:tun1)
      --local-tun-addr <LOCAL_TUN_ADDR>
          Local TUN IP address (e.g. 192.168.100.1 or 192.168.100.1/32)
      --remote-tun-addr <REMOTE_TUN_ADDR>
          Remote TUN IP address (e.g. 192.168.100.2 or 192.168.100.2/32)
      --local-tun-addr6 <LOCAL_TUN_ADDR6>
          Local TUN IPv6 address (e.g. fd00::1 or fd00::1/127)
      --remote-tun-addr6 <REMOTE_TUN_ADDR6>
          Remote TUN IPv6 address (e.g. fd00::2 or fd00::2/127)
      --local-post-up <LOCAL_POST_UP>
          Shell command executed locally after tunnel is established
      --remote-post-up <REMOTE_POST_UP>
          Shell command executed on remote server after tunnel is established
  -N, --no-shell
          Do not execute remote shell command (tunnel mode) [default: true]
      --reconnect-interval <RECONNECT_INTERVAL>
          Seconds to wait before reconnecting on disconnect [default: 5]
      --keepalive-interval <KEEPALIVE_INTERVAL>
          Seconds between link keepalive ping checks [default: 10]
      --keepalive-max <KEEPALIVE_MAX>
          Max failed keepalive pings before declaring link dead [default: 3]
      --fwmark <FWMARK>
          Netfilter fwmark for created SSH socket (e.g. 0x1000 or 4096)
  -v, --verbose...
          Verbose logging output
  -h, --help
          Print help
  -V, --version
          Print version
```

---

## Examples

### 1. Local & Remote Port Forwarding

Forward local port `8080` to `10.0.0.1:80` on the remote network, and remote port `2222` to local SSH port `22`:

```bash
sshtun user@remote-server -L 8080:10.0.0.1:80 -R 2222:127.0.0.1:22
```

### 2. Dynamic SOCKS5 Proxy

Start a local SOCKS5 proxy on `127.0.0.1:1080`:

```bash
sshtun my-ssh-alias -D 1080
```

### 3. Layer-3 TUN Tunnel with Auto Setup & Custom Routing

With `-w auto` (or `-w auto:<id>`, e.g. `-w auto:1024`), `sshtun` automatically provisions TUN interfaces named `tun2222<id>` with dual-stack IPv4 (`169.254.0.0/16`) and IPv6 ULA (`fd00::/8` /127 subnet derived from `<id>`) addresses, and configures remote nftables forwarding and masquerading. You can use `%i` as a placeholder for the dynamically created TUN interface in `--local-post-up` or `--remote-post-up`:

```bash
# Auto-generate ID & dual-stack IPv4/IPv6 IPs, creating tun2222<id>
sudo sshtun root@remote-server -w \
  --local-post-up "ip route add 10.3.1.0/24 dev %i table 5"

# Or manually set ID (creates tun22221024 with 169.254.4.0 <-> 169.254.4.1 and fd..:0 <-> fd..:1):
sudo sshtun root@remote-server -w auto:1024 \
  --local-post-up "ip route add 10.3.1.0/24 dev %i table 5"
```

Or configure manually:

```bash
sudo sshtun root@remote-server -w 0:0 \
  --local-tun-addr 192.168.100.1 \
  --remote-tun-addr 192.168.100.2 \
  --local-post-up "ip route add 10.0.0.0/24 dev %i via 192.168.100.2" \
  --remote-post-up "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
```

### 4. Policy Routing with Netfilter fwmark

Avoid routing loops when directing default traffic through the tunnel by assigning a netfilter fwmark (`SO_MARK`) to the SSH connection socket:

```bash
sudo sshtun root@remote-server -w auto \
  --fwmark 0x1000 \
  --local-post-up "ip rule add not fwmark 0x1000 table 5; ip route add default dev %i table 5"
```

---

## Architecture & How It Works

1. **SSH Connection & Authentication**: `sshtun` parses host definitions from `~/.ssh/config` and command-line arguments. It establishes a raw TCP stream to the destination and performs SSH2 protocol handshakes, authenticating via public key files or `ssh-agent`.
2. **OpenSSH TUN (`tun@openssh.com`)**: When `-w` is specified, `sshtun` opens an SSH channel of type `tun@openssh.com` in Point-to-Point mode (mode 1). It encapsulates layer-3 IP packets with OpenSSH 4-byte family headers (`AF_INET` / `AF_INET6`) and bidirectionally proxies packets between the Linux `/dev/net/tun` interface and the SSH channel.
3. **Post-Up Hooks**: Once tunnels are established, `sshtun` executes optional local shell scripts and remote SSH commands to configure IP addresses and routing tables.
4. **Link Supervisor**: A background task periodically sends keepalive requests. If `keepalive-max` pings fail, `sshtun` tears down state and initiates an automatic reconnect loop.

---

## License

Licensed under the [MIT License](LICENSE).
