use crate::config::DynamicForwardSpec;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

use std::sync::Arc;

pub async fn run_dynamic_forward(
    handle: Arc<Handle<ClientHandler>>,
    spec: DynamicForwardSpec,
) -> anyhow::Result<()> {

    let bind_addr = format!("{}:{}", spec.bind_addr, spec.bind_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Dynamic SOCKS5 proxy listening on {}", bind_addr);

    loop {
        let (mut socket, peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("Dynamic forward accept error on {}: {}", bind_addr, e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let handle = handle.clone();

        tokio::spawn(async move {
            // SOCKS5 Greeting / Method Selection
            let mut buf = [0u8; 257];
            if socket.read_exact(&mut buf[..2]).await.is_err() {
                return;
            }
            if buf[0] != 5 {
                return; // Only SOCKS5 supported
            }
            let nmethods = buf[1] as usize;
            if socket.read_exact(&mut buf[..nmethods]).await.is_err() {
                return;
            }
            // Send method selection response: SOCKS5 (0x05), NO AUTH (0x00)
            if socket.write_all(&[0x05, 0x00]).await.is_err() {
                return;
            }

            // Read SOCKS5 Request
            // Header: ver(1), cmd(1), rsv(1), atyp(1)
            let mut req_hdr = [0u8; 4];
            if socket.read_exact(&mut req_hdr).await.is_err() {
                return;
            }
            if req_hdr[0] != 5 || req_hdr[1] != 1 {
                // Command not supported (only CONNECT 0x01)
                let _ = socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }

            let target_host = match req_hdr[3] {
                1 => {
                    // IPv4
                    let mut ip = [0u8; 4];
                    if socket.read_exact(&mut ip).await.is_err() {
                        return;
                    }
                    Ipv4Addr::from(ip).to_string()
                }
                3 => {
                    // Domain Name
                    let mut len = [0u8; 1];
                    if socket.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let domain_len = len[0] as usize;
                    let mut domain = vec![0u8; domain_len];
                    if socket.read_exact(&mut domain).await.is_err() {
                        return;
                    }
                    String::from_utf8_lossy(&domain).to_string()
                }
                4 => {
                    // IPv6
                    let mut ip = [0u8; 16];
                    if socket.read_exact(&mut ip).await.is_err() {
                        return;
                    }
                    Ipv6Addr::from(ip).to_string()
                }
                _ => return,
            };

            let mut port_buf = [0u8; 2];
            if socket.read_exact(&mut port_buf).await.is_err() {
                return;
            }
            let target_port = u16::from_be_bytes(port_buf);

            let channel_res = handle
                .channel_open_direct_tcpip(
                    &target_host,
                    target_port as u32,
                    &peer_addr.ip().to_string(),
                    peer_addr.port() as u32,
                )
                .await;

            let channel = match channel_res {
                Ok(c) => c,
                Err(e) => {
                    error!("Dynamic forward error for {}:{}: {}", target_host, target_port, e);
                    // Connection refusal reply
                    let _ = socket.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
            };

            // Success reply
            if socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .is_err()
            {
                return;
            }

            let mut stream = channel.into_stream();
            let (mut socket_read, mut socket_write) = socket.split();
            let (mut channel_read, mut channel_write) = tokio::io::split(&mut stream);

            let client_to_server = tokio::io::copy(&mut socket_read, &mut channel_write);
            let server_to_client = tokio::io::copy(&mut channel_read, &mut socket_write);

            let _ = tokio::join!(client_to_server, server_to_client);
        });
    }
}
