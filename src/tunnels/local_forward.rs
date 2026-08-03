use crate::config::LocalForwardSpec;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn run_local_forward(
    handle: Arc<Handle<ClientHandler>>,
    spec: LocalForwardSpec,
) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", spec.bind_addr, spec.bind_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!(
        "Local forward listening on {} -> {}:{}",
        bind_addr, spec.target_host, spec.target_port
    );

    loop {
        let (mut socket, peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("Local forward accept error on {}: {}", bind_addr, e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let handle = handle.clone();
        let spec = spec.clone();

        tokio::spawn(async move {
            let channel_res = handle
                .channel_open_direct_tcpip(
                    &spec.target_host,
                    spec.target_port as u32,
                    &peer_addr.ip().to_string(),
                    peer_addr.port() as u32,
                )
                .await;

            let channel = match channel_res {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Failed to open direct-tcpip channel for {}:{}: {}",
                        spec.target_host, spec.target_port, e
                    );
                    return;
                }
            };

            let mut stream = channel.into_stream();
            let (mut socket_read, mut socket_write) = socket.split();
            let (mut channel_read, mut channel_write) = tokio::io::split(&mut stream);

            let client_to_server = tokio::io::copy(&mut socket_read, &mut channel_write);
            let server_to_client = tokio::io::copy(&mut channel_read, &mut socket_write);

            let _ = tokio::join!(client_to_server, server_to_client);
        });
    }
}
