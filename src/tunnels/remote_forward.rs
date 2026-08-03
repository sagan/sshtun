use crate::config::RemoteForwardSpec;
use crate::ssh::{ClientHandler, IncomingForwardedTcp};
use russh::client::Handle;
use tokio::net::TcpStream;
use tracing::{error, info};


pub async fn register_remote_forward(
    handle: &Handle<ClientHandler>,
    spec: &RemoteForwardSpec,
) -> anyhow::Result<()> {
    info!(
        "Requesting remote forward on remote server {}:{} -> {}:{}",
        spec.bind_addr, spec.bind_port, spec.target_host, spec.target_port
    );
    let port = handle
        .tcpip_forward(spec.bind_addr.clone(), spec.bind_port as u32)
        .await
        .map_err(|e| anyhow::anyhow!("Remote forward request failed for port {}: {}", spec.bind_port, e))?;

    info!("Remote forward successfully registered on port {}", port);
    Ok(())
}


pub async fn handle_incoming_remote_forward(
    req: IncomingForwardedTcp,
    specs: &[RemoteForwardSpec],
) {
    let spec = specs
        .iter()
        .find(|s| s.bind_port as u32 == req.connected_port);

    let spec = match spec {
        Some(s) => s,
        None => {
            error!(
                "No matching remote forward spec for connected port {}",
                req.connected_port
            );
            return;
        }
    };

    let target = format!("{}:{}", spec.target_host, spec.target_port);
    info!(
        "Handling remote forward connection from {}:{} -> {}",
        req.originator_address, req.originator_port, target
    );

    let mut local_socket = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to local target {}: {}", target, e);
            return;
        }
    };

    tokio::spawn(async move {
        let mut stream = req.channel.into_stream();
        let (mut socket_read, mut socket_write) = local_socket.split();
        let (mut channel_read, mut channel_write) = tokio::io::split(&mut stream);

        let client_to_server = tokio::io::copy(&mut socket_read, &mut channel_write);
        let server_to_client = tokio::io::copy(&mut channel_read, &mut socket_write);

        let _ = tokio::join!(client_to_server, server_to_client);
    });
}
