use async_trait::async_trait;
use russh::client::{self, Handle, Handler};
use russh::Channel;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct IncomingForwardedTcp {
    pub channel: Channel<client::Msg>,
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

pub struct ClientHandler {
    pub forwarded_tcp_tx: mpsc::Sender<IncomingForwardedTcp>,
}

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let req = IncomingForwardedTcp {
            channel,
            connected_address: connected_address.to_string(),
            connected_port,
            originator_address: originator_address.to_string(),
            originator_port,
        };
        if let Err(e) = self.forwarded_tcp_tx.send(req).await {
            error!("Failed to forward incoming tcpip channel: {}", e);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DummyHandler;

#[async_trait]
impl Handler for DummyHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn authenticate_handle<H: Handler + Send + 'static>(
    handle: &mut Handle<H>,
    user: &str,
    identity_files: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    let mut authenticated = false;

    // Try key authentication for each identity file
    for key_path in identity_files {
        if !key_path.exists() {
            continue;
        }
        info!("Trying identity key: {:?}", key_path);
        if let Ok(key_pair) = russh_keys::load_secret_key(key_path, None) {
            match handle.authenticate_publickey(user, Arc::new(key_pair)).await {
                Ok(true) => {
                    info!("Successfully authenticated with key: {:?}", key_path);
                    authenticated = true;
                    break;
                }
                Ok(false) => {
                    warn!("Key authentication rejected for {:?}", key_path);
                }
                Err(e) => {
                    warn!("Error attempting key authentication for {:?}: {}", key_path, e);
                }
            }
        }
    }

    // Try ssh-agent if not authenticated
    if !authenticated {
        if let Ok(_agent_path) = std::env::var("SSH_AUTH_SOCK") {
            info!("Trying ssh-agent...");
            if let Ok(mut agent) = russh_keys::agent::client::AgentClient::connect_env().await {
                if let Ok(identities) = agent.request_identities().await {
                    for identity in identities {
                        let (a, auth_res) = handle.authenticate_future(user, identity, agent).await;
                        agent = a;
                        if let Ok(true) = auth_res {
                            info!("Successfully authenticated via ssh-agent");
                            authenticated = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !authenticated {
        return Err(anyhow::anyhow!("Failed to authenticate SSH user '{}'. No valid identity keys or agent auth succeeded.", user));
    }

    Ok(())
}

pub struct SshConnection {
    pub handle: Arc<Handle<ClientHandler>>,
    pub forwarded_tcp_rx: mpsc::Receiver<IncomingForwardedTcp>,
    pub _jump_handles: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

impl SshConnection {
    pub async fn connect(config: &crate::config::ResolvedConfig) -> anyhow::Result<Self> {
        let ssh_client_config = Arc::new(client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(60)),
            ..Default::default()
        });

        let mut _jump_handles: Vec<Box<dyn std::any::Any + Send + Sync>> = Vec::new();

        if config.jump_hosts.is_empty() {
            info!("Connecting to {}:{} as user '{}'...", config.hostname, config.port, config.user);

            let (forwarded_tcp_tx, forwarded_tcp_rx) = mpsc::channel(100);
            let handler = ClientHandler { forwarded_tcp_tx };

            let mut handle = client::connect(ssh_client_config, (config.hostname.as_str(), config.port), handler)
                .await
                .map_err(|e| anyhow::anyhow!("SSH connect failed to {}:{}: {}", config.hostname, config.port, e))?;

            authenticate_handle(&mut handle, &config.user, &config.identity_files).await?;

            Ok(SshConnection {
                handle: Arc::new(handle),
                forwarded_tcp_rx,
                _jump_handles,
            })
        } else {
            info!("Connecting through {} jump server(s)...", config.jump_hosts.len());

            // 1. Connect to the first jump host directly via TCP
            let j1 = &config.jump_hosts[0];
            info!("Connecting to jump server 1/{} ({}:{} as user '{}')...", config.jump_hosts.len(), j1.hostname, j1.port, j1.user);

            let mut j1_handle = client::connect(ssh_client_config.clone(), (j1.hostname.as_str(), j1.port), DummyHandler)
                .await
                .map_err(|e| anyhow::anyhow!("SSH connect failed to jump host {}:{}: {}", j1.hostname, j1.port, e))?;

            authenticate_handle(&mut j1_handle, &j1.user, &j1.identity_files).await?;
            info!("Jump server 1/{} ({}:{}) authenticated.", config.jump_hosts.len(), j1.hostname, j1.port);

            let mut current_jump_arc = Arc::new(j1_handle);

            // 2. Connect to subsequent jump hosts over direct-tcpip channel streams
            for (idx, j_next) in config.jump_hosts.iter().enumerate().skip(1) {
                info!("Connecting to jump server {}/{} ({}:{} as user '{}') via tunnel...", idx + 1, config.jump_hosts.len(), j_next.hostname, j_next.port, j_next.user);

                let channel = current_jump_arc
                    .channel_open_direct_tcpip(&j_next.hostname, j_next.port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to open direct-tcpip channel to jump server {}:{}: {}", j_next.hostname, j_next.port, e))?;

                let stream = channel.into_stream();
                let mut next_handle = client::connect_stream(ssh_client_config.clone(), stream, DummyHandler)
                    .await
                    .map_err(|e| anyhow::anyhow!("SSH connect failed to jump server {}:{}: {}", j_next.hostname, j_next.port, e))?;

                authenticate_handle(&mut next_handle, &j_next.user, &j_next.identity_files).await?;
                info!("Jump server {}/{} ({}:{}) authenticated.", idx + 1, config.jump_hosts.len(), j_next.hostname, j_next.port);

                _jump_handles.push(Box::new(current_jump_arc.clone()));
                current_jump_arc = Arc::new(next_handle);
            }

            // 3. Connect to the final target host over direct-tcpip channel from the last jump host
            info!("Opening tunnel to target host {}:{} through jump server chain...", config.hostname, config.port);
            let channel = current_jump_arc
                .channel_open_direct_tcpip(&config.hostname, config.port as u32, "127.0.0.1", 0)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to open direct-tcpip channel to target {}:{}: {}", config.hostname, config.port, e))?;

            let stream = channel.into_stream();

            let (forwarded_tcp_tx, forwarded_tcp_rx) = mpsc::channel(100);
            let handler = ClientHandler { forwarded_tcp_tx };

            let mut target_handle = client::connect_stream(ssh_client_config.clone(), stream, handler)
                .await
                .map_err(|e| anyhow::anyhow!("SSH connect failed to target {}:{}: {}", config.hostname, config.port, e))?;

            authenticate_handle(&mut target_handle, &config.user, &config.identity_files).await?;
            info!("Target SSH connection established to {}:{}", config.hostname, config.port);

            _jump_handles.push(Box::new(current_jump_arc));

            Ok(SshConnection {
                handle: Arc::new(target_handle),
                forwarded_tcp_rx,
                _jump_handles,
            })
        }
    }
}

