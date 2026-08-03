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

pub struct SshConnection {
    pub handle: Arc<Handle<ClientHandler>>,
    pub forwarded_tcp_rx: mpsc::Receiver<IncomingForwardedTcp>,
}

impl SshConnection {
    pub async fn connect(
        hostname: &str,
        port: u16,
        user: &str,
        identity_files: &[std::path::PathBuf],
    ) -> anyhow::Result<Self> {
        info!("Connecting to {}:{} as user '{}'...", hostname, port, user);

        let config = client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(60)),
            ..Default::default()
        };
        let config = Arc::new(config);

        let (forwarded_tcp_tx, forwarded_tcp_rx) = mpsc::channel(100);
        let handler = ClientHandler { forwarded_tcp_tx };

        let mut handle = client::connect(config, (hostname, port), handler)
            .await
            .map_err(|e| anyhow::anyhow!("SSH connect failed: {}", e))?;

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

        Ok(SshConnection {
            handle: Arc::new(handle),
            forwarded_tcp_rx,
        })
    }
}
