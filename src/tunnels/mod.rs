pub mod dynamic_forward;
pub mod local_forward;
pub mod remote_forward;
pub mod tun_forward;

use crate::config::ResolvedConfig;
use crate::ssh::{ClientHandler, IncomingForwardedTcp};
use russh::client::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::error;


use std::sync::Arc;

pub struct TunnelManager {
    pub tasks: Vec<JoinHandle<()>>,
}

impl TunnelManager {
    pub async fn start(
        handle: &Arc<Handle<ClientHandler>>,
        config: &ResolvedConfig,
        mut forwarded_tcp_rx: mpsc::Receiver<IncomingForwardedTcp>,
    ) -> anyhow::Result<Self> {

        let mut tasks = Vec::new();

        // Local forwards (-L)
        for spec in &config.local_forwards {
            let handle = handle.clone();
            let spec = spec.clone();
            let jh = tokio::spawn(async move {
                if let Err(e) = local_forward::run_local_forward(handle, spec).await {
                    error!("Local forward error: {}", e);
                }
            });
            tasks.push(jh);
        }

        // Dynamic forwards (-D)
        for spec in &config.dynamic_forwards {
            let handle = handle.clone();
            let spec = spec.clone();
            let jh = tokio::spawn(async move {
                if let Err(e) = dynamic_forward::run_dynamic_forward(handle, spec).await {
                    error!("Dynamic forward error: {}", e);
                }
            });
            tasks.push(jh);
        }

        // Remote forwards (-R)
        if !config.remote_forwards.is_empty() {
            for spec in &config.remote_forwards {
                remote_forward::register_remote_forward(handle, spec).await?;
            }

            let remote_specs = config.remote_forwards.clone();
            let jh = tokio::spawn(async move {
                while let Some(req) = forwarded_tcp_rx.recv().await {
                    remote_forward::handle_incoming_remote_forward(req, &remote_specs).await;
                }
            });
            tasks.push(jh);
        }

        // TUN forward (-w)
        if let Some(ref tun_spec) = config.tun_forward {
            let handle = handle.clone();
            let tun_spec = tun_spec.clone();
            let local_ip = config.local_tun_addr.clone();
            let remote_ip = config.remote_tun_addr.clone();

            let jh = tokio::spawn(async move {
                if let Err(e) = tun_forward::run_tun_forward(handle, tun_spec, local_ip, remote_ip).await {
                    error!("TUN forward error: {}", e);
                }
            });
            tasks.push(jh);
        }

        Ok(TunnelManager { tasks })
    }

    pub fn abort_all(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
