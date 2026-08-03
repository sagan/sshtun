use crate::config::ResolvedConfig;
use crate::ssh::ClientHandler;
use russh::client::Handle;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use std::sync::Arc;

pub async fn run_link_monitor(
    handle: Arc<Handle<ClientHandler>>,
    config: ResolvedConfig,
) -> anyhow::Result<()> {

    let interval = Duration::from_secs(config.keepalive_interval);
    let mut failures = 0;

    info!(
        "Starting link monitor (interval: {}s, max failures: {})",
        config.keepalive_interval, config.keepalive_max
    );

    loop {
        sleep(interval).await;

        // Send keepalive@openssh.com global request
        debug!("Sending SSH keepalive ping...");
        let ping_res = tokio::time::timeout(
            Duration::from_secs(5),
            handle.channel_open_session(),
        )
        .await;

        match ping_res {
            Ok(Ok(channel)) => {
                debug!("Keepalive ping succeeded");
                failures = 0;
                let _ = channel.close().await;
            }
            Ok(Err(e)) => {
                failures += 1;
                warn!(
                    "Keepalive ping failed ({}/{}): {}",
                    failures, config.keepalive_max, e
                );
            }
            Err(_) => {
                failures += 1;
                warn!(
                    "Keepalive ping timed out ({}/{})",
                    failures, config.keepalive_max
                );
            }
        }

        if failures >= config.keepalive_max {
            error!(
                "Link health check failed {} consecutive times. Connection declared dead.",
                failures
            );
            return Err(anyhow::anyhow!("Link monitor detected dead connection"));
        }
    }
}
