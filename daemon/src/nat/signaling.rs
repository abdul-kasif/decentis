use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::signaling_proto::signaling_service_client::SignalingServiceClient;
use crate::signaling_proto::{
    signal_message::Payload, DialPeer, PeerFound, RegisterNode, SignalMessage,
};

pub struct SignalingClient {
    server_addr: String,
    node_id: String,
}

impl SignalingClient {
    pub fn new(server_addr: impl Into<String>, node_id: impl Into<String>) -> Self {
        Self {
            server_addr: server_addr.into(),
            node_id: node_id.into(),
        }
    }

    /// Registers with the signaling server and listens for peer discovery events.
    pub async fn start_registration(
        &self,
        public_addr: SocketAddr,
        local_ip: String,
        discovered_peer_tx: mpsc::Sender<PeerFound>,
    ) -> Result<()> {
        let mut client = SignalingServiceClient::connect(self.server_addr.clone())
            .await
            .map_err(|e| anyhow!("Failed to connect to signaling server: {}", e))?;

        let register_msg = SignalMessage {
            payload: Some(Payload::Register(RegisterNode {
                node_id: self.node_id.clone(),
                public_ip: public_addr.ip().to_string(),
                public_port: public_addr.port() as u32,
                local_ip,
            })),
        };

        info!("Registering node {} with signaling server...", self.node_id);
        let mut stream = client.start_connection(register_msg).await?.into_inner();

        tokio::spawn(async move {
            while let Ok(Some(msg)) = stream.message().await {
                if let Some(Payload::PeerFound(peer)) = msg.payload {
                    info!(
                        "Signaling Event: Discovered peer {} at {}:{}",
                        peer.target_node_id, peer.public_ip, peer.public_port
                    );
                    let _ = discovered_peer_tx.send(peer).await;
                }
            }
            error!("Signaling server stream closed.");
        });

        Ok(())
    }

    /// Requests the signaling server to coordinate a mutual rendezvous with a target node.
    pub async fn dial_peer(&self, target_node_id: &str) -> Result<()> {
        let mut client = SignalingServiceClient::connect(self.server_addr.clone())
            .await
            .map_err(|e| anyhow!("Failed to connect to signaling server: {}", e))?;

        let dial_msg = SignalMessage {
            payload: Some(Payload::Dial(DialPeer {
                my_node_id: self.node_id.clone(),
                target_node_id: target_node_id.to_string(),
            })),
        };

        let response = client.send_signal(dial_msg).await?.into_inner();
        if !response.success {
            return Err(anyhow!(
                "Signaling server rejected dial: {}",
                response.message
            ));
        }

        info!("Dial request sent for peer: {}", target_node_id);
        Ok(())
    }

    /// Notifies the signaling server that this node is cleanly disconnecting.
    pub async fn disconnect(&self) -> Result<()> {
        let mut client = SignalingServiceClient::connect(self.server_addr.clone())
            .await
            .map_err(|e| {
                anyhow!(
                    "Failed to connect to signaling server during shutdown: {}",
                    e
                )
            })?;

        // 1. Wrap the DisconnectNode payload variant
        let disconnect_msg = SignalMessage {
            payload: Some(Payload::Disconnect(
                crate::signaling_proto::DisconnectNode {
                    node_id: self.node_id.clone(),
                },
            )),
        };

        // 2. Dispatch it via the same unary signal method you use for dial
        info!("Sending clean disconnect notification to signaling server...");
        let response = client.send_signal(disconnect_msg).await?.into_inner();

        if !response.success {
            return Err(anyhow!(
                "Signaling server rejected disconnect payload: {}",
                response.message
            ));
        }

        info!("Signaling unregistration complete.");
        Ok(())
    }
}
