use base64::{engine::general_purpose::STANDARD as b64, Engine};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc; // Shared atomic pointers
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

pub mod proto {
    tonic::include_proto!("decentis.v1");
}

pub mod signaling_proto {
    tonic::include_proto!("decentis.signaling.v1");
}

use proto::daemon_control_server::{DaemonControl, DaemonControlServer};
use proto::{SendFileRequest, StatusRequest, StatusResponse, TransferProgress};

mod crypto;
mod file_relay;
mod nat;
mod transport;
mod tun;

// Thread-safe registry to map Virtual IPs to active QUIC Connections
type PeerRegistry = Arc<RwLock<HashMap<String, quinn::Connection>>>;

#[derive(Clone)]
pub struct ControlServiceImpl {
    pub peers: PeerRegistry,
    pub local_vip: String,
}

#[tonic::async_trait]
impl DaemonControl for ControlServiceImpl {
    type InitiateSendStream =
        tokio_stream::wrappers::ReceiverStream<Result<TransferProgress, Status>>;

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let active_peers = self.peers.read().await.len() as i32;

        Ok(Response::new(StatusResponse {
            virtual_ip: self.local_vip.clone(),
            is_active: true,
            active_peers,
        }))
    }

    async fn initiate_send(
        &self,
        request: Request<SendFileRequest>,
    ) -> Result<Response<Self::InitiateSendStream>, Status> {
        let req = request.into_inner();

        // 1. Look up the peer's QUIC connection in our registry
        let peers = self.peers.read().await;
        let conn = peers
            .get(&req.peer_virtual_ip)
            .ok_or_else(|| {
                Status::not_found(format!("Peer VIP {} not connected", req.peer_virtual_ip))
            })?
            .clone();
        drop(peers);

        // 2. Set up the progress streaming channel
        let (tx, rx) = mpsc::channel(128);
        let transfer_id = Uuid::new_v4().to_string();
        let file_path = req.file_path.clone();

        // 3. Spawn the heavy chunking and QUIC streaming process in the background
        tokio::spawn(async move {
            match file_relay::chunker::FileChunker::new(transfer_id, file_path).await {
                Ok(chunker) => {
                    tracing::info!("Chunker initialized. Starting network stream...");
                    if let Err(e) = transport::stream::send_file(&conn, chunker, tx.clone()).await {
                        tracing::error!("File transfer failed: {}", e);
                        let _ = tx
                            .send(Err(Status::internal(format!("Transfer failed: {}", e))))
                            .await;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to initialize file chunker: {}", e);
                    let _ = tx
                        .send(Err(Status::internal(format!("Chunker init failed: {}", e))))
                        .await;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Environment configuration
    let vip = env::var("VIP").unwrap_or_else(|_| "10.99.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "51820".to_string());
    let peer_pub_b64 = env::var("PEER_PUB").ok();

    let socket_path = format!("/tmp/decentis_{}.sock", port);

    // Generate static identity key for this node
    let raw_key = crypto::handshake::generate_static_keypair()?;
    tracing::info!(
        "Identity generated. My Public Key: {}",
        b64.encode(&raw_key.public)
    );

    // Wrap the raw keypair inside an Arc atomic container
    let local_key = Arc::new(raw_key);

    // 1. Initialize the TUN Device
    let tun_dev = tun::device::start_tun_device(&vip).await?;

    // 2. Initialize QUIC Endpoint
    let bind_addr = format!("0.0.0.0:{}", port).parse().unwrap();
    let endpoint = transport::endpoint::create_quic_endpoint(bind_addr)?;

    // --- TIER 1 & 2 NAT TRAVERSAL & SIGNALING REGISTRATION ---
    let local_port = port.parse::<u16>().unwrap_or(51820);
    let (peer_discovered_tx, mut peer_discovered_rx) = tokio::sync::mpsc::channel(16);
    let my_node_pubkey_b64 = b64.encode(&local_key.public);

    let sig_client = Arc::new(nat::signaling::SignalingClient::new(
        "http://127.0.0.1:50051",
        my_node_pubkey_b64,
    ));

    let sig_client_clone = sig_client.clone();

    // Clone the target pubkey for the NAT task so it knows who to dial after registering
    let dial_target_pub_for_nat = peer_pub_b64.clone();

    tokio::spawn(async move {
        let mut public_socket: Option<SocketAddr> = None;

        match nat::upnp::map_external_port(local_port).await {
            Ok(public_addr) => {
                tracing::info!("Tier 1 Traversal complete. Endpoint: {}", public_addr);
                public_socket = Some(public_addr);
            }
            Err(e) => {
                tracing::warn!(
                    "Tier 1 UPnP failed: {}. Falling back to Tier 2 (STUN)...",
                    e
                );
                match nat::stun::discover_public_ip().await {
                    Ok(public_addr) => {
                        tracing::info!(
                            "Tier 2 Traversal complete. My Public IP is: {}",
                            public_addr.ip()
                        );
                        public_socket = Some(SocketAddr::new(public_addr.ip(), local_port));
                    }
                    Err(stun_err) => tracing::error!("Tier 2 STUN failed: {}", stun_err),
                }
            }
        }

        // If an external IP was successfully discovered, register with the signaling server
        if let Some(socket) = public_socket {
            tracing::info!(
                "Registering with signaling server using address: {}",
                socket
            );

            if let Err(err) = sig_client_clone
                .start_registration(socket, "127.0.0.1".to_string(), peer_discovered_tx)
                .await
            {
                tracing::error!("Signaling server registration failed: {}", err);
            } else {
                if let Some(target_pub) = dial_target_pub_for_nat {
                    tracing::info!("Registration complete. Requesting signaling rendezvous for target peer: {}", target_pub);
                    if let Err(e) = sig_client_clone.dial_peer(&target_pub).await {
                        tracing::error!(
                            "Failed to request rendezvous from signaling server: {:?}",
                            e
                        );
                    }
                }
            }
        } else {
            tracing::error!("Skipping signaling registration: No public IP discovered.");
        }
    });

    let quic_endpoint = endpoint.clone();
    let active_tun = tun_dev.clone();

    // Initialize the shared Peer Registry
    let peer_registry: PeerRegistry = Arc::new(RwLock::new(HashMap::new()));

    let _vip_network_clone = vip.clone();
    let registry_for_network = peer_registry.clone();

    // Default save directory for incoming files (current directory)
    let save_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    // --- 3. Dynamic Rendezvous & Connection Management ---
    let quic_endpoint_active = quic_endpoint.clone();
    let tun_for_dialer = active_tun.clone();
    let local_key_for_dialer = local_key.clone();
    let peer_registry_for_dialer = registry_for_network.clone();
    let save_dir_for_dialer = save_dir.clone();
    let vip_for_dialer = vip.clone();
    let current_peer_pub_filter = peer_pub_b64.clone(); // Safely moved into closure instead of parent scope mapping

    // Spawn the Rendezvous Listener Task
    tokio::spawn(async move {
        // Handle incoming rendezvous discovery events from the signaling stream
        while let Some(peer) = peer_discovered_rx.recv().await {
            tracing::info!(
                "Rendezvous event received for peer {} at {}:{} (LAN: {})",
                peer.target_node_id,
                peer.public_ip,
                peer.public_port,
                peer.local_ip
            );

            let target_ip: std::net::IpAddr = match peer.public_ip.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    tracing::error!("Failed to parse peer public IP: {}", e);
                    continue;
                }
            };
            let target_port = peer.public_port as u16;

            // Tier 3: Fire UDP Hole-Punching Probes to open local NAT mapping
            if let Err(e) = nat::punch::fire_prediction_probes(target_ip, target_port).await {
                tracing::warn!("Hole punch probe batch warning: {}", e);
            }

            // If we are the initiating dialer (started with PEER_PUB), dial the peer over QUIC
            if current_peer_pub_filter.as_deref() == Some(&peer.target_node_id) {
                let target_public = SocketAddr::new(target_ip, target_port);

                // Parse the local IP from the signaling server
                let target_local_ip: std::net::IpAddr = peer.local_ip.parse().unwrap_or(target_ip);
                let target_local = SocketAddr::new(target_local_ip, target_port);

                let remote_pub = match b64.decode(&peer.target_node_id) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!("Failed to decode peer public key: {}", e);
                        continue;
                    }
                };

                tracing::info!(
                    "Dialing QUIC... (LAN: {}, Public: {})",
                    target_local,
                    target_public
                );

                // Allow a brief delay for NAT state tables to settle after hole punching
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                // Try connecting via the local network first (Bypasses NAT Hairpinning)
                let conn_result = match quic_endpoint_active
                    .connect(target_local, "decentis.local")
                    .unwrap()
                    .await
                {
                    Ok(conn) => {
                        tracing::info!("Connected via LAN/Localhost!");
                        Ok(conn)
                    }
                    Err(_) => {
                        tracing::warn!("LAN route failed, attempting Public STUN route...");
                        // Fallback to UDP hole-punched public route
                        quic_endpoint_active
                            .connect(target_public, "decentis.local")
                            .unwrap()
                            .await
                    }
                };

                match conn_result {
                    Ok(conn) => {
                        tracing::info!(
                            "QUIC connection established! Initiating Noise_IK handshake..."
                        );
                        match transport::handshake::initiate_noise_handshake(
                            &conn,
                            &local_key_for_dialer,
                            &remote_pub,
                        )
                        .await
                        {
                            Ok((tx, rx)) => {
                                tracing::info!(
                                    "Noise_IK handshake successful. Secure tunnel active."
                                );
                                let peer_vip = if vip_for_dialer == "10.99.0.1" {
                                    "10.99.0.2"
                                } else {
                                    "10.99.0.1"
                                };
                                peer_registry_for_dialer
                                    .write()
                                    .await
                                    .insert(peer_vip.to_string(), conn.clone());

                                transport::stream::spawn_incoming_stream_listener(
                                    conn.clone(),
                                    save_dir_for_dialer.clone(),
                                );

                                let _ = transport::datagram::start_secure_datagram_bridge(
                                    conn,
                                    tun_for_dialer.clone(),
                                    tx,
                                    rx,
                                )
                                .await;
                            }
                            Err(e) => tracing::error!("Noise_IK handshake failed: {:?}", e),
                        }
                    }
                    Err(e) => {
                        tracing::error!("QUIC dial connections exhausted and failed: {:?}", e)
                    }
                }
            }
        }
    });

    // --- 4. Continuous Inbound Listener Logic ---
    // Every node acts as a server to handle incoming connections seamlessly
    let quic_endpoint_listener = quic_endpoint.clone();
    let active_tun_listener = active_tun.clone();
    let registry_for_listener = registry_for_network.clone();
    let local_key_listener = local_key.clone();
    let save_dir_listener = save_dir.clone();
    let vip_listener = vip.clone();

    tokio::spawn(async move {
        tracing::info!("Awaiting inbound P2P socket allocations...");
        while let Some(incoming) = quic_endpoint_listener.accept().await {
            let active_tun = active_tun_listener.clone();
            let local_key = local_key_listener.clone();
            let registry_ref = registry_for_listener.clone();
            let save_dir_ref = save_dir_listener.clone();
            let current_node_vip = vip_listener.clone();

            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        tracing::info!("Accepted connection. Awaiting Noise_IK handshake...");
                        match transport::handshake::respond_noise_handshake(&conn, &local_key).await
                        {
                            Ok((tx, rx)) => {
                                tracing::info!("Handshake successful. Establishing secure bridge.");
                                let peer_vip = if current_node_vip == "10.99.0.1" {
                                    "10.99.0.2"
                                } else {
                                    "10.99.0.1"
                                };
                                registry_ref
                                    .write()
                                    .await
                                    .insert(peer_vip.to_string(), conn.clone());
                                transport::stream::spawn_incoming_stream_listener(
                                    conn.clone(),
                                    save_dir_ref,
                                );
                                let _ = transport::datagram::start_secure_datagram_bridge(
                                    conn, active_tun, tx, rx,
                                )
                                .await;
                            }
                            Err(e) => tracing::error!("Noise_IK handshake failed: {:?}", e),
                        }
                    }
                    Err(err) => {
                        tracing::error!("Failed to complete QUIC inbound handshake: {:?}", err)
                    }
                }
            });
        }
    });

    // 5. Start gRPC IPC Server
    if Path::new(&socket_path).exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("IPC listening on UDS: {}", socket_path);
    let service = ControlServiceImpl {
        peers: peer_registry,
        local_vip: vip,
    };
    Server::builder()
        .add_service(DaemonControlServer::new(service))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;

    Ok(())
}
