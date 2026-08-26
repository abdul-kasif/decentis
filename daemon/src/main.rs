use base64::{engine::general_purpose::STANDARD as b64, Engine};
use std::collections::HashMap;
use std::env;
use std::fs;
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

use proto::daemon_control_server::{DaemonControl, DaemonControlServer};
use proto::{SendFileRequest, StatusRequest, StatusResponse, TransferProgress};

mod crypto;
mod file_relay;
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
    let peer_addr = env::var("PEER").ok();
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

    let quic_endpoint = endpoint.clone();
    let active_tun = tun_dev.clone();

    // Initialize the shared Peer Registry
    let peer_registry: PeerRegistry = Arc::new(RwLock::new(HashMap::new()));

    let vip_network_clone = vip.clone();
    let registry_for_network = peer_registry.clone();

    // Default save directory for incoming files (current directory)
    let save_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

    tokio::spawn(async move {
        let vip = vip_network_clone;

        if let Some(peer) = peer_addr {
            // --- DIALER LOGIC ---
            let addr = peer.parse().unwrap();
            let remote_pub = b64
                .decode(peer_pub_b64.expect("PEER_PUB env var required for dialer"))
                .unwrap();

            tracing::info!("Dialing peer at {}...", addr);
            let conn = quic_endpoint
                .connect(addr, "decentis.local")
                .unwrap()
                .await
                .unwrap();
            tracing::info!("Connected! Initiating Noise_IK handshake...");

            match transport::handshake::initiate_noise_handshake(&conn, &local_key, &remote_pub)
                .await
            {
                Ok((tx, rx)) => {
                    tracing::info!("Handshake successful. Establishing secure bridge.");

                    let peer_vip = if vip == "10.99.0.1" {
                        "10.99.0.2"
                    } else {
                        "10.99.0.1"
                    };
                    registry_for_network
                        .write()
                        .await
                        .insert(peer_vip.to_string(), conn.clone());

                    transport::stream::spawn_incoming_stream_listener(
                        conn.clone(),
                        save_dir.clone(),
                    );

                    let _ =
                        transport::datagram::start_secure_datagram_bridge(conn, active_tun, tx, rx)
                            .await;
                }
                Err(e) => tracing::error!("Noise_IK handshake failed: {:?}", e),
            }
        } else {
            // --- LISTENER LOGIC ---
            tracing::info!("Waiting for incoming P2P connections...");
            while let Some(incoming) = quic_endpoint.accept().await {
                let active_tun = active_tun.clone();
                let local_key = local_key.clone();
                let registry_ref = registry_for_network.clone();
                let save_dir_ref = save_dir.clone();

                let current_node_vip = vip.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            tracing::info!("Accepted connection. Awaiting Noise_IK handshake...");
                            match transport::handshake::respond_noise_handshake(&conn, &local_key)
                                .await
                            {
                                Ok((tx, rx)) => {
                                    tracing::info!(
                                        "Handshake successful. Establishing secure bridge."
                                    );

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
        }
    });

    // 3. Start gRPC IPC Server
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
