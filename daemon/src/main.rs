// ==============================================================================
// DECENTIS DAEMON PRODUCTION HARDENING ROADMAP
// ==============================================================================

// TODO 1: CONCURRENT HAPPY EYEBALLS RACING (RFC 8305)
// ------------------------------------------------------------------------------
// CURRENT: Sequential dialing (tries LAN first, waits for timeout, then tries Public).
// PRODUCTION STRATEGY:
// - Spawn simultaneous connection attempts to all candidate endpoints (Local LAN,
//   Reflexive STUN, UPnP external) using `tokio::select!` or a `FuturesUnordered` race.
// - Establish the QUIC connection on whichever candidate handshake finishes first,
//   canceling the slower pending attempts immediately.

// TODO 2: SOCKET SHARING VIA SO_REUSEPORT (CRUCIAL FOR SYMMETRIC NAT)
// ------------------------------------------------------------------------------
// CURRENT: `nat::punch::fire_prediction_probes` binds an ephemeral socket (0.0.0.0:0).
// PRODUCTION STRATEGY:
// - Construct the underlying UDP socket using the `socket2` crate with `SO_REUSEADDR`
//   and `SO_REUSEPORT` enabled before passing it to `quinn::Endpoint`.
// - Fire Tier 3 hole-punching packets directly from the SAME socket bound to Quinn.
//   This guarantees the router's NAT mapping matches the Quinn endpoint's external port.

// TODO 3: DYNAMIC IPAM & VIRTUAL IP ALLOCATION
// ------------------------------------------------------------------------------
// CURRENT: Hardcoded VIP toggle (`if vip == "10.99.0.1" { "10.99.0.2" }`).
// PRODUCTION STRATEGY:
// - Implement a mesh IPAM (IP Address Management) table or deterministic hash-to-IP
//   mapping (e.g., mapping the first 3 bytes of the SHA-256(PublicKey) to 10.99.X.Y).
// - Maintain a dynamic `PeerRoutingTable` associating `PeerPublicKey` -> `VirtualIP`.

// TODO 5: GRACEFUL SHUTDOWN & CLEANUP HOOKS
// ------------------------------------------------------------------------------
// CURRENT: Process termination leaves the UDS socket file and UPnP mappings active.
// PRODUCTION STRATEGY:
// - Trap `tokio::signal::ctrl_c()` and `SIGTERM`.
// - On shutdown:
//     1. Call `nat::upnp::remove_external_port(local_port)`.
//     2. Remove `/tmp/decentis_{port}.sock`.
//     3. Bring down and delete the TUN network interface cleanly.
//     4. Notify the signaling server with a `Disconnect` event.

// TODO 6: SIGNALING RECONNECT RESILIENCE & EXPONENTIAL BACKOFF
// ------------------------------------------------------------------------------
// CURRENT: Single-shot `start_registration` call.
// PRODUCTION STRATEGY:
// - Wrap the signaling gRPC stream in a supervision loop with exponential backoff
//   (1s, 2s, 4s, ... max 30s) so transient internet drops or signaling restarts
//   do not sever future peer rendezvous.
//
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc; // Shared atomic pointers
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
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

async fn shutdown_signal(token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received! Initiating graceful teardown...");
    token.cancel();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let shutdown_token = CancellationToken::new();

    // Environment configuration
    let port = env::var("PORT").unwrap_or_else(|_| "51820".to_string());
    let _peer_addr = env::var("PEER").ok();
    let peer_pub_b64 = env::var("PEER_PUB").ok();

    let socket_path = format!("/tmp/decentis_{}.sock", port);

    // Load or generate persistent identity
    let identity_path =
        env::var("IDENTITY_PATH").unwrap_or_else(|_| format!("/etc/decentis/node_{}.key", port));
    let raw_key = crypto::identity::load_or_generate_identity(&identity_path)?;

    // --- DYNAMIC IPAM ALLOCATION ---
    let vip = crypto::identity::derive_virtual_ip(&raw_key.public).to_string();

    tracing::info!(
        "Node Identity Loaded. My Public Key: {} -> Assigned VIP: {}",
        b64.encode(&raw_key.public),
        vip
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

    let upnp_mapped = Arc::new(AtomicBool::new(false));
    let upnp_mapped_clone = upnp_mapped.clone();

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

                upnp_mapped_clone.store(true, Ordering::SeqCst);
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
    let _vip_for_dialer = vip.clone();
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

                                // Derive their VIP dynamically from their public key!
                                let peer_vip =
                                    crypto::identity::derive_virtual_ip(&remote_pub).to_string();
                                tracing::info!("Registering peer {} in routing table.", peer_vip);

                                peer_registry_for_dialer
                                    .write()
                                    .await
                                    .insert(peer_vip, conn.clone());

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
    let quic_endpoint_listener = quic_endpoint.clone();
    let active_tun_listener = active_tun.clone();
    let registry_for_listener = registry_for_network.clone();
    let local_key_listener = local_key.clone();
    let save_dir_listener = save_dir.clone();
    let _vip_listener = vip.clone();
    let inbound_peer_filter = peer_pub_b64.clone();

    tokio::spawn(async move {
        tracing::info!("Awaiting inbound P2P socket allocations...");
        while let Some(incoming) = quic_endpoint_listener.accept().await {
            let active_tun = active_tun_listener.clone();
            let local_key = local_key_listener.clone();
            let registry_ref = registry_for_listener.clone();
            let save_dir_ref = save_dir_listener.clone();
            let current_filter = inbound_peer_filter.clone();

            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        tracing::info!("Accepted connection. Awaiting Noise_IK handshake...");

                        // Capture the 3-tuple straight from your updated handshake processor
                        match transport::handshake::respond_noise_handshake(&conn, &local_key).await
                        {
                            Ok((tx, rx, remote_pub)) => {
                                let remote_pub_b64 = b64.encode(&remote_pub);

                                // Run your active verification check boundary
                                if let Some(ref allowed_key) = current_filter {
                                    if allowed_key != &remote_pub_b64 {
                                        tracing::warn!(
                                            "SECURITY ALERT: Rejected unauthorized connection from rogue public key: {}", 
                                            remote_pub_b64
                                        );
                                        conn.close(4001u32.into(), b"Unauthorized Node Public Key");
                                        return;
                                    }
                                }

                                tracing::info!(
                                    "Handshake verified successfully. Establishing secure bridge."
                                );

                                let peer_vip =
                                    crypto::identity::derive_virtual_ip(&remote_pub).to_string();

                                tracing::info!(
                                    "Registering peer {} in secure routing table.",
                                    peer_vip
                                );
                                registry_ref.write().await.insert(peer_vip, conn.clone());

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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o777))
            .expect("Failed to set socket permissions");
    }

    tracing::info!("IPC listening on UDS: {}", socket_path);
    let service = ControlServiceImpl {
        peers: peer_registry,
        local_vip: vip,
    };

    let token_clone = shutdown_token.clone();

    // Use `serve_with_incoming_shutdown` and pass our signal listener
    // Start gRPC server and await the signal trigger
    Server::builder()
        .add_service(DaemonControlServer::new(service))
        .serve_with_incoming_shutdown(
            UnixListenerStream::new(listener),
            shutdown_signal(token_clone),
        )
        .await?;

    // =========================================================
    // TEARDOWN SEQUENCE (Executes after signal is received)
    // =========================================================
    tracing::info!("Shutting down Decentis daemon...");

    // 1. Notify the signaling server with a Disconnect event
    tracing::info!("Notifying signaling server of disconnection...");
    // Assuming your client has a disconnect method or you drop it to close the channel
    if let Err(e) = sig_client.disconnect().await {
        tracing::warn!("Failed to notify signaling server: {:?}", e);
    }

    // 2. Close all active QUIC connections immediately
    quic_endpoint.close(0u32.into(), b"Daemon shutting down");

    // 3. Clean up the Unix Domain Socket file
    if Path::new(&socket_path).exists() {
        if let Err(e) = fs::remove_file(&socket_path) {
            tracing::warn!("Failed to remove UDS socket: {}", e);
        } else {
            tracing::info!("IPC socket removed.");
        }
    }

    // 4. Release the UPnP router port mapping if we created one
    if upnp_mapped.load(Ordering::SeqCst) {
        tracing::info!("Releasing UPnP port mapping from router...");
        if let Err(e) = nat::upnp::remove_external_port(local_port).await {
            tracing::warn!("Failed to clean up UPnP: {}", e);
        } else {
            tracing::info!("UPnP mapping cleanly released.");
        }
    }

    // 5. Explicitly drop the TUN device to force the OS to delete the virtual interface
    tracing::info!("Bringing down TUN network interface...");
    drop(tun_dev);

    tracing::info!("Cleanup complete. Goodbye!");
    Ok(())
}
