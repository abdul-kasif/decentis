use base64::{engine::general_purpose::STANDARD as b64, Engine};
use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};

pub mod proto {
    tonic::include_proto!("decentis.v1");
}

use proto::daemon_control_server::{DaemonControl, DaemonControlServer};
use proto::{SendFileRequest, StatusRequest, StatusResponse, TransferProgress};

mod crypto;
mod file_relay;
mod transport;
mod tun;

#[derive(Default)]
pub struct ControlServiceImpl;

#[tonic::async_trait]
impl DaemonControl for ControlServiceImpl {
    type InitiateSendStream =
        tokio_stream::wrappers::ReceiverStream<Result<TransferProgress, Status>>;

    async fn get_status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse {
            virtual_ip: "10.99.0.x".to_string(),
            is_active: true,
            active_peers: 1,
        }))
    }

    async fn initiate_send(
        &self,
        _request: Request<SendFileRequest>,
    ) -> Result<Response<Self::InitiateSendStream>, Status> {
        Err(Status::unimplemented(
            "File transfer pipeline not initialized yet",
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

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

    let local_key = Arc::new(raw_key);

    // 1. Initialize the TUN Device
    let tun_dev = tun::device::start_tun_device(&vip).await?;

    // 2. Initialize QUIC Endpoint
    let bind_addr = format!("0.0.0.0:{}", port).parse().unwrap();
    let endpoint = transport::endpoint::create_quic_endpoint(bind_addr)?;

    let quic_endpoint = endpoint.clone();
    let active_tun = tun_dev.clone();

    tokio::spawn(async move {
        if let Some(peer) = peer_addr {
            // DIALER LOGIC
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
                    let _ =
                        transport::datagram::start_secure_datagram_bridge(conn, active_tun, tx, rx)
                            .await;
                }
                Err(e) => tracing::error!("Noise_IK handshake failed: {:?}", e),
            }
        } else {
            // LISTENER LOGIC
            tracing::info!("Waiting for incoming P2P connections...");
            while let Some(incoming) = quic_endpoint.accept().await {
                let active_tun = active_tun.clone();
                let local_key = local_key.clone();

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

    // 3. Start IPC Server
    if Path::new(&socket_path).exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("IPC listening on UDS: {}", socket_path);

    Server::builder()
        .add_service(DaemonControlServer::new(ControlServiceImpl))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;

    Ok(())
}
