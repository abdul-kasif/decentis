use std::env;
use std::fs;
use std::path::Path;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};

pub mod proto {
    tonic::include_proto!("decentis.v1");
}

use proto::daemon_control_server::{DaemonControl, DaemonControlServer};
use proto::{SendFileRequest, StatusRequest, StatusResponse, TransferProgress};

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

    // Environment configuration for local testing
    let vip = env::var("VIP").unwrap_or_else(|_| "10.99.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "51820".to_string());
    let peer_addr = env::var("PEER").ok();

    // UDS path varies to avoid collisions when running 2 local nodes
    let socket_path = format!("/tmp/decentis_{}.sock", port);

    // 1. Initialize the TUN Device
    let tun_dev = tun::device::start_tun_device(&vip).await?;

    // 2. Initialize QUIC Endpoint
    let bind_addr = format!("0.0.0.0:{}", port).parse().unwrap();
    let endpoint = transport::endpoint::create_quic_endpoint(bind_addr)?;

    // 3. Establish P2P Connection (Hardcoded for Step 5 testing)
    let quic_endpoint = endpoint.clone();
    let active_tun = tun_dev.clone();

    tokio::spawn(async move {
        if let Some(peer) = peer_addr {
            let addr = peer.parse().unwrap();
            tracing::info!("Dialing peer at {}...", addr);
            let conn = quic_endpoint
                .connect(addr, "decentis.local")
                .unwrap()
                .await
                .unwrap();
            tracing::info!("Connected to peer!");

            let _ = transport::datagram::start_datagram_bridge(conn, active_tun).await;
        } else {
            tracing::info!("Waiting for incoming P2P connections...");
            // Run a continuous loop so your node can accept multi-peer links
            // and gracefully handle client reconnection flows.
            while let Some(incoming) = quic_endpoint.accept().await {
                let active_tun = active_tun.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            tracing::info!(
                                "Accepted connection from peer at: {}",
                                conn.remote_address()
                            );
                            let _ =
                                transport::datagram::start_datagram_bridge(conn, active_tun).await;
                        }
                        Err(err) => {
                            tracing::error!("Failed to complete inbound handshake: {:?}", err);
                        }
                    }
                });
            }
        }
    });

    // 4. Start IPC Server
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
