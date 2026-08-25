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
        tracing::info!("Received GetStatus request from CLI");

        let response = StatusResponse {
            virtual_ip: "10.99.0.1".to_string(),
            is_active: true,
            active_peers: 0,
        };

        Ok(Response::new(response))
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

    let socket_path = "/tmp/decentis.sock";

    // Clean up stale socket file if it exists
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("Decentis Daemon IPC listening on UDS: {}", socket_path);

    let stream = UnixListenerStream::new(listener);
    let service = ControlServiceImpl::default();

    Server::builder()
        .add_service(DaemonControlServer::new(service))
        .serve_with_incoming(stream)
        .await?;

    Ok(())
}
