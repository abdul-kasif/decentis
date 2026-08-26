use anyhow::Result;
use bytes::Bytes;
use quinn::Connection;
use std::sync::Arc;
use tracing::{error, info};
use tun_rs::AsyncDevice;

pub async fn start_datagram_bridge(conn: Connection, tun_dev: Arc<AsyncDevice>) -> Result<()> {
    let tun_read = tun_dev.clone();
    let tun_write = tun_dev;
    let conn_write = conn.clone();
    let conn_read = conn;

    // Task 1: Intercept L3 packets from OS and transmit via QUIC Datagrams
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match tun_read.recv(&mut buf).await {
                Ok(len) => {
                    // Zero-copy abstraction: slice the buffer into Bytes
                    let packet = Bytes::copy_from_slice(&buf[..len]);

                    if let Err(e) = conn_write.send_datagram(packet) {
                        error!("Failed to dispatch QUIC datagram: {}", e);
                        break; // Connection likely dropped
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN device: {}", e);
                    break;
                }
            }
        }
    });

    // Task 2: Receive QUIC Datagrams from peer and inject into OS networking stack
    tokio::spawn(async move {
        loop {
            match conn_read.read_datagram().await {
                Ok(datagram) => {
                    if let Err(e) = tun_write.send(&datagram).await {
                        error!("Failed to inject packet into TUN: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("QUIC stream disconnected: {}", e);
                    break;
                }
            }
        }
    });

    info!("L3 Network Bridge established over QUIC Unreliable Datagrams");
    Ok(())
}
