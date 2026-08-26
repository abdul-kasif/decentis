use anyhow::Result;
use bytes::BytesMut;
use quinn::Connection;
use std::sync::Arc;
use tracing::{error, info, trace};
use tun_rs::AsyncDevice;

use crate::crypto::session::{SessionRx, SessionTx};
use crate::transport::frame::{FrameHeader, TYPE_L3_TUN_DATAGRAM}; // Cleaned up unused imports

pub async fn start_secure_datagram_bridge(
    conn: Connection,
    tun_dev: Arc<AsyncDevice>,
    mut tx_session: SessionTx,
    mut rx_session: SessionRx,
) -> Result<()> {
    let tun_read = tun_dev.clone();
    let tun_write = tun_dev;
    let conn_write = conn.clone();
    let conn_read = conn;

    // Task 1: TUN -> Encrypt -> QUIC
    tokio::spawn(async move {
        let mut tun_buf = vec![0u8; 1500];
        let mut cipher_buf = vec![0u8; 2000];

        loop {
            match tun_read.recv(&mut tun_buf).await {
                Ok(len) => {
                    let plaintext = &tun_buf[..len];

                    // 1. Encrypt the payload (🔥 FIX: Added .await)
                    // Note: We use an inner block or local variable to avoid holding references across loops
                    match tx_session.encrypt(plaintext, &mut cipher_buf).await {
                        Ok((seq, cipher_len)) => {
                            // 2. Build the framing header
                            let header = FrameHeader {
                                frame_type: TYPE_L3_TUN_DATAGRAM,
                                flags: 0,
                                stream_id: 0,
                                seq_num: seq,
                            };

                            // 3. Serialize Header + Ciphertext
                            let mut packet = BytesMut::with_capacity(10 + cipher_len);
                            header.encode(&mut packet);
                            packet.extend_from_slice(&cipher_buf[..cipher_len]);

                            // 4. Transmit!
                            if let Err(e) = conn_write.send_datagram(packet.freeze()) {
                                error!("Failed to dispatch encrypted datagram: {}", e);
                                break;
                            }
                        }
                        Err(e) => error!("Encryption error: {}", e),
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN device: {}", e);
                    break;
                }
            }
        }
    });

    // Task 2: QUIC -> Decrypt -> TUN
    tokio::spawn(async move {
        let mut plain_buf = vec![0u8; 2000];

        loop {
            match conn_read.read_datagram().await {
                Ok(datagram) => {
                    let mut cursor = std::io::Cursor::new(&datagram);

                    // 1. Decode and verify the frame header
                    match FrameHeader::decode(&mut cursor) {
                        Ok(header) => {
                            if header.frame_type != TYPE_L3_TUN_DATAGRAM {
                                trace!("Ignoring non-L3 datagram");
                                continue;
                            }

                            let ciphertext_offset = cursor.position() as usize;
                            let ciphertext = &datagram[ciphertext_offset..];

                            // 2. Anti-Replay Check & Decrypt
                            match rx_session
                                .decrypt(header.seq_num, ciphertext, &mut plain_buf)
                                .await
                            {
                                Ok(plain_len) => {
                                    // 3. Inject into the OS Kernel
                                    if let Err(e) = tun_write.send(&plain_buf[..plain_len]).await {
                                        error!("Failed to inject decrypted packet into TUN: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => trace!("Decryption/Replay block: {}", e),
                            }
                        }
                        Err(e) => trace!("Malformed frame header received: {}", e),
                    }
                }
                Err(e) => {
                    error!("QUIC stream disconnected: {}", e);
                    break;
                }
            }
        }
    });

    info!("Secure Encrypted L3 Bridge established!");
    Ok(())
}
