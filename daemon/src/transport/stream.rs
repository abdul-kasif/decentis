use crate::proto::TransferProgress;
use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn::Connection;
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{error, info, trace};

use crate::file_relay::chunker::FileChunker;
use crate::file_relay::manifest::{ChunkPayload, FileManifest};
use crate::file_relay::writer::DiskWriter;
use crate::transport::frame::{FrameHeader, TYPE_FILE_CHUNK_PAYLOAD, TYPE_FILE_MANIFEST};

/// Initiates a file transfer to a connected peer over a new QUIC Uni-directional stream.
pub async fn send_file(
    conn: &Connection,
    mut chunker: FileChunker,
    progress_tx: mpsc::Sender<Result<TransferProgress, tonic::Status>>,
) -> Result<()> {
    let mut send_stream = conn
        .open_uni()
        .await
        .context("Failed to open QUIC stream")?;

    let (transfer_id, total_chunks, file_size, manifest_bytes) = {
        let manifest = chunker.manifest();
        (
            manifest.transfer_id.clone(),
            manifest.total_chunks,
            manifest.file_size,
            manifest.to_bytes()?,
        )
    }; // The immutable reference to 'manifest' drops right here!

    // Send Manifest Frame
    let manifest_header = FrameHeader {
        frame_type: TYPE_FILE_MANIFEST,
        flags: 0,
        stream_id: 0,
        seq_num: 0,
    };
    let mut header_buf = BytesMut::with_capacity(10);
    manifest_header.encode(&mut header_buf);

    send_stream.write_all(&header_buf).await?;
    send_stream
        .write_all(&(manifest_bytes.len() as u32).to_be_bytes())
        .await?;
    send_stream.write_all(&manifest_bytes).await?;

    let start_time = Instant::now();
    let mut bytes_sent = 0u64;

    for i in 0..total_chunks {
        let (chunk_meta, chunk_data) = chunker.read_chunk(i).await?;
        let chunk_meta_bytes = chunk_meta.to_bytes()?;

        let chunk_header = FrameHeader {
            frame_type: TYPE_FILE_CHUNK_PAYLOAD,
            flags: 0,
            stream_id: 0,
            seq_num: i,
        };
        header_buf.clear();
        chunk_header.encode(&mut header_buf);

        send_stream.write_all(&header_buf).await?;
        send_stream
            .write_all(&(chunk_meta_bytes.len() as u32).to_be_bytes())
            .await?;
        send_stream.write_all(&chunk_meta_bytes).await?;
        send_stream.write_all(&chunk_data).await?;

        bytes_sent += chunk_data.len() as u64;

        // Send progress update to gRPC every 50 chunks or on the last chunk
        if i % 50 == 0 || i == total_chunks - 1 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed_mbps = if elapsed > 0.0 {
                (bytes_sent as f64 * 8.0 / 1_000_000.0) / elapsed
            } else {
                0.0
            };

            let progress = TransferProgress {
                transfer_id: transfer_id.clone(),
                bytes_transferred: bytes_sent,
                total_bytes: file_size,
                speed_mbps,
                status: if i == total_chunks - 1 {
                    "COMPLETED".into()
                } else {
                    "STREAMING".into()
                },
            };

            if progress_tx.send(Ok(progress)).await.is_err() {
                break; // gRPC client disconnected
            }
        }
    }

    send_stream.finish()?;
    Ok(())
}

/// Spawns a background listener on the QUIC connection to accept incoming file streams.
pub fn spawn_incoming_stream_listener(conn: Connection, save_directory: PathBuf) {
    tokio::spawn(async move {
        info!("Listening for incoming file transfers...");

        // Loop continuously to accept multiple streams (multiple files)
        while let Ok(mut recv_stream) = conn.accept_uni().await {
            let save_dir = save_directory.clone();

            // Spawn a dedicated task for each incoming file to allow parallel transfers
            tokio::spawn(async move {
                let mut header_buf = [0u8; 10];
                let mut writer: Option<DiskWriter> = None;

                loop {
                    // 1. Read the Frame Header
                    if recv_stream.read_exact(&mut header_buf).await.is_err() {
                        break; // Stream closed gracefully
                    }

                    let mut cursor = std::io::Cursor::new(&header_buf[..]);
                    let header = match FrameHeader::decode(&mut cursor) {
                        Ok(h) => h,
                        Err(e) => {
                            error!("Stream frame decode error: {}", e);
                            break;
                        }
                    };

                    // 2. Read the dynamic payload size
                    let mut size_buf = [0u8; 4];
                    if recv_stream.read_exact(&mut size_buf).await.is_err() {
                        break;
                    }
                    let payload_size = u32::from_be_bytes(size_buf) as usize;
                    let mut payload_buf = vec![0u8; payload_size];
                    if recv_stream.read_exact(&mut payload_buf).await.is_err() {
                        break;
                    }

                    // 3. Process based on Frame Type
                    match header.frame_type {
                        TYPE_FILE_MANIFEST => {
                            if let Ok(manifest) = FileManifest::from_bytes(&payload_buf) {
                                info!(
                                    "Receiving incoming file: {} ({} bytes)",
                                    manifest.file_name, manifest.file_size
                                );
                                match DiskWriter::new(&save_dir, manifest).await {
                                    Ok(w) => writer = Some(w),
                                    Err(e) => error!("Failed to initialize disk writer: {}", e),
                                }
                            }
                        }
                        TYPE_FILE_CHUNK_PAYLOAD => {
                            if let Some(w) = writer.as_mut() {
                                if let Ok(chunk_meta) = ChunkPayload::from_bytes(&payload_buf) {
                                    // Read the actual binary file data following the metadata
                                    let mut raw_chunk =
                                        vec![0u8; chunk_meta.payload_length as usize];
                                    if recv_stream.read_exact(&mut raw_chunk).await.is_ok() {
                                        if let Err(e) =
                                            w.write_chunk(chunk_meta.chunk_index, &raw_chunk).await
                                        {
                                            error!("Disk write error: {}", e);
                                        }

                                        if w.is_complete() {
                                            info!("File received and verified successfully!");
                                        }
                                    }
                                }
                            }
                        }
                        _ => trace!("Unknown frame type on file stream: {}", header.frame_type),
                    }
                }
            });
        }
    });
}
