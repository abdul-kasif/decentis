use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::Connection;
use snow::Keypair;

use crate::crypto::handshake::{build_initiator, build_responder};
use crate::crypto::session::{split_session, SessionRx, SessionTx};

/// Initiator (Dialer) executes this immediately after connecting.
pub async fn initiate_noise_handshake(
    conn: &Connection,
    local_key: &Arc<Keypair>,
    remote_pub: &[u8],
) -> Result<(SessionTx, SessionRx)> {
    // 1. Open a reliable bi-directional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut initiator = build_initiator(local_key, remote_pub)?;

    let mut buf = vec![0u8; 1024];

    // 2. Generate and Send Init Payload (contains ephemeral key + encrypted static key)
    let len = initiator.write_message(&[], &mut buf)?;
    send.write_all(&buf[..len]).await?;

    // 3. Wait for Responder's Reply
    let mut resp_buf = vec![0u8; 1024];
    let resp_len = recv
        .read(&mut resp_buf)
        .await?
        .context("Stream closed prematurely")?;

    // 4. Process Reply & Establish Keys
    initiator.read_message(&resp_buf[..resp_len], &mut buf)?;

    let transport = initiator.into_stateless_transport_mode()?;

    send.finish()?;

    Ok(split_session(transport))
}

/// Responder (Listener) executes this upon accepting a connection.
pub async fn respond_noise_handshake(
    conn: &Connection,
    local_key: &Arc<Keypair>,
) -> Result<(SessionTx, SessionRx)> {
    // 1. Accept the incoming bi-directional stream
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut responder = build_responder(local_key)?;

    let mut init_buf = vec![0u8; 1024];
    let mut buf = vec![0u8; 1024];

    // 2. Receive Init Payload
    let init_len = recv
        .read(&mut init_buf)
        .await?
        .context("Stream closed prematurely")?;
    responder.read_message(&init_buf[..init_len], &mut buf)?;

    // 3. Generate and Send Reply Payload (completes Diffie-Hellman)
    let resp_len = responder.write_message(&[], &mut buf)?;
    send.write_all(&buf[..resp_len]).await?;

    let transport = responder.into_stateless_transport_mode()?;

    send.finish()?;

    Ok(split_session(transport))
}
