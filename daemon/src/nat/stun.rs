use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::info;

const STUN_SERVER: &str = "stun.l.google.com:19302";
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// Queries a public STUN server to discover the NAT's external IP address.
pub async fn discover_public_ip() -> Result<SocketAddr> {
    info!(
        "Tier 2 Traversal: Querying STUN server at {}...",
        STUN_SERVER
    );

    // Bind to a temporary ephemeral UDP port for the discovery probe
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(STUN_SERVER).await?;

    // 1. Build a raw STUN Binding Request (RFC 5389)
    let mut request = vec![0u8; 20];
    request[0..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Message Type: Binding Request
    request[2..4].copy_from_slice(&0x0000u16.to_be_bytes()); // Message Length: 0
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes()); // Magic Cookie

    // Generate a random 12-byte Transaction ID
    let transaction_id: [u8; 12] = rand::random();
    request[8..20].copy_from_slice(&transaction_id);

    // 2. Transmit the probe
    socket.send(&request).await?;

    // 3. Await the response with a 3-second timeout
    let mut buf = vec![0u8; 1024];
    let len = timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("STUN request timed out"))??;

    let response = &buf[..len];

    // 4. Parse the STUN Response
    if response.len() < 20 {
        return Err(anyhow!("STUN response too short"));
    }

    let msg_type = u16::from_be_bytes([response[0], response[1]]);
    if msg_type != 0x0101 {
        // 0x0101 = Binding Success Response
        return Err(anyhow!("Unexpected STUN message type: {:#06x}", msg_type));
    }

    // Iterate through STUN attributes to find the XOR-MAPPED-ADDRESS (0x0020)
    let mut offset = 20;
    while offset + 4 <= response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        offset += 4;

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            if response[offset + 1] == 0x01 {
                // IPv4 Family
                let port_xor = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
                let ip_xor = u32::from_be_bytes([
                    response[offset + 4],
                    response[offset + 5],
                    response[offset + 6],
                    response[offset + 7],
                ]);

                // Undo the XOR cipher using the Magic Cookie
                let port = port_xor ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                let ip_raw = ip_xor ^ STUN_MAGIC_COOKIE;

                let ip = IpAddr::V4(Ipv4Addr::from(ip_raw));
                let external_addr = SocketAddr::new(ip, port);

                info!(
                    "STUN Success! Public IP resolved to: {}",
                    external_addr.ip()
                );
                return Ok(external_addr);
            }
        }

        offset += attr_len;
        // STUN attributes are padded to 4-byte boundaries
        let padding = (4 - (attr_len % 4)) % 4;
        offset += padding;
    }

    Err(anyhow!(
        "XOR-MAPPED-ADDRESS attribute not found in STUN response"
    ))
}
