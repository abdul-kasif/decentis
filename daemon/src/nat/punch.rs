use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tracing::info;

/// Fires ~128 simultaneous UDP probes to a target IP across a predicted port range.
/// This forces the local NAT to proactively open outbound firewall mappings (Hole Punching).
pub async fn fire_prediction_probes(target_ip: IpAddr, target_base_port: u16) -> Result<()> {
    info!("Tier 3 Traversal: Initiating Symmetric NAT Port Prediction barrage...");

    // In a production scenario, we would use the exact same socket that Quinn is bound to
    // (via socket2 and SO_REUSEPORT). For this implementation, we bind an ephemeral socket
    // to rapidly populate the router's NAT translation tables.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // A tiny, recognizable payload so the peer can drop it instantly if it accidentally reads it
    let magic_probe = b"DECENTIS_PUNCH";

    // Calculate a window of 128 ports around the target's base port
    let start_port = target_base_port.saturating_sub(64).max(1024);
    let end_port = target_base_port.saturating_add(63);

    let mut probes_fired = 0;

    // Fire a barrage of UDP packets. We don't await responses; this is "fire and forget"
    // to punch outgoing holes in our local firewall.
    for port in start_port..=end_port {
        let target = SocketAddr::new(target_ip, port);
        if socket.send_to(magic_probe, target).await.is_ok() {
            probes_fired += 1;
        }
    }

    info!(
        "Tier 3 Traversal: Fired {} UDP hole-punching probes to {}:[{}..{}]",
        probes_fired, target_ip, start_port, end_port
    );

    Ok(())
}
