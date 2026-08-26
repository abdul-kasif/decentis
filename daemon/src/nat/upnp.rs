use anyhow::{anyhow, Result};
use igd_next::SearchOptions;
use std::net::{SocketAddr, SocketAddrV4};
use tracing::info;

/// Attempts to negotiate a public port forward with the local router via UPnP.
/// Returns the external, publicly reachable IP and Port tuple.
pub async fn map_external_port(local_port: u16) -> Result<SocketAddr> {
    info!("Tier 1 Traversal: Searching for UPnP Internet Gateway Device...");

    // Search for the router's UPnP entrypoint
    let gateway =
        tokio::task::spawn_blocking(move || igd_next::search_gateway(SearchOptions::default()))
            .await?
            .map_err(|e| anyhow!("UPnP Gateway not found on local network: {}", e))?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_ip = match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(anyhow!("IPv6 gateway mapping is currently unsupported")),
    };

    let local_addr = SocketAddrV4::new(local_ip, local_port);
    info!("UPnP Gateway found! Our local IP is {}", local_ip);

    // Request the port mapping.
    let ext_port = local_port;
    let gw_clone = gateway.clone();

    tokio::task::spawn_blocking(move || {
        gw_clone.add_port(
            igd_next::PortMappingProtocol::UDP,
            ext_port,
            SocketAddr::V4(local_addr),
            86400,
            "Decentis Mesh UDP",
        )
    })
    .await?
    .map_err(|e| anyhow!("Router rejected UPnP port mapping: {}", e))?;

    // We map it using a match statement to guarantee a valid Ipv4Addr structure.
    let external_ip_raw = tokio::task::spawn_blocking(move || gateway.get_external_ip())
        .await?
        .map_err(|e| anyhow!("Failed to fetch external IP from router: {}", e))?;

    let external_ip = match external_ip_raw {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(anyhow!("Router returned unsupported IPv6 public address")),
    };

    let external_addr = SocketAddr::V4(SocketAddrV4::new(external_ip, ext_port));
    info!(
        "UPnP Success! Node is externally reachable at: {}",
        external_addr
    );

    Ok(external_addr)
}

/// Removes the port mapping cleanly on shutdown
pub async fn remove_external_port(local_port: u16) -> Result<()> {
    let gateway =
        tokio::task::spawn_blocking(move || igd_next::search_gateway(SearchOptions::default()))
            .await?
            .map_err(|e| anyhow!("UPnP Gateway not found during shutdown removal: {}", e))?;

    tokio::task::spawn_blocking(move || {
        gateway.remove_port(igd_next::PortMappingProtocol::UDP, local_port)
    })
    .await?
    .map_err(|e| anyhow!("Failed to cleanly close UPnP mapping on router: {}", e))?;

    info!("UPnP port mapping gracefully removed.");
    Ok(())
}
