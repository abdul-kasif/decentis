use anyhow::Result;
use std::sync::Arc;
use tracing::info;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub async fn start_tun_device(vip: &str) -> Result<Arc<AsyncDevice>> {
    info!("Initializing TUN interface with IP {}...", vip);

    // Build and instantiate the AsyncDevice using the provided Virtual IP
    let dev = DeviceBuilder::new()
        .name(format!("mesh{}", vip.replace(".", ""))) // Note: On Linux, running multiple instances might require unique names like mesh0, mesh1. For local testing, we will use default OS behavior.
        .ipv4(vip, "255.255.255.0", None)
        .mtu(1420)
        .build_async()?;

    info!(
        "Virtual interface successfully created and bound to {}",
        vip
    );

    Ok(Arc::new(dev))
}
