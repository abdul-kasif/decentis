use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};
use tun_rs::DeviceBuilder;

pub async fn start_tun_device() -> Result<()> {
    info!("Initializing TUN interface...");

    // 1. Build and instantiate the AsyncDevice
    let dev = DeviceBuilder::new()
        .name("mesh0")
        .ipv4("10.99.0.1", "255.255.255.0", None)
        .mtu(1420)
        .build_async()?;

    info!("Virtual interface 'mesh0' successfully created and bound to 10.99.0.1");

    // 2. Wrap the interface in an Arc to safely share it across tasks
    let dev = Arc::new(dev);
    let read_dev = dev.clone();

    // 3. Spawn a background Tokio task to continuously read intercepted L3 packets
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];

        loop {
            match read_dev.recv(&mut buf).await {
                Ok(len) => {
                    let packet = &buf[..len];

                    // Basic IPv4 Parsing (First nibble = Version)
                    if packet.len() > 20 && (packet[0] >> 4) == 4 {
                        let proto = packet[9]; // Protocol field
                        let src = &packet[12..16];
                        let dst = &packet[16..20];

                        info!(
                            "Intercepted IPv4 | Src: {}.{}.{}.{} -> Dst: {}.{}.{}.{} | Proto: {} | Len: {} bytes",
                            src[0], src[1], src[2], src[3],
                            dst[0], dst[1], dst[2], dst[3],
                            proto,
                            len
                        );
                    }
                }
                Err(e) => {
                    error!("Error reading from TUN device: {}", e);
                    break;
                }
            }
        }
    });

    Ok(())
}
