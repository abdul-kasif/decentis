use anyhow::{anyhow, Context, Result};
use snow::Keypair;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Loads a persistent Noise keypair from disk, or generates and saves a new one if it doesn't exist.
pub fn load_or_generate_identity(path: impl AsRef<Path>) -> Result<Keypair> {
    let path = path.as_ref();

    // 1. Direct secure open attempt to eliminate TOCTOU race conditions
    match fs::File::open(path) {
        Ok(mut file) => {
            info!("Found existing cryptographic identity at {:?}", path);
            let mut data = Vec::with_capacity(64);
            file.read_to_end(&mut data)?;

            // A Curve25519 Keypair contains exactly 32 bytes public + 32 bytes private = 64 bytes
            if data.len() == 64 {
                let public = data[0..32].to_vec();
                let private = data[32..64].to_vec();
                return Ok(Keypair { public, private });
            } else {
                warn!(
                    "Identity file size mismatch ({} bytes)! Re-generating...",
                    data.len()
                );
            }
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            info!("Identity file absent. Proceeding with keypair creation...");
        }
        Err(e) => {
            return Err(anyhow!(e).context(format!(
                "Failed to read existing identity file at {:?}",
                path
            )));
        }
    }

    // 2. Generate a new identity safely
    info!("Generating new persistent cryptographic identity...");
    let builder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?);
    let keypair = builder.generate_keypair()?;

    // Ensure the destination parent directory tree exists securely
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(format!(
            "Failed to create identity parent directory: {:?}",
            parent
        ))?;
    }

    // 3. Setup secure atomic write operations across platforms
    let tmp_path = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    // Apply strict 0600 permissions safely on POSIX/Linux configurations only
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(&tmp_path)
        .context("Failed to open temporary identity file for secure writing")?;

    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&keypair.public);
    data.extend_from_slice(&keypair.private);

    // Flush completely to the temporary path before committing
    file.write_all(&data)?;
    file.sync_all()?;
    drop(file);

    // Atomic filesystem swap guarantees that identity files are never left half-written
    fs::rename(&tmp_path, path)
        .context("Failed to atomically swap temporary identity file into final destination")?;

    info!(
        "Identity saved securely with 0600 permissions to {:?}",
        path
    );
    Ok(keypair)
}
