use anyhow::{Context, Result};
use snow::{Builder, HandshakeState, Keypair};

// We use Curve25519 for DH, ChaCha20-Poly1305 for AEAD, and BLAKE2s for hashing.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Generates a new static Curve25519 keypair for a Decentis node.
pub fn generate_static_keypair() -> Result<Keypair> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    Ok(keypair)
}

/// Creates a Noise_IK Initiator state.
/// The initiator MUST know the responder's static public key in advance.
pub fn build_initiator(local_keypair: &Keypair, remote_pub_key: &[u8]) -> Result<HandshakeState> {
    let state = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&local_keypair.private)?
        .remote_public_key(remote_pub_key)?
        .build_initiator()
        .context("Failed to build Noise_IK initiator state")?;
    Ok(state)
}

/// Creates a Noise_IK Responder state.
/// The responder does not know the initiator's identity until the first packet arrives.
pub fn build_responder(local_keypair: &Keypair) -> Result<HandshakeState> {
    let state = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&local_keypair.private)?
        .build_responder()
        .context("Failed to build Noise_IK responder state")?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_ik_handshake() -> Result<()> {
        // 1. Generate keys for Node A (Initiator) and Node B (Responder)
        let key_a = generate_static_keypair()?;
        let key_b = generate_static_keypair()?;

        // 2. Initialize states. Node A knows Node B's public key.
        let mut initiator = build_initiator(&key_a, &key_b.public)?;
        let mut responder = build_responder(&key_b)?;

        let mut buf_a = vec![0u8; 65535];
        let mut buf_b = vec![0u8; 65535];

        // --- HANDSHAKE PHASE ---

        // Step 1: Initiator -> Responder (writes the IK init frame)
        let len_1 = initiator.write_message(&[], &mut buf_a)?;

        // Step 2: Responder reads the frame. It now knows who the Initiator is.
        responder.read_message(&buf_a[..len_1], &mut buf_b)?;

        // Step 3: Responder -> Initiator (writes the IK response frame)
        let len_2 = responder.write_message(&[], &mut buf_a)?;

        // Step 4: Initiator reads the response.
        initiator.read_message(&buf_a[..len_2], &mut buf_b)?;

        // --- TRANSPORT PHASE ---
        // Both sides should now automatically transition into Stateless Transport mode
        let transport_a = initiator.into_stateless_transport_mode()?;
        let transport_b = responder.into_stateless_transport_mode()?;

        // Test encryption/decryption
        let secret_msg = b"Decentis Zero-Trust Payload";
        let mut ciphertext = vec![0u8; 65535];
        let mut plaintext = vec![0u8; 65535];

        // Node A encrypts
        let cipher_len = transport_a.write_message(0, secret_msg, &mut ciphertext)?;

        // Node B decrypts
        let plain_len = transport_b.read_message(0, &ciphertext[..cipher_len], &mut plaintext)?;

        assert_eq!(&plaintext[..plain_len], secret_msg);

        Ok(())
    }
}
