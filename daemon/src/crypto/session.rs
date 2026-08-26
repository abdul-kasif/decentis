use super::replay::ReplayFilter;
use anyhow::{anyhow, Result};
use snow::StatelessTransportState;

/// Manages an active cryptographic session with a peer.
pub struct ActiveSession {
    transport: StatelessTransportState,
    replay_filter: ReplayFilter,
    tx_seq: u64,
}

impl ActiveSession {
    /// Creates a new ActiveSession from a completed Noise_IK handshake.
    pub fn new(transport: StatelessTransportState) -> Self {
        Self {
            transport,
            replay_filter: ReplayFilter::new(),
            tx_seq: 0,
        }
    }

    /// Encrypts a plaintext payload.
    /// Returns the sequence number used and the length of the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(u64, usize)> {
        let seq = self.tx_seq;
        self.tx_seq += 1; // Monotonically increase for the next packet

        let len = self
            .transport
            .write_message(seq, plaintext, ciphertext)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        Ok((seq, len))
    }

    /// Decrypts a ciphertext payload.
    /// Checks the anti-replay window FIRST before allocating CPU cycles to decryption.
    pub fn decrypt(&mut self, seq: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize> {
        // 1. Check the replay filter
        if !self.replay_filter.check_and_mark(seq) {
            return Err(anyhow!("Packet dropped by replay filter (seq: {})", seq));
        }

        // 2. Perform ChaCha20-Poly1305 decryption and MAC authentication
        let len = self
            .transport
            .read_message(seq, ciphertext, plaintext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::handshake::{build_initiator, build_responder, generate_static_keypair};

    #[test]
    fn test_secure_session_exchange() -> Result<()> {
        let key_a = generate_static_keypair()?;
        let key_b = generate_static_keypair()?;

        let mut initiator = build_initiator(&key_a, &key_b.public)?;
        let mut responder = build_responder(&key_b)?;

        let mut buf_a = vec![0u8; 1024];
        let mut buf_b = vec![0u8; 1024];

        // Do Handshake
        let len_1 = initiator.write_message(&[], &mut buf_a)?;
        responder.read_message(&buf_a[..len_1], &mut buf_b)?;
        let len_2 = responder.write_message(&[], &mut buf_a)?;
        initiator.read_message(&buf_a[..len_2], &mut buf_b)?;

        // Transition to Sessions
        let mut session_a = ActiveSession::new(initiator.into_stateless_transport_mode()?);
        let mut session_b = ActiveSession::new(responder.into_stateless_transport_mode()?);

        // Test Encryption / Decryption with Replay Filter
        let secret = b"Target acquired.";
        let mut cipher = vec![0u8; 1024];
        let mut plain = vec![0u8; 1024];

        // A encrypts
        let (seq, c_len) = session_a.encrypt(secret, &mut cipher)?;

        // B decrypts
        let p_len = session_b.decrypt(seq, &cipher[..c_len], &mut plain)?;
        assert_eq!(&plain[..p_len], secret);

        // Test Replay Block: B attempts to decrypt the EXACT same packet again
        let replay_result = session_b.decrypt(seq, &cipher[..c_len], &mut plain);
        assert!(
            replay_result.is_err(),
            "Session failed to block a replay attack!"
        );

        Ok(())
    }
}
