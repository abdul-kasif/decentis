use super::replay::ReplayFilter;
use anyhow::{anyhow, Result};
use snow::StatelessTransportState;
use std::sync::Arc;
use tokio::sync::Mutex;

// Clone the outer Arc wrapper to provide clean tx/rx separation handles
#[derive(Clone)]
pub struct SessionTx {
    state: Arc<Mutex<StatelessTransportState>>,
    tx_seq: u32,
}

impl SessionTx {
    pub async fn encrypt(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(u32, usize)> {
        let seq = self.tx_seq;
        self.tx_seq = self.tx_seq.wrapping_add(1);

        // Lock the internal crypto state across the message write operation
        let mut state = self.state.lock().await;
        let len = state
            .write_message(seq as u64, plaintext, ciphertext)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        Ok((seq, len))
    }
}

pub struct SessionRx {
    state: Arc<Mutex<StatelessTransportState>>,
    replay_filter: ReplayFilter,
}

impl SessionRx {
    pub async fn decrypt(
        &mut self,
        seq: u32,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        // Evaluate the anti-replay window first before acquiring a mutex lock
        if !self.replay_filter.check_and_mark(seq as u64) {
            return Err(anyhow!("Packet dropped by replay filter (seq: {})", seq));
        }

        let mut state = self.state.lock().await;
        let len = state
            .read_message(seq as u64, ciphertext, plaintext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        Ok(len)
    }
}

/// Splits a stateless transport into thread-safe thread-shared Tx and Rx handles.
pub fn split_session(transport: StatelessTransportState) -> (SessionTx, SessionRx) {
    let shared_state = Arc::new(Mutex::new(transport));

    (
        SessionTx {
            state: shared_state.clone(),
            tx_seq: 0,
        },
        SessionRx {
            state: shared_state,
            replay_filter: ReplayFilter::new(),
        },
    )
}
