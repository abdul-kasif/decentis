use serde::{Deserialize, Serialize};

/// The default chunk size for Decentis file transfers (64 KB)
pub const CHUNK_SIZE: u32 = 65_536;

/// Frame Type 0x05: Sent by the Initiator to announce a new file transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileManifest {
    pub transfer_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub blake3_root_hash: [u8; 32],
}

impl FileManifest {
    pub fn new(
        transfer_id: String,
        file_name: String,
        file_size: u64,
        root_hash: [u8; 32],
    ) -> Self {
        let total_chunks = (file_size as f64 / CHUNK_SIZE as f64).ceil() as u32;

        Self {
            transfer_id,
            file_name,
            file_size,
            chunk_size: CHUNK_SIZE,
            total_chunks,
            blake3_root_hash: root_hash,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

/// Frame Type 0x06: Represents a single 64 KB slice of the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)] // Added PartialEq for easier testing
pub struct ChunkPayload {
    pub chunk_index: u32,
    // Note: The actual binary payload will be appended directly after this struct
    // on the wire to avoid double-allocation, but we define the header here.
    pub payload_length: u32,
}

impl ChunkPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_serialization() {
        let hash = blake3::hash(b"dummy data");
        let manifest = FileManifest::new(
            "transfer-123".to_string(),
            "ubuntu.iso".to_string(),
            1024 * 1024 * 500, // 500 MB
            *hash.as_bytes(),
        );

        // A 500 MB file should have exactly 8000 chunks of 64 KB
        assert_eq!(manifest.total_chunks, 8000);

        let bytes = manifest.to_bytes().unwrap();
        let decoded = FileManifest::from_bytes(&bytes).unwrap();

        assert_eq!(manifest, decoded);
    }
}
