use super::manifest::{ChunkPayload, FileManifest, CHUNK_SIZE};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub struct FileChunker {
    file: File,
    manifest: FileManifest,
}

impl FileChunker {
    /// Opens a file, calculates its BLAKE3 Merkle tree root hash using a background blocking reader,
    /// and prepares the manifest for transmission.
    pub async fn new(transfer_id: String, file_path: impl Into<PathBuf>) -> Result<Self> {
        let path = file_path.into();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.bin")
            .to_string();

        let mut file = File::open(&path)
            .await
            .context("Failed to open source file")?;
        let metadata = file.metadata().await?;
        let file_size = metadata.len();

        // 1. Calculate the BLAKE3 file contents hash on a dedicated worker pool thread.
        let path_clone = path.clone();
        let root_hash = tokio::task::spawn_blocking(move || -> Result<blake3::Hash> {
            let mut hasher = blake3::Hasher::new();
            let mut std_file = std::fs::File::open(&path_clone)
                .context("Failed to open file for hashing")?;
            hasher.update_reader(&mut std_file)
                .context("Error reading data during hash streaming")?;
            Ok(hasher.finalize())
        })
        .await? // Unwraps the JoinError from tokio task scheduling
        ?       // Unwraps the standard Result returned from our inner closure block
        ;

        // 2. Build the structural file asset representation
        let manifest = FileManifest::new(transfer_id, file_name, file_size, *root_hash.as_bytes());

        Ok(Self { file, manifest })
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    /// Reads a specific 64 KB chunk from the disk.
    /// This allows the QUIC multiplexer to request chunks out-of-order or in parallel.
    pub async fn read_chunk(&mut self, chunk_index: u32) -> Result<(ChunkPayload, Vec<u8>)> {
        if chunk_index >= self.manifest.total_chunks {
            return Err(anyhow::anyhow!("Chunk index {} out of bounds", chunk_index));
        }

        let offset = (chunk_index as u64) * (CHUNK_SIZE as u64);
        self.file.seek(std::io::SeekFrom::Start(offset)).await?;

        // Calculate expected read size (the last chunk might be smaller than 64 KB)
        let mut expected_size = CHUNK_SIZE;
        if chunk_index == self.manifest.total_chunks - 1 {
            let remainder = self.manifest.file_size % (CHUNK_SIZE as u64);
            if remainder > 0 {
                expected_size = remainder as u32;
            }
        }

        let mut buffer = vec![0u8; expected_size as usize];
        self.file.read_exact(&mut buffer).await?;

        let header = ChunkPayload {
            chunk_index,
            payload_length: expected_size,
        };

        Ok((header, buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_chunker_hashing_and_reading() -> Result<()> {
        let temp_dir = env::temp_dir();
        let file_path = temp_dir.join("test_chunker_source.bin");

        // 1. Create a dummy file of exactly 100 KB
        // This will result in two chunks: Chunk 0 (65,536 bytes) and Chunk 1 (36,864 bytes).
        let file_size = 102_400;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .await?;

        let dummy_data = vec![0x77; file_size];
        file.write_all(&dummy_data).await?;
        file.sync_all().await?;

        // 2. Initialize the Chunker
        let mut chunker = FileChunker::new("transfer-777".to_string(), &file_path).await?;

        // 3. Verify Manifest Metadata
        let manifest = chunker.manifest();
        assert_eq!(manifest.file_size, 102_400);
        assert_eq!(manifest.total_chunks, 2);

        // 4. Verify Chunk 0 (Full 64 KB)
        let (header0, data0) = chunker.read_chunk(0).await?;
        assert_eq!(header0.chunk_index, 0);
        assert_eq!(header0.payload_length, CHUNK_SIZE);
        assert_eq!(data0.len(), CHUNK_SIZE as usize);
        assert_eq!(data0[0], 0x77);

        // 5. Verify Chunk 1 (Partial 36 KB)
        let (header1, data1) = chunker.read_chunk(1).await?;
        assert_eq!(header1.chunk_index, 1);
        assert_eq!(header1.payload_length, 36_864);
        assert_eq!(data1.len(), 36_864);

        // Cleanup
        tokio::fs::remove_file(file_path).await?;

        Ok(())
    }
}
