use super::manifest::{FileManifest, CHUNK_SIZE};
use anyhow::{Context, Result};
use bitvec::prelude::*;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

pub struct DiskWriter {
    file: File,
    manifest: FileManifest,
    received_chunks: BitVec<u8, Lsb0>,
}

impl DiskWriter {
    /// Initializes a new transfer, allocating the sparse file on disk.
    pub async fn new(save_dir: impl Into<PathBuf>, manifest: FileManifest) -> Result<Self> {
        let mut path = save_dir.into();
        path.push(&manifest.file_name);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .await
            .context("Failed to open destination file")?;

        // Sparse Allocation: Seek to the absolute end of the target size and write a single byte.
        // On modern filesystems (Btrfs, ext4, APFS, NTFS), this takes 0 milliseconds and
        // allocates the virtual size without writing gigabytes of zeros.
        if manifest.file_size > 0 {
            file.seek(std::io::SeekFrom::Start(manifest.file_size - 1))
                .await?;
            file.write_all(&[0]).await?;
        }

        // Initialize a bitset tracking which chunks we have received.
        let received_chunks = bitvec![u8, Lsb0; 0; manifest.total_chunks as usize];

        Ok(Self {
            file,
            manifest,
            received_chunks,
        })
    }

    /// Writes a 64 KB chunk directly to its exact offset on disk.
    pub async fn write_chunk(&mut self, chunk_index: u32, payload: &[u8]) -> Result<()> {
        if chunk_index >= self.manifest.total_chunks {
            return Err(anyhow::anyhow!("Chunk index out of bounds"));
        }

        // Prevent redundant writes if we already have this chunk (e.g., from network retries)
        if self.received_chunks[chunk_index as usize] {
            return Ok(());
        }

        let offset = (chunk_index as u64) * (CHUNK_SIZE as u64);

        self.file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.file.write_all(payload).await?;

        // Mark the chunk as successfully received
        self.received_chunks.set(chunk_index as usize, true);

        Ok(())
    }

    /// Checks if the bitset is entirely 1s (transfer complete)
    pub fn is_complete(&self) -> bool {
        self.received_chunks.all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio::fs;

    #[tokio::test]
    async fn test_sparse_allocation_and_out_of_order_writes() -> Result<()> {
        let manifest = FileManifest::new(
            "test-transfer".to_string(),
            "sparse_test.bin".to_string(),
            CHUNK_SIZE as u64 * 3, // Exactly 3 chunks (192 KB)
            [0u8; 32],
        );

        let temp_dir = env::temp_dir();
        let mut writer = DiskWriter::new(&temp_dir, manifest.clone()).await?;

        assert!(!writer.is_complete());

        let dummy_chunk = vec![0xAA; CHUNK_SIZE as usize];

        // Write Chunk 2 (Out of order)
        writer.write_chunk(2, &dummy_chunk).await?;
        assert!(!writer.is_complete());

        // Write Chunk 0
        writer.write_chunk(0, &dummy_chunk).await?;
        assert!(!writer.is_complete());

        // Write Chunk 1
        writer.write_chunk(1, &dummy_chunk).await?;

        // Transfer should now be marked complete
        assert!(writer.is_complete());

        // Cleanup
        let mut file_path = temp_dir;
        file_path.push(&manifest.file_name);
        fs::remove_file(file_path).await?;

        Ok(())
    }
}
