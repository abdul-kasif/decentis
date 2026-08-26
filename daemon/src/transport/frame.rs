use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut};

pub const MAGIC_BYTE: u8 = 0x49; // 0x49 is ASCII 'I'
pub const PROTOCOL_VERSION: u8 = 0x01;

// --- Frame Types ---
pub const TYPE_HANDSHAKE_INIT: u8 = 0x01;
pub const TYPE_HANDSHAKE_RESP: u8 = 0x02;
pub const TYPE_KEEPALIVE_PING: u8 = 0x03;
pub const TYPE_L3_TUN_DATAGRAM: u8 = 0x04;
pub const TYPE_FILE_MANIFEST: u8 = 0x05;
pub const TYPE_FILE_CHUNK_PAYLOAD: u8 = 0x06;
pub const TYPE_FILE_CHUNK_ACK: u8 = 0x07;
pub const TYPE_RELAY_WRAPPER: u8 = 0x08;

// --- Flags ---
pub const FLAG_PRIORITY_HIGH: u8 = 0b0000_0001;
pub const FLAG_COMPRESSED_ZSTD: u8 = 0b0000_0010;

#[derive(Debug, Clone, PartialEq)]
pub struct FrameHeader {
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u16,
    pub seq_num: u32, // Note: We use the lower 32-bits of the Noise u64 sequence
}

impl FrameHeader {
    /// Encodes the header directly into a mutable byte buffer (10 bytes total)
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(MAGIC_BYTE);
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u8(self.frame_type);
        buf.put_u8(self.flags);
        buf.put_u16(self.stream_id);
        buf.put_u32(self.seq_num);
    }

    /// Decodes a header from a byte buffer. Returns an error if the Magic Byte or Version is invalid.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if buf.remaining() < 10 {
            return Err(anyhow!("Buffer too small for Decentis frame header"));
        }

        let magic = buf.get_u8();
        if magic != MAGIC_BYTE {
            return Err(anyhow!(
                "Invalid Magic Byte: expected {:#X}, got {:#X}",
                MAGIC_BYTE,
                magic
            ));
        }

        let version = buf.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(anyhow!(
                "Protocol mismatch: expected v{}, got v{}",
                PROTOCOL_VERSION,
                version
            ));
        }

        Ok(Self {
            frame_type: buf.get_u8(),
            flags: buf.get_u8(),
            stream_id: buf.get_u16(),
            seq_num: buf.get_u32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_frame_encode_decode() {
        let header = FrameHeader {
            frame_type: TYPE_L3_TUN_DATAGRAM,
            flags: FLAG_PRIORITY_HIGH,
            stream_id: 1024,
            seq_num: 999_999,
        };

        let mut buf = BytesMut::with_capacity(10);
        header.encode(&mut buf);

        assert_eq!(buf.len(), 10);

        let mut read_buf = std::io::Cursor::new(buf);
        let decoded = FrameHeader::decode(&mut read_buf).expect("Failed to decode header");

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_invalid_magic_byte() {
        let mut buf = BytesMut::with_capacity(10);
        buf.put_u8(0xFF); // Wrong magic byte
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u64(0); // Fill the rest

        let mut read_buf = std::io::Cursor::new(buf);
        assert!(FrameHeader::decode(&mut read_buf).is_err());
    }
}
