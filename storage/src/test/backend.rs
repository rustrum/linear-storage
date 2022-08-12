use crate::header::{header_to_bytes, BlockHeader, HeaderTypever, BLOCK_HEADER_SPACE_BYTES};
use linear_storage_core::{StorageBackend, StorageError};

pub const TEST_BLOCK_PAYLOAD_SIZE: u32 = 20 as u32;
pub const TEST_BLOCK_SIZE: u32 = BLOCK_HEADER_SPACE_BYTES as u32 + TEST_BLOCK_PAYLOAD_SIZE;

pub struct TestVecBackend {
    pub vec: Vec<u8>,
}

impl TestVecBackend {
    pub fn new_with_capacity(blocks: u32) -> Self {
        TestVecBackend {
            vec: vec![0; (blocks * TEST_BLOCK_SIZE) as usize],
        }
    }

    pub fn write_block(&mut self, block: u32, buf: &[u8]) {
        if buf.len() != self.block_size() as usize {
            panic!("WTF you are thinking")
        }

        self.write((self.block_size() * block) as u64, buf)
            .expect("Should not happen");
    }

    pub fn write_single_block(&mut self, block: u32, meta: &[u8], content: &[u8]) {
        let h = BlockHeader {
            typever: HeaderTypever::HEAD_SINGLE,
            next_block: 0,
            payload_version: 0,
            meta_size_or_prev_block: meta.len() as u32,
            content_size_or_root_block: content.len() as u32,
        };
        let hb = header_to_bytes(&h);

        let mut buf = vec![0u8; self.block_size() as usize];
        let mut idx = 0;
        for v in hb {
            buf[idx] = v;
            idx += 1;
        }

        for v in meta {
            buf[idx] = v.clone();
            idx += 1;
        }

        for v in content {
            buf[idx] = v.clone();
            idx += 1;
        }
        self.write_block(block, &buf);
    }

    pub fn write_empty_block(&mut self, block: u32) {
        let mut buf = vec![0u8; self.block_size() as usize];
        self.write_block(block, &buf);
    }
}

impl StorageBackend for TestVecBackend {
    fn block_size(&self) -> u32 {
        (BLOCK_HEADER_SPACE_BYTES + 20) as u32
    }

    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        let off = offset as usize;
        if off >= self.vec.len() {
            return Err(StorageError::BadInput);
        }
        let to_read = if off + buf.len() > self.vec.len() {
            self.vec.len() - off
        } else {
            buf.len()
        };

        //println!("OFF {} LIMIT {}", off, (off + to_read));
        let mut read: usize = 0;
        for i in off..(off + to_read) {
            buf[i - off] = self.vec[i];
            read += 1;
        }
        Ok(read)
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), StorageError> {
        let off = offset as usize;
        if off + buf.len() >= self.vec.len() {
            return Err(StorageError::BadInput);
        }
        for i in 0..buf.len() {
            self.vec[off + i] = buf[i].clone();
        }
        Ok(())
    }

    fn extend(&mut self, blocks_to_add: u32) -> Result<u32, StorageError> {
        let capacity = blocks_to_add * self.block_size();
        let zeroes = vec![0u8; capacity as usize];
        self.vec.extend_from_slice(&zeroes);
        Ok(blocks_to_add)
    }

    fn size_blocks(&self) -> u32 {
        (self.size_bytes() / self.block_size() as usize) as u32
    }

    fn size_bytes(&self) -> usize {
        self.vec.len()
    }
}
