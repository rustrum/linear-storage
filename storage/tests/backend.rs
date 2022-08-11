use linear_storage::header::BLOCK_HEADER_SPACE_BYTES;
use linear_storage_core::{StorageBackend, StorageError};

pub struct TestVecBackend {
    vec: Vec<u8>,
}

impl TestVecBackend {
    fn write_block(&mut self, block: u32, buf: &[u8]) {
        if buf.len() != self.block_size() as usize {
            panic!("WTF you are thinking")
        }

        self.write((self.block_size() * block) as u64, buf)
            .expect("Should not happen");
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
            off
        };

        for i in off..(off + to_read) {
            buf[i - off] = self.vec[i];
        }
        Ok(to_read)
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
