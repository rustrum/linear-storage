extern crate core;

use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;

use crate::header::{header_from_bytes, BlockHeader, HeaderTypever, BLOCK_HEADER_SPACE_BYTES};
use crate::meta::{deserialize_meta, Metadata};
use linear_storage_core::{StorageBackend, StorageError};

pub mod header;
pub mod meta;
#[cfg(test)]
pub mod test;

pub struct PayloadInfo {
    version: u16,
    first_block: u32,
    payload_size: u32,
    meta_size: u32,
}

pub struct LinearStorage {
    pub(crate) backend: Box<dyn StorageBackend>,
    pub(crate) index: HashMap<String, PayloadInfo>,
    pub(crate) free: FreeSpace,
}

impl LinearStorage {
    pub fn load(backend: Box<dyn StorageBackend>) -> Result<LinearStorage, StorageError> {
        let mut store = LinearStorage {
            backend,
            index: HashMap::new(),
            free: FreeSpace::none(),
        };
        store.index_build()?;
        Ok(store)
    }

    /// Read content by key
    pub fn read_content_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let value = match self.index.get(key) {
            Some(v) => v,
            None => {
                return Ok(None);
            }
        };

        let (_, bytes) = self.read_bytes_from_blocks(value.first_block, Payload::Content)?;
        Ok(Some(bytes))
    }

    pub fn write(&self) {
        unimplemented!()
    }

    /// Read all meta bytes or payload bytes
    fn read_bytes_from_blocks(
        &self,
        block: u32,
        payload_part: Payload,
    ) -> Result<(BlockHeader, Vec<u8>), StorageError> {
        let mut now_block = block;
        let (mut header, mut bytes) = self.read_block(now_block)?;
        if !header.typever.is_head() {
            return Err(StorageError::LowLevel(format!(
                "First block {} in a sequence is not a head {:?}",
                now_block, header.typever
            )));
        }
        let init_header = header.clone();

        let (offset, until) = LinearStorage::read_bytes_from_blocks_offsets(header, payload_part);

        // until offset is a literally a length of bytes from the 0 position in the first block
        let total_blocks = self.blocks_for_bytes(until);

        let mut blk: u32 = 0;
        let mut res: Vec<u8> = vec![0; (until - offset) as usize];
        let mut read_pos = 0u32;
        let mut write_pos = 0usize;

        // Loopee
        'blocks: loop {
            'bytes: for i in 0..bytes.len() {
                // println!(
                //     "read {} write {}, offset {} until {}",
                //     read_pos, write_pos, offset, until
                // );
                if read_pos >= until {
                    break 'blocks;
                }
                if read_pos >= offset {
                    res[write_pos] = bytes[i];
                    write_pos += 1;
                }
                read_pos += 1;
            }

            if header.typever.is_last() {
                break;
            }
            let (header, bytes) = self.read_block(now_block)?;
            if !header.typever.is_valid() || header.typever.is_head() {
                // next must be valid and could not be head
                return Err(StorageError::LowLevel(format!(
                    "Invalid block {} while reading from {}",
                    now_block, block
                )));
            }
            blk += 1;
            if blk >= total_blocks {
                break;
            }
        }
        Ok((init_header, res))
    }

    #[inline]
    fn read_bytes_from_blocks_offsets(h: BlockHeader, c: Payload) -> (u32, u32) {
        match c {
            Payload::All => (0, h.meta_size_or_prev_block + h.content_size_or_root_block),
            Payload::Content => (
                h.meta_size_or_prev_block,
                h.meta_size_or_prev_block + h.content_size_or_root_block,
            ),
            Payload::Meta => (0, h.meta_size_or_prev_block),
        }
    }

    /// Read `BlockHeader` from some block by it's number.
    pub fn read_block_header(&self, block: u32) -> Result<BlockHeader, StorageError> {
        let mut buf_head: [u8; BLOCK_HEADER_SPACE_BYTES] = [0; BLOCK_HEADER_SPACE_BYTES];
        let bytes_read = self.backend.read(self.block_offset(block), &mut buf_head)?;
        if bytes_read != buf_head.len() {
            return Err(StorageError::LowLevel(format!(
                "Only {} bytes were read for header in block {}",
                bytes_read, block
            )));
        }
        Ok(header_from_bytes(&buf_head))
    }

    /// Read all bytes from the block
    pub fn read_block_bytes(&self, block: u32) -> Result<Vec<u8>, StorageError> {
        let mut buf = vec![0; self.backend.block_size() as usize];
        let bytes_read = self.backend.read(self.block_offset(block), &mut buf)?;
        if bytes_read != buf.len() {
            return Err(StorageError::LowLevel(format!(
                "Only {} bytes were read for the block {}",
                bytes_read, block
            )));
        }
        Ok(buf)
    }

    /// Return block header and all bytes after the header
    pub fn read_block(&self, block: u32) -> Result<(BlockHeader, Vec<u8>), StorageError> {
        let bbytes = self.read_block_bytes(block)?;
        let mut buf_head: [u8; BLOCK_HEADER_SPACE_BYTES] = [0; BLOCK_HEADER_SPACE_BYTES];

        if bbytes.len() <= BLOCK_HEADER_SPACE_BYTES {
            return Err(StorageError::LowLevel(
                "Block bytes must be greater than required for header".to_string(),
            ));
        }

        for i in 0..buf_head.len() {
            buf_head[i] = bbytes[i];
        }
        let header = header_from_bytes(&buf_head);

        let payload_bytes = &bbytes[BLOCK_HEADER_SPACE_BYTES..];
        Ok((header, Vec::from(payload_bytes)))
    }

    /// Read meta data from one or multiple blocks.
    /// Input should reference to HEAD block
    #[inline]
    pub(crate) fn read_meta_from_block(
        &self,
        block: u32,
    ) -> Result<(BlockHeader, Metadata), StorageError> {
        let (h, bytes) = self.read_bytes_from_blocks(block, Payload::Meta)?;
        // println!("{:?}\nMeta bytes {:?}", h, bytes);
        let meta = deserialize_meta(&bytes)?;
        Ok((h, meta))
    }

    #[inline]
    pub fn block_offset(&self, block: u32) -> u64 {
        self.backend.block_size() as u64 * block as u64
    }

    /// Return number of blocks required to store provided amount of bytes.
    #[inline]
    pub fn blocks_for_bytes(&self, bytes: u32) -> u32 {
        let block_payload = self.backend.block_size() - BLOCK_HEADER_SPACE_BYTES as u32;
        let mut blocks = bytes / block_payload;

        if bytes % block_payload > 0 {
            blocks += 1;
        }
        blocks
    }

    /// Number of content/payload bytes in the block
    #[inline]
    pub fn bytes_in_block(&self) -> u32 {
        self.backend.block_size() - BLOCK_HEADER_SPACE_BYTES as u32
    }

    fn index_build(&mut self) -> Result<(), StorageError> {
        let blocks_total = self.backend.size_blocks();

        let mut occupied = vec![false; blocks_total as usize];

        for bid in 0..blocks_total {
            if occupied[bid as usize] {
                continue;
            }

            let header = self.read_block_header(bid)?;
            if header.typever.is_head() {
                self.index_from_head(bid, header, &mut occupied)?;
            }
        }

        // 0 block should not be available
        // Maybe in the future it will hold some meta info about all storage
        occupied[0] = true;
        self.free = FreeSpace::from_occupied(occupied);
        Ok(())
    }

    fn index_from_head(
        &mut self,
        blid: u32,
        header: BlockHeader,
        occupied: &mut Vec<bool>,
    ) -> Result<(), StorageError> {
        if !header.typever.is_head() {
            return Err(StorageError::BadInput);
        }

        self.index_add(blid)?;

        let mut header = header;
        let mut block = blid;
        loop {
            occupied[block as usize] = true;

            if header.typever.is_last() {
                break;
            }

            block = header.next_block;
            header = self.read_block_header(block)?;
            match &header.typever {
                HeaderTypever::MID | HeaderTypever::TAIL => {
                    // Nothing to to here
                }
                _ => {
                    return Err(StorageError::LowLevel(format!(
                        "Unexpected type {:?} for next block {}",
                        header.typever, block
                    )))
                }
            }
        }
        Ok(())
    }

    fn index_add(&mut self, blid: u32) -> Result<(), StorageError> {
        let (header, meta) = self.read_meta_from_block(blid)?;
        let info = PayloadInfo {
            version: header.payload_version,
            payload_size: header.content_size_or_root_block,
            first_block: blid,
            meta_size: header.meta_size_or_prev_block,
        };

        self.index.insert(meta.key, info);

        Ok(())
    }
}

/// Determines parts of the payload to operate on.
/// Payload is a literally any byte except header.
#[derive(Debug)]
enum Payload {
    /// Meta + content
    All,
    /// Only meta data
    Meta,
    /// Only content bytes
    Content,
}

struct FreeSpace {
    pub(crate) empty: BTreeSet<u32>,
    pub(crate) empty_after: u32,
}

impl FreeSpace {
    fn none() -> FreeSpace {
        FreeSpace {
            empty_after: 0,
            empty: BTreeSet::new(),
        }
    }
    fn from_occupied(occupied: Vec<bool>) -> FreeSpace {
        // Calculate free space
        let mut empty_after = 0;
        for i in (0..occupied.len()).rev() {
            if occupied[i] == true {
                empty_after = i;
                break;
            }
        }

        let mut empty = BTreeSet::new();
        for i in 0..(empty_after + 1) {
            if !occupied[i] {
                empty.insert(i as u32);
            }
        }

        FreeSpace {
            empty,
            empty_after: empty_after as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::{TestVecBackend, TEST_BLOCK_PAYLOAD_SIZE, TEST_BLOCK_SIZE};

    #[test]
    fn read_block_headers() {
        let mut backend = TestVecBackend::new_with_capacity(10);
        let m = meta::tests::simple_meta_bytes("abc");
        backend.write_single_block(3, &m, &[1u8]);

        let storage = LinearStorage::load(Box::new(backend)).unwrap();

        let h = storage.read_block_header(0).unwrap();
        assert_eq!(h.typever, HeaderTypever::EMPTY);
        assert!(!h.typever.is_valid());

        let h = storage.read_block_header(3).unwrap();
        assert_eq!(h.typever, HeaderTypever::HEAD_SINGLE);
        assert!(h.typever.is_valid());
        assert!(h.typever.is_head());
    }

    #[test]
    fn single_block_indexing() {
        let mut backend = TestVecBackend::new_with_capacity(10);
        backend.write_single_block(1, &meta::tests::simple_meta_bytes("abc"), &[1u8]);
        backend.write_single_block(3, &meta::tests::simple_meta_bytes("bcd"), &[2u8]);
        backend.write_single_block(5, &meta::tests::simple_meta_bytes("cde"), &[3u8]);

        let storage = LinearStorage::load(Box::new(backend)).unwrap();

        assert_eq!(storage.index.len(), 3);
        assert!(storage.index.contains_key("abc"));
        assert!(storage.index.contains_key("bcd"));
        assert!(storage.index.contains_key("cde"));

        assert_eq!(storage.free.empty_after, 5);
        assert_eq!(storage.free.empty.contains(&0), false);
        assert_eq!(storage.free.empty.len(), 2);
        assert!(storage.free.empty.contains(&2));
        assert!(storage.free.empty.contains(&4));
    }

    #[test]
    fn single_block_reading() {
        let mut backend = TestVecBackend::new_with_capacity(10);

        let k1 = meta::tests::simple_meta_bytes("abc");
        let c1 = vec![1u8; 1];

        let k2 = meta::tests::simple_meta_bytes("bcd");
        let c2 = vec![1u8; TEST_BLOCK_PAYLOAD_SIZE as usize - k2.len() - 1];

        let k3 = meta::tests::simple_meta_bytes("cde");
        let c3 = vec![1u8; TEST_BLOCK_PAYLOAD_SIZE as usize - k3.len()];

        backend.write_single_block(1, &k1, &c1);
        backend.write_single_block(3, &k2, &c2);
        backend.write_single_block(5, &k3, &c3);

        let storage = LinearStorage::load(Box::new(backend)).unwrap();

        let none = storage.read_content_bytes("non-existing-key").unwrap();
        assert!(none.is_none());

        let b1 = storage.read_content_bytes("abc").unwrap().unwrap();
        assert_eq!(c1, b1, "Key is {:?}", k1);

        let b2 = storage.read_content_bytes("bcd").unwrap().unwrap();
        assert_eq!(c2, b2, "Key is {:?}", k2);

        let b3 = storage.read_content_bytes("cde").unwrap().unwrap();
        assert_eq!(c3, b3, "Key is {:?}", k3);
    }
}
