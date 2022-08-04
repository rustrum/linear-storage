extern crate core;

use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;

use crate::header::{header_from_bytes, BlockHeader, HeaderTypever, BLOCK_HEADER_SPACE_BYTES};
use crate::meta::{deserialize_meta, Metadata};
use linear_storage_core::{StorageBackend, StorageError};

pub mod header;
pub mod meta;

pub struct PayloadInfo {
    version: u16,
    first_block: u32,
    payload_size: u32,
    has_meta: bool,
}

pub struct LinearStorage {
    backend: Box<dyn StorageBackend>,
    index: HashMap<String, PayloadInfo>,
    free: FreeSpace,
}

impl LinearStorage {
    pub fn load(backend: Box<dyn StorageBackend>) -> LinearStorage {
        LinearStorage {
            backend,
            index: HashMap::new(),
            free: FreeSpace::none(),
        }
    }

    pub fn read(&self) -> Option<Vec<u8>> {
        unimplemented!()
    }

    pub fn write(&self) {
        unimplemented!()
    }

    fn index_build(&mut self) -> Result<(), StorageError> {
        let blocks_total = self.backend.size_blocks();

        let mut occupied = vec![false; blocks_total as usize];

        for bid in 0..blocks_total {
            if occupied[bid as usize] {
                continue;
            }

            let header = self.read_block_header(bid)?;
            let tv = header.header_typever.clone();
            match tv {
                HeaderTypever::HEAD => {
                    self.index_head_block(bid, header, &mut occupied)?;
                }
                HeaderTypever::SINGLE => {
                    occupied[bid as usize] = true;
                }
                _ => {
                    continue;
                }
            }
        }

        self.free = FreeSpace::from_occupied(occupied);
        Ok(())
    }

    fn index_head_block(
        &mut self,
        blid: u32,
        header: BlockHeader,
        occupied: &mut Vec<bool>,
    ) -> Result<(), StorageError> {
        if header.header_typever != HeaderTypever::HEAD {
            return Err(StorageError::BadInput);
        }

        self.index_add(blid, &header)?;

        let mut header = header;
        let mut block = blid;
        loop {
            occupied[block as usize] = true;

            if header.header_typever == HeaderTypever::TAIL {
                break;
            }

            block = header.next_block;
            header = self.read_block_header(block)?;
            match &header.header_typever {
                HeaderTypever::MID | HeaderTypever::TAIL => {
                    // Nothing to to here
                }
                _ => {
                    return Err(StorageError::LowLevel(format!(
                        "Unexpected type {:?} for next block {}",
                        header.header_typever, block
                    )))
                }
            }
        }
        Ok(())
    }

    fn index_add(&mut self, blid: u32, header: &BlockHeader) -> Result<(), StorageError> {
        let meta = self.read_meta_with_header(blid, header)?;
        let info = PayloadInfo {
            version: header.payload_version,
            payload_size: header.payload_size_or_root_block,
            first_block: blid,
            has_meta: header.meta_size_or_prev_block > 0,
        };

        self.index.insert(meta.key, info);

        Ok(())
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

    #[inline]
    pub(crate) fn read_meta_from_block(&self, block: u32) -> Result<Metadata, StorageError> {
        let header = self.read_block_header(block)?;
        self.read_meta_with_header(block, &header)
    }

    pub(crate) fn read_meta_with_header(
        &self,
        block: u32,
        header: &BlockHeader,
    ) -> Result<Metadata, StorageError> {
        if header.header_typever != HeaderTypever::HEAD {
            return Err(StorageError::BadInput);
        }

        let mut bytes_to_read = header.meta_size_or_prev_block;
        let mut meta_buf = vec![0u8; bytes_to_read as usize];
        let mut blocks_left = self.blocks_for_bytes(bytes_to_read);
        let mut now_block = block;
        let mut offset = 0;

        if blocks_left > 0 {
            blocks_left -= 1;
        }
        loop {
            let (header, bytes) = self.read_block(now_block)?;
            for i in 0..bytes.len() {
                if offset >= bytes_to_read {
                    break;
                }
                meta_buf[offset as usize] = bytes[i];
                offset += 1;
            }

            if header.header_typever == HeaderTypever::TAIL {
                break;
            }

            now_block = header.next_block;

            if blocks_left == 0 {
                break;
            }
            blocks_left -= 1;
        }

        let meta = deserialize_meta(&meta_buf)?;
        Ok(meta)
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
}

struct FreeSpace {
    empty: BTreeSet<u32>,
    empty_after: u32,
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
