//! Header takes a fixed set of bytes in any block.
//! Header size is very small but still it occupy some space and if your block size is small
//! this could affect your storage capacity.
//! With 20 bytes headers and 256 bytes blocks only 92.2% will be available for storing data.
//! With 128 bytes blocks -> 84.4%.
//!
use std::collections::HashMap;
use std::error::Error;

use crate::HeaderTypever::{EMPTY, HEAD, HEAD_SINGLE, TAIL, UNDEFINED};
use linear_storage_core::StorageError;

/// Fixed space allocated for header in each block.
pub const BLOCK_HEADER_SPACE_BYTES: usize = 20;

const BLOCK_HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();

const HEADER_V1: u8 = 0x10;

/// Combination of type and version of the header 4x4 bits.
/// Having more than 16 variants of headers is too much as well as supporting 16 different binary versions.
#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HeaderTypever {
    /// This is not a header.
    /// All data must be considered as invalid.
    EMPTY = 0x0,
    /// Undefined first block.
    /// It should mean that payload write is in progress right now.
    /// Also it could be some kind of improperly saved block, damaged, empty.
    UNDEFINED = HEADER_V1 | 0x00,
    /// Single block  that holds all payload.
    HEAD_SINGLE = HEADER_V1 | 0x01,
    /// First block in the sequence.
    HEAD = HEADER_V1 | 0x02,
    /// One of the many middle blocks in the sequence.
    MID = HEADER_V1 | 0x03,
    /// Tail block, the last one.
    TAIL = HEADER_V1 | 0x04,
}

impl HeaderTypever {
    /// Check whether this block is first in the sequence and it is valid.
    pub fn is_head(&self) -> bool {
        self == &HEAD_SINGLE || self == &HEAD
    }

    /// True if this is last or the only one block in the sequence.
    pub fn is_last(&self) -> bool {
        self == &HEAD_SINGLE || self == &TAIL
    }

    /// Check if current type block contains valid data
    pub fn is_valid(&self) -> bool {
        self != &EMPTY && self != &UNDEFINED
    }
}

#[repr(C)]
#[derive(PartialEq, Clone, Copy, Debug)]
pub struct BlockHeader {
    /// Combined header type and version field.
    /// For internal use only.
    pub(crate) typever: HeaderTypever,

    /// Counter that is incremented each time payload updates.
    /// After `u16::MAX` resets to zero.
    /// Could be used to implement some kind of optimistic locking.
    /// It is also barely possible that you will have something like `u16::MAX` concurrent events at the same time.
    pub(crate) content_version: u16,

    /// Size of the payload in bytes for `HEAD` block or number of the first block.
    /// Notice that we could potentially have multiple tails for the one root.
    /// Reference to root is just an additional information.
    pub(crate) content_size_or_root_block: u32,

    /// Next block if it is exists or zero.
    /// The only one true valid reference that you should rely while reading payload.
    pub(crate) next_block: u32,

    /// For `HEAD` block hold size of the meta bytes, for others - previous block number.
    /// Prev block could also lead to the same issues as reference to the root block.
    /// This is just an additional information.
    pub(crate) meta_size_or_prev_block: u32,
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader {
            typever: HeaderTypever::HEAD,
            content_version: 0,
            content_size_or_root_block: 0,
            next_block: 0,
            meta_size_or_prev_block: 0,
        }
    }
}

/// Serialize header to bytes array of the fixed size.
/// The size of [u8] must be bigger that required to store header.
pub(crate) fn header_to_bytes(h: &BlockHeader) -> [u8; BLOCK_HEADER_SPACE_BYTES] {
    let mut buf = [0; BLOCK_HEADER_SPACE_BYTES];
    let ser: [u8; BLOCK_HEADER_SIZE] = unsafe { core::mem::transmute_copy(h) };

    for i in 0..BLOCK_HEADER_SIZE {
        buf[i] = ser[i];
    }

    buf
}

/// Read header from bytes.
/// Assuming that input buffer size is bigger that space occupied by header.
pub(crate) fn header_from_bytes(buffer: &[u8; BLOCK_HEADER_SPACE_BYTES]) -> BlockHeader {
    let mut sliced_buff: [u8; BLOCK_HEADER_SIZE] = [0; BLOCK_HEADER_SIZE];
    for i in 0..BLOCK_HEADER_SIZE {
        sliced_buff[i] = buffer[i];
    }
    unsafe { core::mem::transmute(sliced_buff) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size() {
        assert!(BLOCK_HEADER_SPACE_BYTES > BLOCK_HEADER_SIZE);
    }

    #[test]
    fn header_read_write() {
        let fh1 = BlockHeader::default();
        let fh2 = BlockHeader {
            typever: HeaderTypever::TAIL,
            content_size_or_root_block: 10,
            meta_size_or_prev_block: 10,
            ..BlockHeader::default()
        };

        let fh1_bts = header_to_bytes(&fh1);
        let fh2_bts = header_to_bytes(&fh2);

        let fh1_deser = header_from_bytes(&fh1_bts);
        let fh2_deser = header_from_bytes(&fh2_bts);

        assert_eq!(fh1_bts, header_to_bytes(&fh1_deser));
        assert_eq!(fh1, fh1_deser);
        assert_eq!(fh2, fh2_deser);

        let fh1_bts2 = header_to_bytes(&fh1_deser);
        let fh2_bts2 = header_to_bytes(&fh2_deser);

        assert_eq!(fh1_bts, fh1_bts2);
        assert_eq!(fh2_bts, fh2_bts2);
    }
}
