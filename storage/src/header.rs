use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::error::Error;

use linear_storage_core::StorageError;

/// Fixed space allocated for header in each block.
pub const BLOCK_HEADER_SPACE_BYTES: usize = 20;

const BLOCK_HEADER_SIZE: usize = core::mem::size_of::<FlatHeader>();

const HEADER_V1: u8 = 0x10;

/// Combination of type and version of the header 4x4 bits.
/// Having more than 16 variants of headers is too much as well as supporting 16 different binary versions.
#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum HeaderTypever {
    /// Undefined first block.
    /// It should mean that payload write is in progress right now.
    /// Also it could be some kind of improperly saved block, damaged, empty.
    HEAD_UNDEF = HEADER_V1 | 0x00,
    /// First block, could be the last one too.
    HEAD = HEADER_V1 | 0x01,
    /// One of the many possible middle blocks
    MID = HEADER_V1 | 0x02,
    /// Tail block, the last one.
    TAIL = HEADER_V1 | 0x03,
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct FlatHeader {
    /// Combined header type and version field.
    /// For internal use only.
    header_typever: HeaderTypever,

    /// Counter that is incremented each time payload updates.
    /// After `u16::MAX` resets to zero.
    /// Could be used to implement some kind of optimistic locking.
    /// It is also barely possible that you will have something like `u16::MAX` concurrent events at the same time.
    payload_version: u16,

    /// Size of the payload in bytes for `HEAD` block or number of the first block.
    /// Notice that we could potentially have multiple tails for the one root.
    /// Reference to root is just an additional information.
    payload_size_or_root_block: u32,

    /// Next block if it is exists or zero.
    /// The only one true valid reference that you should rely while reading payload.
    next_block: u32,

    /// For `HEAD` block hold size of the meta bytes, for others - previous block number.
    /// Prev block could also lead to the same issues as reference to the root block.
    /// This is just an additional information.
    meta_size_or_prev_block: u32,
}

impl Default for FlatHeader {
    fn default() -> Self {
        FlatHeader {
            header_typever: HeaderTypever::HEAD,
            payload_version: 0,
            payload_size_or_root_block: 0,
            next_block: 0,
            meta_size_or_prev_block: 0,
        }
    }
}

/// Serialize header to bytes array of the fixed size.
/// The size of [u8] must be bigger that required to store header.
pub(crate) fn header_to_bytes(h: &FlatHeader) -> [u8; BLOCK_HEADER_SPACE_BYTES] {
    let mut buf = [0; BLOCK_HEADER_SPACE_BYTES];
    let ser: [u8; BLOCK_HEADER_SIZE] = unsafe { core::mem::transmute_copy(h) };

    for i in 0..BLOCK_HEADER_SIZE {
        buf[i] = ser[i];
    }

    buf
}

/// Read header from bytes.
/// Assuming that input buffer size is bigger that space occupied by header.
pub(crate) fn header_from_bytes(buffer: &[u8; BLOCK_HEADER_SPACE_BYTES]) -> FlatHeader {
    let mut sliced_buff: [u8; BLOCK_HEADER_SIZE] = [0; BLOCK_HEADER_SIZE];
    for i in 0..BLOCK_HEADER_SIZE {
        sliced_buff[i] = buffer[i];
    }
    unsafe { core::mem::transmute(sliced_buff) }
}

#[cfg(test)]
mod tests {
    use super::{
        header_from_bytes, header_to_bytes, FlatHeader, HeaderTypever, BLOCK_HEADER_SIZE,
        BLOCK_HEADER_SPACE_BYTES,
    };

    #[test]
    fn header_size() {
        assert!(BLOCK_HEADER_SPACE_BYTES > BLOCK_HEADER_SIZE);
    }

    #[test]
    fn header_read_write() {
        let fh1 = FlatHeader::default();
        let fh2 = FlatHeader {
            header_typever: HeaderTypever::TAIL,
            payload_size_or_root_block: 10,
            meta_size_or_prev_block: 10,
            ..FlatHeader::default()
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
