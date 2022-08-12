use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum StorageError {
    LowLevel(String),
    /// No available space left and it is impossible to extend storage.
    NoSpace,
    /// Something wrong in user input cause this error (offset, buffer length, etc.).
    BadInput,
    /// Wrapper for other external errors.
    Other(Box<dyn Error>),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::LowLevel(cause) => {
                write!(f, "{}", cause)
            }
            Self::Other(err) => Display::fmt(&err, f),
            _ => {
                write!(f, "{:?}", self)
            }
        }
    }
}

impl Error for StorageError {}

/// Low level backend for any type of the storage.
/// There could be anything that could store some bytes.
/// It is not even required for storage to be extendable.
/// It could have some fixed size at start.
pub trait StorageBackend {
    /// Return virtual block size in bytes for the current backend.
    fn block_size(&self) -> u32;

    /// Read data from the storage starting at the offset and up to the length of the input buffer.
    /// Returning how many bytes were read.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError>;

    /// Write data into the storage starting at the provided offset.
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), StorageError>;

    /// Attempt to extend storage size by some amount of blocks.
    /// Returning how many blocks were added. Assuming possibility that this value could be greater than in the input.
    fn extend(&mut self, blocks_to_add: u32) -> Result<u32, StorageError>;

    /// Return current available storage size in blocks.
    fn size_blocks(&self) -> u32;

    /// Return current available storage size in bytes.
    fn size_bytes(&self) -> usize;
}
