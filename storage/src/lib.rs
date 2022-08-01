extern crate core;

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

use flat_storage_backend::FlatBackend;

pub mod header;
pub mod meta;

#[derive(Debug)]
pub enum FlatStorageError {
    LowLevel(String),
    /// Wrapper for other external errors
    Other(Box<dyn Error>),
}

impl Display for FlatStorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::LowLevel(cause) => {
                write!(f, "{}", cause)
            }
            Self::Other(err) => Display::fmt(&err, f),
        }
    }
}

impl Error for FlatStorageError {}

pub struct PayloadInfo {
    version: u16,
    first_block: u32,
    payload_size: u32,
    has_meta: bool,
}

pub struct FlatStorage {
    backend: Box<dyn FlatBackend>,
    index: HashMap<String, PayloadInfo>,
}

impl FlatStorage {
    pub fn load(backend: Box<dyn FlatBackend>) -> FlatStorage {
        FlatStorage {
            backend,
            index: HashMap::new(),
        }
    }

    pub fn read(&self) -> Option<Vec<u8>> {
        unimplemented!()
    }

    pub fn write(&self) {
        unimplemented!()
    }
}

/// TODO Flag to cache meta in the memory or not to cache meta in the memory
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
