extern crate core;

use std::collections::HashMap;
use std::fmt::Debug;

use linear_storage_core::StorageBackend;

pub mod header;
pub mod meta;

pub struct PayloadInfo {
    version: u16,
    first_block: u32,
    payload_size: u32,
    has_meta: bool,
}

pub struct FlatStorage {
    backend: Box<dyn StorageBackend>,
    index: HashMap<String, PayloadInfo>,
}

impl FlatStorage {
    pub fn load(backend: Box<dyn StorageBackend>) -> FlatStorage {
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
