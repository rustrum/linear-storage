extern crate core;

pub mod header;

use std::collections::HashMap;
use flat_storage_backend::FlatBackend;

/// TODO Flag to cache meta in the memory or not to cache meta in the memory


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
