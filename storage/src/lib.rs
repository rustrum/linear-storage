extern crate core;

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use flat_storage_backend::FlatBackend;

pub mod header;

#[derive(Debug)]
struct LowLevelError {
    cause: String,
}

impl Display for LowLevelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cause)
    }
}

impl Error for LowLevelError {
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
