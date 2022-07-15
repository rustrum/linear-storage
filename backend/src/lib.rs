pub trait FlatBackend {
    /// Return block size in bytes for the current backend implementation.
    /// I think that for some cases it definitely will be a constant.
    fn block_size(&self) -> usize;

    /// Read data from the storage starting at the offset and up to the length of the input buffer.
    fn read(&mut self, offset: u64, buf: &mut [u8]);

    /// Write data into the storage starting at the provided offset.
    fn write(&mut self, offset: u64, buf: &[u8]);

    /// Attempt to extend storage size by some amount of blocks.
    fn extend(&mut self, blocks_to_add: usize);

    /// Return current available storage size in blocks.
    fn size_blocks(&self) -> usize;

    /// Return current available storage size in bytes.
    fn size_bytes(&self) -> usize;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
