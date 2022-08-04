//! Metadata is a chunk of bytes that comes after the HEAD block.
//! It is not expected by design but it could be large enough to occupy several blocks.
//!
//! The main purpose of meta is to hold object key.
//! Also you could add there as many k->v entries as you wish.
//! Metadata with entries could be read separately and could give you fast insight about payload content.
//! For the such cases when payload size is huge compared to meta.
use linear_storage_core::StorageError;

/// Payload meta object which main purpose is to hold the KEY.
#[derive(PartialEq, Clone, Debug)]
pub(crate) struct Metadata {
    /// This is the primary key of your object.
    pub(crate) key: String,

    /// Any relatively short info about payload.
    pub(crate) meta: Vec<MetaEntry>,
}

/// Compact entry with key->value pair but key is just a `u8`.
#[derive(PartialEq, Clone, Debug)]
pub(crate) struct MetaEntry {
    /// Entry key code.
    k: u8,
    /// Payload as raw bytes
    v: Vec<u8>,
}

pub(crate) fn serialize_meta(metadata: &Metadata) -> Vec<u8> {
    let mut res = Vec::new();

    let key_bytes = metadata.key.clone().into_bytes();
    let key_len = (key_bytes.len() as u32).to_le_bytes();

    res.extend_from_slice(&key_len);
    res.extend(&key_bytes);

    // No need to save entries len.
    // Metadata payload size stored in the header thus we will be able to read all required bytes.
    let entries = serialize_meta_entries(&metadata.meta);
    res.extend(entries);
    res
}

/// Desearialize meta data from the input buffer.
/// Input buffer must contain all and only meta data bytes.
pub(crate) fn deserialize_meta(buf: &[u8]) -> Result<Metadata, StorageError> {
    let key_size_bytes = &buf[0..4];
    let key_size = u32::from_le_bytes(
        key_size_bytes
            .try_into()
            .map_err(|e| StorageError::Other(Box::new(e)))?,
    ) as usize;

    if key_size == 0 {
        return Err(StorageError::LowLevel("Found empty key".to_string()));
    }
    let key_offset = 4 + key_size;
    if key_offset > buf.len() {
        return Err(StorageError::LowLevel(
            "Expecting to read more bytes for the key than available in the input buffer"
                .to_string(),
        ));
    }

    let key_value_bytes: &[u8] = &buf[4..key_offset];
    let key = String::from_utf8_lossy(key_value_bytes);

    let entries = deserialize_meta_entries(&buf[key_offset..])?;

    Ok(Metadata {
        key: key.to_string(),
        meta: entries,
    })
}

/// From input with all meta data bytes deserialize only entries.
pub(crate) fn deserialize_meta_entries_only(buf: &[u8]) -> Result<Vec<MetaEntry>, StorageError> {
    let key_size_bytes = &buf[0..4];
    let key_size = u32::from_le_bytes(
        key_size_bytes
            .try_into()
            .map_err(|e| StorageError::Other(Box::new(e)))?,
    ) as usize;

    if key_size == 0 {
        return Err(StorageError::LowLevel("Found empty key".to_string()));
    }
    let key_offset = 4 + key_size;
    if key_offset > buf.len() {
        return Err(StorageError::LowLevel(
            "Expecting to read more bytes for the key than available in the input buffer"
                .to_string(),
        ));
    }

    deserialize_meta_entries(&buf[key_offset..])
}

pub(crate) fn serialize_meta_entries(entires: &[MetaEntry]) -> Vec<u8> {
    let mut res = Vec::new();
    for e in entires {
        let mut evec = serialize_meta_entry(e);
        res.append(&mut evec);
    }
    res
}

pub(crate) fn deserialize_meta_entries(buf: &[u8]) -> Result<Vec<MetaEntry>, StorageError> {
    let mut entries = Vec::new();
    if buf.is_empty() {
        return Ok(entries);
    }

    let mut offset = 0;
    loop {
        let (entry, bytes_read) = deserialize_meta_entry(&buf[offset..])?;
        if bytes_read == 0 {
            break;
        }
        entries.push(entry);

        offset += bytes_read;
        if offset >= buf.len() {
            break;
        }
    }
    Ok(entries)
}

pub(crate) fn serialize_meta_entry(e: &MetaEntry) -> Vec<u8> {
    let kb = e.k.clone();
    let vb = e.v.to_vec();

    let k: [u8; 1] = [kb];
    let vbs: [u8; 4] = (vb.len() as u32).to_le_bytes();

    let mut res = Vec::with_capacity(5 + vb.len());
    res.extend_from_slice(&k);
    res.extend_from_slice(&vbs);
    res.extend_from_slice(&vb);
    res
}

/// Returns deserialized entry and number of bytes that was read
pub(crate) fn deserialize_meta_entry(buf: &[u8]) -> Result<(MetaEntry, usize), StorageError> {
    const init_offset: usize = 5;
    let key = buf[0];
    let value_size_bytes = &buf[1..5];

    let value_size = u32::from_le_bytes(
        value_size_bytes
            .try_into()
            .map_err(|e| StorageError::Other(Box::new(e)))?,
    ) as usize;

    let end_offset = init_offset + value_size;

    if value_size == 0 {
        return Err(StorageError::LowLevel(
            "Meta entry value can not be empty".to_string(),
        ));
    }
    if end_offset > buf.len() {
        return Err(StorageError::LowLevel(
            "Expecting to read more bytes than available in the input buffer".to_string(),
        ));
    }

    let value_bytes: &[u8] = &buf[init_offset..end_offset];
    let value = Vec::from(value_bytes);

    Ok((
        MetaEntry {
            k: key.clone(),
            v: value,
        },
        end_offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_ser_deser() {
        let metadata1 = Metadata {
            key: "user:shruti_gupta".to_string(),
            meta: vec![
                MetaEntry {
                    k: 0x01,
                    v: vec![1u8, 2u8, 3u8, 4u8, 5u8],
                },
                MetaEntry {
                    k: 0x04,
                    v: vec![1u8, 2u8, 3u8, 4u8, 5u8, 6u8],
                },
            ],
        };
        let metadata2 = Metadata {
            key: "user:john_smith".to_string(),
            meta: Vec::new(),
        };

        let ser1 = serialize_meta(&metadata1);
        let ser2 = serialize_meta(&metadata2);

        let deser1 = deserialize_meta(&ser1).unwrap();
        assert_eq!(metadata1, deser1);

        let deser2 = deserialize_meta(&ser2).unwrap();
        assert_eq!(metadata2, deser2);

        let entr1 = deserialize_meta_entries_only(&ser1).unwrap();
        assert_eq!(metadata1.meta, entr1);

        let entr2 = deserialize_meta_entries_only(&ser2).unwrap();
        assert_eq!(metadata2.meta, entr2);
    }

    #[test]
    fn meta_entry_ser_deser() {
        let m1 = MetaEntry {
            k: 0x01,
            v: vec![1u8, 2u8, 3u8, 4u8, 5u8],
        };

        let m1_vec = serialize_meta_entry(&m1);

        let (m1_deser, m1_bytes) = deserialize_meta_entry(&m1_vec).unwrap();

        assert_eq!(m1_bytes, m1_vec.len());
        assert_eq!(m1, m1_deser);

        let mut m1_vec2 = serialize_meta_entry(&m1_deser);

        assert_eq!(m1_vec, m1_vec2);

        let mut m1_vec_long = m1_vec.clone();
        m1_vec_long.extend_from_slice(&[0, 2, 3, 3, 4, 5]);
        let (m1_long_deser, m1_long_bytes) = deserialize_meta_entry(&m1_vec_long).unwrap();

        assert!(m1_vec.len() < m1_vec_long.len());
        assert_eq!(m1_long_bytes, m1_vec.len());
        assert_eq!(m1_long_deser, m1_deser);
    }

    #[test]
    fn meta_entires_ser_deser() {
        let m1 = MetaEntry {
            k: 0x01,
            v: vec![1u8, 2u8, 3u8, 4u8, 5u8],
        };
        let m2 = MetaEntry {
            k: 0x02,
            v: vec![11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8],
        };
        let m3 = MetaEntry {
            k: 0x0A,
            v: vec![21u8, 22u8, 23u8, 24u8, 25u8],
        };

        let meta = vec![m1.clone(), m2.clone(), m3.clone()];

        let meta_ser = serialize_meta_entries(&meta);

        let meta_deser = deserialize_meta_entries(&meta_ser).unwrap();

        assert_eq!(meta, meta_deser);
    }
}
