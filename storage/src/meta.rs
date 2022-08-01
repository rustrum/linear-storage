use crate::FlatStorageError;

#[derive(PartialEq, Debug)]
pub(crate) struct FlatMeta {
    /// This is the primary key of your object.
    payload_key: String,

    /// Some info about payload that could be cached in the memory for fast access.
    meta: Vec<MetaEntry>,
}

#[derive(PartialEq, Clone, Debug)]
pub(crate) struct MetaEntry {
    /// Key code (non zero value)
    k: u8,
    /// Payload as raw bytes
    v: Vec<u8>,
}

pub(crate) fn serialize_meta(entires: &[MetaEntry]) -> Vec<u8> {
    let mut res = Vec::new();
    for e in entires {
        let mut evec = serialize_entry(e);
        res.append(&mut evec);
    }
    res
}

pub(crate) fn deserialize_meta(buf: &[u8]) -> Result<Vec<MetaEntry>, FlatStorageError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        let (entry, bytes_read) = deserialize_entry(&buf[offset..])?;
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

pub(crate) fn serialize_entry(e: &MetaEntry) -> Vec<u8> {
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
pub(crate) fn deserialize_entry(buf: &[u8]) -> Result<(MetaEntry, usize), FlatStorageError> {
    const init_offset: usize = 5;
    let key = buf[0];
    let value_size_bytes = &buf[1..5];

    let value_size = u32::from_le_bytes(
        value_size_bytes
            .try_into()
            .map_err(|e| FlatStorageError::Other(Box::new(e)))?,
    ) as usize;

    let end_offset = init_offset + value_size;

    if key == 0u8 || value_size == 0 {
        return Err(FlatStorageError::LowLevel(
            "Key or value can not be empty".to_string(),
        ));
    }
    if end_offset > buf.len() {
        return Err(FlatStorageError::LowLevel(
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
    use super::{deserialize_entry, deserialize_meta, serialize_entry, serialize_meta, MetaEntry};

    #[test]
    fn meta_entry_ser_deser() {
        let m1 = MetaEntry {
            k: 0x01,
            v: vec![1u8, 2u8, 3u8, 4u8, 5u8],
        };

        let m1_vec = serialize_entry(&m1);

        let (m1_deser, m1_bytes) = deserialize_entry(&m1_vec).unwrap();

        assert_eq!(m1_bytes, m1_vec.len());
        assert_eq!(m1, m1_deser);

        let mut m1_vec2 = serialize_entry(&m1_deser);

        assert_eq!(m1_vec, m1_vec2);

        let mut m1_vec_long = m1_vec.clone();
        m1_vec_long.extend_from_slice(&[0, 2, 3, 3, 4, 5]);
        let (m1_long_deser, m1_long_bytes) = deserialize_entry(&m1_vec_long).unwrap();

        assert!(m1_vec.len() < m1_vec_long.len());
        assert_eq!(m1_long_bytes, m1_vec.len());
        assert_eq!(m1_long_deser, m1_deser);
    }

    #[test]
    fn meta_ser_deser() {
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

        let meta_ser = serialize_meta(&meta);

        let meta_deser = deserialize_meta(&meta_ser).unwrap();

        assert_eq!(meta, meta_deser);
    }
}
