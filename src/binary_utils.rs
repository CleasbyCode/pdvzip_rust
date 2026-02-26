#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    Big,
    Little,
}

pub type BinResult<T> = Result<T, String>;

pub fn search_sig(data: &[u8], sig: &[u8], start: usize) -> Option<usize> {
    if sig.is_empty() || start >= data.len() {
        return None;
    }
    data.get(start..)?
        .windows(sig.len())
        .position(|window| window == sig)
        .map(|offset| start + offset)
}

pub fn update_value(
    data: &mut [u8],
    index: usize,
    value: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<()> {
    if length != 2 && length != 4 {
        return Err(format!("update_value: unsupported length {length}"));
    }

    let write_index = match byte_order {
        ByteOrder::Big => index,
        ByteOrder::Little => {
            if index + 1 < length {
                return Err("update_value: little-endian index underflow".to_string());
            }
            index - (length - 1)
        }
    };

    if write_index > data.len() || length > (data.len() - write_index) {
        return Err("update_value: index out of bounds".to_string());
    }

    let max_value = if length == 2 {
        u16::MAX as usize
    } else {
        u32::MAX as usize
    };
    if value > max_value {
        return Err(format!(
            "update_value: value {value} exceeds {length}-byte field"
        ));
    }

    for i in 0..length {
        let shift = match byte_order {
            ByteOrder::Big => (length - 1 - i) * 8,
            ByteOrder::Little => i * 8,
        };
        data[write_index + i] = ((value >> shift) & 0xFF) as u8;
    }

    Ok(())
}

pub fn get_value(
    data: &[u8],
    index: usize,
    length: usize,
    byte_order: ByteOrder,
) -> BinResult<usize> {
    if length != 2 && length != 4 {
        return Err(format!("get_value: unsupported length {length}"));
    }

    let read_index = match byte_order {
        ByteOrder::Big => index,
        ByteOrder::Little => {
            if index + 1 < length {
                return Err("get_value: little-endian index underflow".to_string());
            }
            index - (length - 1)
        }
    };

    if read_index > data.len() || length > (data.len() - read_index) {
        return Err("get_value: index out of bounds".to_string());
    }

    let mut value = 0usize;
    for i in 0..length {
        let shift = match byte_order {
            ByteOrder::Big => (length - 1 - i) * 8,
            ByteOrder::Little => i * 8,
        };
        value |= (data[read_index + i] as usize) << shift;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{ByteOrder, get_value, search_sig, update_value};

    #[test]
    fn update_and_get_value_round_trip() {
        let mut bytes = [0u8; 8];
        update_value(&mut bytes, 0, 0x1234_5678, 4, ByteOrder::Big).expect("update");
        assert_eq!(
            get_value(&bytes, 0, 4, ByteOrder::Big).expect("get"),
            0x1234_5678
        );

        update_value(&mut bytes, 7, 0xBEEF, 2, ByteOrder::Little).expect("update");
        assert_eq!(
            get_value(&bytes, 7, 2, ByteOrder::Little).expect("get"),
            0xBEEF
        );
    }

    #[test]
    fn bounds_and_length_validation() {
        let mut bytes = [0u8; 2];
        assert!(update_value(&mut bytes, 0, 1, 3, ByteOrder::Big).is_err());
        assert!(get_value(&bytes, 0, 3, ByteOrder::Big).is_err());
        assert!(update_value(&mut bytes, 0, 1, 2, ByteOrder::Little).is_err());
    }

    #[test]
    fn search_signature() {
        let data = [1u8, 2, 3, 4, 3, 4, 5];
        assert_eq!(search_sig(&data, &[3, 4], 0), Some(2));
        assert_eq!(search_sig(&data, &[3, 4], 3), Some(4));
        assert_eq!(search_sig(&data, &[9], 0), None);
    }
}
