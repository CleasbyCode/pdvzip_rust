use anyhow::{bail, Result};

/// Find the first occurrence of `sig` within `data` starting from `start`.
/// Returns the index of the match, or `None` if not found.
pub fn search_sig(data: &[u8], sig: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() || sig.is_empty() {
        return None;
    }
    data[start..]
        .windows(sig.len())
        .position(|w| w == sig)
        .map(|pos| start + pos)
}

/// Write a 16-bit or 32-bit value into `data` at `index` with the given byte order.
///
/// **Index convention** (matching the C++ original):
/// - Big-endian: `index` is the **first** byte of the value.
/// - Little-endian: `index` is the **last** byte of the value.
pub fn update_value(
    data: &mut [u8],
    index: usize,
    value: u32,
    length: usize,
    big_endian: bool,
) -> Result<()> {
    let write_index = if big_endian {
        index
    } else {
        index.checked_sub(length - 1)
            .ok_or_else(|| anyhow::anyhow!("update_value: index underflow"))?
    };

    if write_index + length > data.len() {
        bail!("update_value: index out of bounds");
    }

    match length {
        2 => {
            let val = value as u16;
            let bytes = if big_endian { val.to_be_bytes() } else { val.to_le_bytes() };
            data[write_index..write_index + 2].copy_from_slice(&bytes);
        }
        4 => {
            let bytes = if big_endian { value.to_be_bytes() } else { value.to_le_bytes() };
            data[write_index..write_index + 4].copy_from_slice(&bytes);
        }
        _ => bail!("update_value: unsupported length {}", length),
    }
    Ok(())
}

/// Convenience wrapper: write a value in big-endian byte order.
pub fn update_value_be(data: &mut [u8], index: usize, value: u32, length: usize) -> Result<()> {
    update_value(data, index, value, length, true)
}

/// Read a 16-bit or 32-bit value from `data` at `index` with the given byte order.
///
/// **Index convention** (matching the C++ original):
/// - Big-endian: `index` is the **first** byte of the value.
/// - Little-endian: `index` is the **last** byte of the value.
pub fn get_value(data: &[u8], index: usize, length: usize, big_endian: bool) -> Result<u32> {
    let read_index = if big_endian {
        index
    } else {
        index.checked_sub(length - 1)
            .ok_or_else(|| anyhow::anyhow!("get_value: index underflow"))?
    };

    if read_index + length > data.len() {
        bail!("get_value: index out of bounds");
    }

    match length {
        2 => {
            let bytes: [u8; 2] = data[read_index..read_index + 2].try_into().unwrap();
            let val = if big_endian { u16::from_be_bytes(bytes) } else { u16::from_le_bytes(bytes) };
            Ok(val as u32)
        }
        4 => {
            let bytes: [u8; 4] = data[read_index..read_index + 4].try_into().unwrap();
            let val = if big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) };
            Ok(val)
        }
        _ => bail!("get_value: unsupported length {}", length),
    }
}

/// Convenience wrapper: read a value in big-endian byte order.
pub fn get_value_be(data: &[u8], index: usize, length: usize) -> Result<u32> {
    get_value(data, index, length, true)
}
