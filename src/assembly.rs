use crate::binary_utils::{ByteOrder, get_value, search_sig, update_value};
use crc32fast::Hasher;

pub type AssemblyResult<T> = Result<T, String>;

fn find_last_signature(data: &[u8], sig: &[u8]) -> Option<usize> {
    if sig.is_empty() || data.len() < sig.len() {
        return None;
    }
    data.windows(sig.len()).rposition(|window| window == sig)
}

fn fix_zip_offsets(
    image_vec: &mut [u8],
    original_image_size: usize,
    script_data_size: usize,
) -> AssemblyResult<()> {
    const CENTRAL_LOCAL_INDEX_DIFF: usize = 45;
    const ZIP_COMMENT_LENGTH_DIFF: usize = 21;
    const END_CENTRAL_START_DIFF: usize = 19;
    const ZIP_RECORDS_DIFF: usize = 11;
    const PNG_IEND_LENGTH: usize = 16;
    const ZIP_LOCAL_INDEX_DIFF: usize = 4;
    const ZIP_SIG_LENGTH: usize = 4;
    const LAST_IDAT_INDEX_DIFF: usize = 4;

    const VALUE_BYTE_LENGTH_TWO: usize = 2;
    const VALUE_BYTE_LENGTH_FOUR: usize = 4;

    const ZIP_LOCAL_SIG: [u8; ZIP_SIG_LENGTH] = [0x50, 0x4B, 0x03, 0x04];
    const END_CENTRAL_DIR_SIG: [u8; ZIP_SIG_LENGTH] = [0x50, 0x4B, 0x05, 0x06];
    const START_CENTRAL_DIR_SIG: [u8; ZIP_SIG_LENGTH] = [0x50, 0x4B, 0x01, 0x02];

    const EOCD_MIN_SIZE: usize = 22;

    let complete_size = image_vec.len();
    let last_idat_index = original_image_size
        .checked_add(script_data_size)
        .and_then(|v| v.checked_add(LAST_IDAT_INDEX_DIFF))
        .ok_or_else(|| "ZIP Error: Size overflow while computing last IDAT index.".to_string())?;

    let end_central_dir_index = find_last_signature(image_vec, &END_CENTRAL_DIR_SIG)
        .ok_or_else(|| "ZIP Error: End of Central Directory signature not found.".to_string())?;

    if end_central_dir_index
        .checked_add(EOCD_MIN_SIZE)
        .map_or(true, |end| end > complete_size)
    {
        return Err("ZIP Error: End of Central Directory record is truncated.".to_string());
    }

    let total_records_index = end_central_dir_index + ZIP_RECORDS_DIFF;
    let end_central_start = end_central_dir_index + END_CENTRAL_START_DIFF;
    let comment_length_index = end_central_dir_index + ZIP_COMMENT_LENGTH_DIFF;

    let total_records = get_value(
        image_vec,
        total_records_index,
        VALUE_BYTE_LENGTH_TWO,
        ByteOrder::Little,
    )
    .map_err(|err| format!("ZIP Error: {err}"))? as u16;

    if total_records == 0 {
        return Err("ZIP Error: Archive contains no records.".to_string());
    }

    let original_comment_length = get_value(
        image_vec,
        comment_length_index,
        VALUE_BYTE_LENGTH_TWO,
        ByteOrder::Little,
    )
    .map_err(|err| format!("ZIP Error: {err}"))? as u16;

    if original_comment_length > (u16::MAX - PNG_IEND_LENGTH as u16) {
        return Err("ZIP Error: Comment length overflow.".to_string());
    }

    let new_comment_length = original_comment_length + PNG_IEND_LENGTH as u16;
    update_value(
        image_vec,
        comment_length_index,
        usize::from(new_comment_length),
        VALUE_BYTE_LENGTH_TWO,
        ByteOrder::Little,
    )
    .map_err(|err| format!("ZIP Error: {err}"))?;

    let mut start_central_index = 0usize;
    let mut search_end = complete_size;

    for i in 0..total_records {
        let next = find_last_signature(&image_vec[..search_end], &START_CENTRAL_DIR_SIG)
            .ok_or_else(|| {
                format!(
                    "ZIP Error: Expected {total_records} central directory records, found only {i}."
                )
            })?;
        start_central_index = next;
        search_end = next + ZIP_SIG_LENGTH - 1;
    }

    update_value(
        image_vec,
        end_central_start,
        start_central_index,
        VALUE_BYTE_LENGTH_FOUR,
        ByteOrder::Little,
    )
    .map_err(|err| format!("ZIP Error: {err}"))?;

    let mut local_index = last_idat_index + ZIP_LOCAL_INDEX_DIFF;
    let mut central_local_index = start_central_index + CENTRAL_LOCAL_INDEX_DIFF;

    for i in 0..total_records {
        update_value(
            image_vec,
            central_local_index,
            local_index,
            VALUE_BYTE_LENGTH_FOUR,
            ByteOrder::Little,
        )
        .map_err(|err| format!("ZIP Error: {err}"))?;

        if i + 1 < total_records {
            let next_local =
                search_sig(image_vec, &ZIP_LOCAL_SIG, local_index + 1).ok_or_else(|| {
                    format!(
                        "ZIP Error: Local file header {} of {} not found.",
                        i + 2,
                        total_records
                    )
                })?;
            local_index = next_local;

            let next_central =
                search_sig(image_vec, &START_CENTRAL_DIR_SIG, central_local_index + 1).ok_or_else(
                    || {
                        format!(
                            "ZIP Error: Central directory entry {} of {} not found.",
                            i + 2,
                            total_records
                        )
                    },
                )?;
            central_local_index = next_central + CENTRAL_LOCAL_INDEX_DIFF;
        }
    }

    Ok(())
}

pub fn embed_chunks(
    image_vec: &mut Vec<u8>,
    mut script_vec: Vec<u8>,
    mut archive_vec: Vec<u8>,
    original_image_size: usize,
) -> AssemblyResult<()> {
    const ICCP_CHUNK_INDEX: usize = 0x21;
    const VALUE_BYTE_LENGTH_FOUR: usize = 4;
    const ARCHIVE_INSERT_INDEX_DIFF: usize = 12;
    const EXCLUDE_SIZE_AND_CRC_LENGTH: usize = 8;
    const LAST_IDAT_INDEX_DIFF: usize = 4;
    const LAST_IDAT_CRC_INDEX_DIFF: usize = 16;
    const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;

    if script_vec.len() < CHUNK_FIELDS_COMBINED_LENGTH {
        return Err("Script Error: iCCP chunk is truncated.".to_string());
    }
    if image_vec.len() < ICCP_CHUNK_INDEX {
        return Err("PNG Error: Cover image is too small for iCCP insertion.".to_string());
    }
    if image_vec.len() < ARCHIVE_INSERT_INDEX_DIFF {
        return Err("PNG Error: Cover image is truncated before IEND.".to_string());
    }
    if archive_vec.len() < EXCLUDE_SIZE_AND_CRC_LENGTH {
        return Err("ZIP Error: Archive data is truncated.".to_string());
    }

    let script_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
    let archive_file_size = archive_vec.len();

    image_vec.reserve(image_vec.len() + script_vec.len() + archive_vec.len());

    image_vec.splice(ICCP_CHUNK_INDEX..ICCP_CHUNK_INDEX, script_vec.drain(..));
    image_vec.splice(
        (image_vec.len() - ARCHIVE_INSERT_INDEX_DIFF)
            ..(image_vec.len() - ARCHIVE_INSERT_INDEX_DIFF),
        archive_vec.drain(..),
    );

    fix_zip_offsets(image_vec, original_image_size, script_data_size)?;

    let last_idat_index = original_image_size
        .checked_add(script_data_size)
        .and_then(|v| v.checked_add(LAST_IDAT_INDEX_DIFF))
        .ok_or_else(|| "ZIP Error: Size overflow while computing CRC start.".to_string())?;
    let crc_len = archive_file_size - EXCLUDE_SIZE_AND_CRC_LENGTH;
    let crc_end = last_idat_index
        .checked_add(crc_len)
        .ok_or_else(|| "ZIP Error: Size overflow while computing CRC range.".to_string())?;
    if crc_end > image_vec.len() {
        return Err("ZIP Error: Invalid IDAT CRC range.".to_string());
    }

    let mut hasher = Hasher::new();
    hasher.update(&image_vec[last_idat_index..crc_end]);
    let last_idat_crc = hasher.finalize();

    let complete_size = image_vec.len();
    if complete_size < LAST_IDAT_CRC_INDEX_DIFF {
        return Err("ZIP Error: Output is truncated before final IDAT CRC.".to_string());
    }
    let crc_index = complete_size - LAST_IDAT_CRC_INDEX_DIFF;
    update_value(
        image_vec,
        crc_index,
        last_idat_crc as usize,
        VALUE_BYTE_LENGTH_FOUR,
        ByteOrder::Big,
    )
    .map_err(|err| format!("ZIP Error: {err}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::embed_chunks;

    fn base_image() -> Vec<u8> {
        include_bytes!("../tests/fixtures/assembly_base_image.bin").to_vec()
    }

    fn base_image_size() -> usize {
        include_str!("../tests/fixtures/assembly_base_image_size.txt")
            .trim()
            .parse()
            .expect("base image size fixture must parse")
    }

    #[test]
    fn parity_zip_video_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = include_bytes!("../tests/fixtures/assembly_zip_video.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_zip_video.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed zip fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn parity_jar_fixture() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_jar_manifest.script.bin").to_vec();
        let archive =
            include_bytes!("../tests/fixtures/assembly_jar_manifest.archive.bin").to_vec();
        let expected = include_bytes!("../tests/fixtures/assembly_jar_manifest.out.bin").to_vec();

        embed_chunks(&mut image, script, archive, base_image_size()).expect("embed jar fixture");
        assert_eq!(image, expected);
    }

    #[test]
    fn rejects_truncated_script_chunk() {
        let mut image = vec![0u8; 64];
        let script = vec![0u8; 11];
        let archive = vec![0u8; 8];
        let err =
            embed_chunks(&mut image, script, archive, 0).expect_err("expected truncation error");
        assert!(err.contains("iCCP chunk is truncated"));
    }

    #[test]
    fn rejects_archive_without_eocd() {
        let mut image = base_image();
        let script = include_bytes!("../tests/fixtures/assembly_zip_video.script.bin").to_vec();
        let archive = vec![0u8; 8];
        let err = embed_chunks(&mut image, script, archive, base_image_size())
            .expect_err("expected EOCD lookup failure");
        assert!(err.contains("End of Central Directory signature not found"));
    }
}
