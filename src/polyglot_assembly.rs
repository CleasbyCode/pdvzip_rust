use crate::binary_utils::{get_value, search_sig, update_value, update_value_be};
use crate::CHUNK_FIELDS_COMBINED_LENGTH;
use anyhow::{bail, Result};

const CENTRAL_LOCAL_INDEX_DIFF: usize = 45;
const ZIP_COMMENT_LENGTH_DIFF: usize = 21;
const END_CENTRAL_START_DIFF: usize = 19;
const ZIP_RECORDS_DIFF: usize = 11;
const PNG_IEND_LENGTH: u16 = 16;
const ZIP_LOCAL_INDEX_DIFF: usize = 4;
const ZIP_SIG_LENGTH: usize = 4;
const LAST_IDAT_INDEX_DIFF: usize = 4;

const ZIP_LOCAL_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const END_CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const START_CENTRAL_DIR_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];

const EOCD_MIN_SIZE: usize = 22;

/// Fix all ZIP record offsets so the archive is valid within the polyglot.
fn fix_zip_offsets(
    image_vec: &mut Vec<u8>,
    original_image_size: usize,
    script_data_size: usize,
) -> Result<()> {
    let complete_size = image_vec.len();
    let last_idat_index = original_image_size + script_data_size + LAST_IDAT_INDEX_DIFF;

    // --- Locate the End of Central Directory record (searching backwards) ---
    let end_central_dir_index = image_vec
        .windows(ZIP_SIG_LENGTH)
        .rposition(|w| w == END_CENTRAL_DIR_SIG)
        .ok_or_else(|| anyhow::anyhow!("ZIP Error: End of Central Directory signature not found."))?;

    if end_central_dir_index + EOCD_MIN_SIZE > complete_size {
        bail!("ZIP Error: End of Central Directory record is truncated.");
    }

    let total_records_index = end_central_dir_index + ZIP_RECORDS_DIFF;
    let end_central_start = end_central_dir_index + END_CENTRAL_START_DIFF;
    let comment_length_index = end_central_dir_index + ZIP_COMMENT_LENGTH_DIFF;

    let total_records = get_value(image_vec, total_records_index, 2, false)? as u16;

    if total_records == 0 {
        bail!("ZIP Error: Archive contains no records.");
    }

    // Extend the ZIP comment length to cover the PNG IEND chunk (required for JAR).
    let original_comment_length = get_value(image_vec, comment_length_index, 2, false)? as u16;

    if original_comment_length > u16::MAX - PNG_IEND_LENGTH {
        bail!("ZIP Error: Comment length overflow.");
    }

    let new_comment_length = original_comment_length + PNG_IEND_LENGTH;
    update_value(image_vec, comment_length_index, new_comment_length as u32, 2, false)?;

    // --- Find the first Start Central Directory entry (searching backwards) ---
    let mut start_central_index: usize = 0;
    let mut search_from = complete_size;

    for i in 0..total_records {
        // Search backwards for START_CENTRAL_DIR_SIG.
        let found = image_vec[..search_from]
            .windows(ZIP_SIG_LENGTH)
            .rposition(|w| w == START_CENTRAL_DIR_SIG)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "ZIP Error: Expected {} central directory records, found only {}.",
                    total_records,
                    i
                )
            })?;
        start_central_index = found;
        search_from = found;
    }

    // Update the End Central Directory to point to the Start Central Directory.
    update_value(
        image_vec,
        end_central_start,
        start_central_index as u32,
        4,
        false,
    )?;

    // --- Rewrite each central directory entry's local header offset ---
    let mut local_index = last_idat_index + ZIP_LOCAL_INDEX_DIFF;
    let mut central_local_index = start_central_index + CENTRAL_LOCAL_INDEX_DIFF;

    for i in 0..total_records {
        update_value(
            image_vec,
            central_local_index,
            local_index as u32,
            4,
            false,
        )?;

        // Only search for the next record if this isn't the last one.
        if i + 1 < total_records {
            local_index = search_sig(image_vec, &ZIP_LOCAL_SIG, local_index + 1).ok_or_else(|| {
                anyhow::anyhow!(
                    "ZIP Error: Local file header {} of {} not found.",
                    i + 2,
                    total_records
                )
            })?;

            let next_central = search_sig(image_vec, &START_CENTRAL_DIR_SIG, central_local_index + 1)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "ZIP Error: Central directory entry {} of {} not found.",
                        i + 2,
                        total_records
                    )
                })?;
            central_local_index = next_central + CENTRAL_LOCAL_INDEX_DIFF;
        }
    }

    Ok(())
}

/// Embed the script chunk and archive into the image.
pub fn embed_chunks(
    image_vec: &mut Vec<u8>,
    script_vec: Vec<u8>,
    archive_vec: Vec<u8>,
    original_image_size: usize,
) -> Result<()> {
    const ICCP_CHUNK_INDEX: usize = 0x21;
    const ARCHIVE_INSERT_INDEX_DIFF: usize = 12;
    const EXCLUDE_SIZE_AND_CRC_LENGTH: usize = 8;
    const LAST_IDAT_INDEX_DIFF_LOCAL: usize = 4;
    const LAST_IDAT_CRC_INDEX_DIFF: usize = 16;

    let script_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
    let archive_file_size = archive_vec.len();

    image_vec.reserve(script_vec.len() + archive_vec.len());

    // Insert iCCP script chunk after the PNG header.
    image_vec.splice(
        ICCP_CHUNK_INDEX..ICCP_CHUNK_INDEX,
        script_vec.into_iter(),
    );

    // Insert archive data before the IEND chunk.
    let insert_pos = image_vec.len() - ARCHIVE_INSERT_INDEX_DIFF;
    image_vec.splice(insert_pos..insert_pos, archive_vec.into_iter());

    // Fix ZIP internal offsets.
    fix_zip_offsets(image_vec, original_image_size, script_data_size)?;

    // Recompute the last IDAT chunk CRC.
    let last_idat_index = original_image_size + script_data_size + LAST_IDAT_INDEX_DIFF_LOCAL;
    let complete_size = image_vec.len();

    let crc_data_len = archive_file_size - EXCLUDE_SIZE_AND_CRC_LENGTH;
    let last_idat_crc = crc32fast::hash(&image_vec[last_idat_index..last_idat_index + crc_data_len]);

    let crc_index = complete_size - LAST_IDAT_CRC_INDEX_DIFF;
    update_value_be(image_vec, crc_index, last_idat_crc, 4)?;

    Ok(())
}
