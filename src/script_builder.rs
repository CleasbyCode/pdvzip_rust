use crate::binary_utils::{update_value_be};
use crate::user_input::UserArguments;
use crate::{FileType, CHUNK_FIELDS_COMBINED_LENGTH, LINUX_PROBLEM_METACHARACTERS, MAX_SCRIPT_SIZE};
use anyhow::{bail, Result};

const SCRIPT_INDEX: usize = 0x16;
const ICCP_CHUNK_NAME_INDEX: usize = 0x04;
const ICCP_CHUNK_NAME_LENGTH: usize = 4;
const ICCP_CRC_INDEX_DIFF: usize = 8;
const LENGTH_FIRST_BYTE_INDEX: usize = 3;

/// Build the combined Linux+Windows extraction script for each file type.
fn get_extraction_scripts() -> Vec<Vec<u8>> {
    let crlf = b"\r\n";
    let templates: &[(&[u8], &[u8])] = &[
        // VIDEO_AUDIO (0)
        (
            br#"ITEM="";DIR="pdvzip_extracted";NUL="/dev/null";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v mpv >$NUL 2>&1;then clear;mpv --quiet --geometry=50%:50% "$ITEM" &> $NUL;elif command -v vlc >$NUL 2>&1;then clear;vlc --play-and-exit --no-video-title-show "$ITEM" &> $NUL;elif command -v firefox >$NUL 2>&1;then clear;firefox "$ITEM" &> $NUL;else clear;fi;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&""&exit"#,
        ),
        // PDF (1)
        (
            br#"ITEM="";DIR="pdvzip_extracted";NUL="/dev/null";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v evince >$NUL 2>&1;then clear;evince "$ITEM" &> $NUL;else firefox "$ITEM" &> $NUL;clear;fi;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&""&exit"#,
        ),
        // PYTHON (2)
        (
            br#"ITEM="";DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v python3 >/dev/null 2>&1;then clear;python3 "$ITEM" ;else clear;fi;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set ITEM=&set ARGS=&set APP=python3&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&where !APP! >nul 2>&1 && (!APP! "!ITEM!" !ARGS! ) || (cls&exit)&echo.&exit"#,
        ),
        // POWERSHELL (3)
        (
            br#"DIR="pdvzip_extracted";ITEM="";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v pwsh >/dev/null 2>&1;then clear;pwsh "$ITEM" ;else clear;fi;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set ITEM=&set ARGS=&set DIR=pdvzip_extracted&set PDIR="%SystemDrive%\Program Files\PowerShell\"&cls&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&IF EXIST !PDIR! (pwsh -ExecutionPolicy Bypass -File "!ITEM!" !ARGS!&echo.&exit) ELSE (powershell -ExecutionPolicy Bypass -File "!ITEM!" !ARGS!&echo.&exit))"#,
        ),
        // BASH_SHELL (4)
        (
            br#"ITEM="";DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";chmod +x "$ITEM";./"$ITEM" ;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&"" &cls&exit"#,
        ),
        // WINDOWS_EXECUTABLE (5)
        (
            br#"DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";clear;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&"" &echo.&exit"#,
        ),
        // FOLDER (6)
        (
            br#"ITEM="";DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";xdg-open "$ITEM" &> /dev/null;clear;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&powershell "II ''"&cls&exit"#,
        ),
        // LINUX_EXECUTABLE (7)
        (
            br#"ITEM="";DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";chmod +x "$ITEM";./"$ITEM" ;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&cls&exit"#,
        ),
        // JAR (8)
        (
            br#"clear;hash -r;if command -v java >/dev/null 2>&1;then clear;java -jar "$0" ;else clear;fi;exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set ARGS=&set APP=java&cls&where !APP! >nul 2>&1 && (!APP! -jar "%~dpnx0" !ARGS! ) || (cls)&ren "%~dpnx0" *.png&echo.&exit"#,
        ),
        // UNKNOWN_FILE_TYPE (9)
        (
            br#"ITEM="";DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";xdg-open "$ITEM";exit;"#,
            br#"#&cls&setlocal EnableDelayedExpansion&set DIR=pdvzip_extracted&mkdir .\!DIR!&move "%~dpnx0" .\!DIR!&cd .\!DIR!&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&""&echo.&exit"#,
        ),
    ];

    templates
        .iter()
        .map(|(linux_part, windows_part)| {
            let mut combined = Vec::with_capacity(linux_part.len() + crlf.len() + windows_part.len());
            combined.extend_from_slice(linux_part);
            combined.extend_from_slice(crlf);
            combined.extend_from_slice(windows_part);
            combined
        })
        .collect()
}

/// Script insertion offset map: (script_id, offsets...).
/// Offsets are insertion points within the script vector for filenames, arguments, etc.
fn get_script_offsets(file_type: FileType) -> &'static [u16] {
    match file_type {
        FileType::VideoAudio       => &[0, 0x1E4, 0x1C],
        FileType::Pdf              => &[1, 0x196, 0x1C],
        FileType::Python           => &[2, 0x10B, 0x101, 0xBC, 0x1C],
        FileType::PowerShell       => &[3, 0x105, 0xFB, 0xB6, 0x33],
        FileType::BashShell        => &[4, 0x134, 0x132, 0x8E, 0x1C],
        FileType::WindowsExecutable => &[5, 0x116, 0x114],
        FileType::Folder           => &[6, 0x149, 0x1C],
        FileType::LinuxExecutable  => &[7, 0x8E, 0x1C],
        FileType::Jar              => &[8, 0xA6, 0x61],
        FileType::UnknownFileType  => &[9, 0x127, 0x1C],
    }
}

pub fn build_extraction_script(
    file_type: FileType,
    first_filename: &str,
    user_args: &UserArguments,
) -> Result<Vec<u8>> {
    // iCCP chunk header skeleton.
    let mut script_vec: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x69, 0x43, 0x43, 0x50,
        0x44, 0x56, 0x5A, 0x49, 0x50, 0x5F, 0x5F, 0x00,
        0x00, 0x0D, 0x52, 0x45, 0x4D, 0x3B, 0x0D, 0x0A,
        0x00, 0x00, 0x00, 0x00,
    ];
    script_vec.reserve(MAX_SCRIPT_SIZE);

    let offsets = get_script_offsets(file_type);
    let script_id = offsets[0] as usize;
    let extraction_scripts = get_extraction_scripts();

    // Insert the base script template.
    let template = &extraction_scripts[script_id];
    let insert_pos = SCRIPT_INDEX;
    script_vec.splice(insert_pos..insert_pos, template.iter().copied());

    // Helper to insert a string at a given offset within the script vector.
    let insert_at = |vec: &mut Vec<u8>, offset: u16, s: &str| {
        let pos = offset as usize;
        vec.splice(pos..pos, s.bytes());
    };

    // Patch the script with filenames and user arguments.
    // The offsets are ordered largest-first so that earlier
    // insertions don't invalidate later offsets.
    let args_combined = if user_args.linux_args.is_empty() {
        &user_args.windows_args
    } else {
        &user_args.linux_args
    };

    match file_type {
        FileType::WindowsExecutable | FileType::LinuxExecutable => {
            insert_at(&mut script_vec, offsets[1], args_combined);
            insert_at(&mut script_vec, offsets[2], first_filename);
        }
        FileType::Jar => {
            insert_at(&mut script_vec, offsets[1], &user_args.windows_args);
            insert_at(&mut script_vec, offsets[2], &user_args.linux_args);
        }
        FileType::Python | FileType::PowerShell | FileType::BashShell => {
            insert_at(&mut script_vec, offsets[1], &user_args.windows_args);
            insert_at(&mut script_vec, offsets[2], first_filename);
            insert_at(&mut script_vec, offsets[3], &user_args.linux_args);
            insert_at(&mut script_vec, offsets[4], first_filename);
        }
        _ => {
            // VIDEO_AUDIO, PDF, FOLDER, UNKNOWN — just patch the filename.
            insert_at(&mut script_vec, offsets[1], first_filename);
            insert_at(&mut script_vec, offsets[2], first_filename);
        }
    }

    // Update the iCCP chunk length field.
    let mut chunk_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
    update_value_be(&mut script_vec, 0, chunk_data_size as u32, 4)?;

    // If the first byte of the chunk length is a problematic metacharacter,
    // pad the chunk to shift past it.
    if LINUX_PROBLEM_METACHARACTERS.contains(&script_vec[LENGTH_FIRST_BYTE_INDEX]) {
        let pad = b"........";
        let pad_offset = chunk_data_size + 8;
        script_vec.splice(pad_offset..pad_offset, pad.iter().copied());
        chunk_data_size = script_vec.len() - CHUNK_FIELDS_COMBINED_LENGTH;
        update_value_be(&mut script_vec, 0, chunk_data_size as u32, 4)?;
    }

    if chunk_data_size > MAX_SCRIPT_SIZE {
        bail!("Script Size Error: Extraction script exceeds size limit.");
    }

    // Compute and write the CRC for the iCCP chunk.
    let iccp_chunk_length = chunk_data_size + ICCP_CHUNK_NAME_LENGTH;
    let crc = crc32fast::hash(&script_vec[ICCP_CHUNK_NAME_INDEX..ICCP_CHUNK_NAME_INDEX + iccp_chunk_length]);
    let crc_index = chunk_data_size + ICCP_CRC_INDEX_DIFF;
    update_value_be(&mut script_vec, crc_index, crc, 4)?;

    Ok(script_vec)
}
