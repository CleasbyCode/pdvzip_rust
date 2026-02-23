use crate::FileType;
use anyhow::{bail, Result};

const EXTENSION_LIST: &[&str] = &[
    "mp4", "mp3", "wav", "mpg", "webm", "flac", "3gp", "aac", "aiff", "aif", "alac", "ape",
    "avchd", "avi", "dsd", "divx", "f4v", "flv", "m4a", "m4v", "mkv", "mov", "midi", "mpeg",
    "ogg", "pcm", "swf", "wma", "wmv", "xvid", "pdf", "py", "ps1", "sh", "exe",
];

const FIRST_FILENAME_LENGTH_INDEX: usize = 0x22;
const FIRST_FILENAME_INDEX: usize = 0x26;
const FIRST_FILENAME_MIN_LENGTH: usize = 4;

pub fn determine_file_type(archive_data: &[u8], is_zip_file: bool) -> Result<FileType> {
    let filename_length = archive_data[FIRST_FILENAME_LENGTH_INDEX] as usize;

    if filename_length < FIRST_FILENAME_MIN_LENGTH {
        bail!(
            "File Error:\n\nName length of first file within archive is too short.\n\
             Increase length (minimum 4 characters). Make sure it has a valid extension."
        );
    }

    let filename: String = archive_data[FIRST_FILENAME_INDEX..FIRST_FILENAME_INDEX + filename_length]
        .iter()
        .map(|&b| b as char)
        .collect();

    if !is_zip_file {
        if filename != "META-INF/MANIFEST.MF" && filename != "META-INF/" {
            bail!("File Type Error: Archive does not appear to be a valid JAR file.");
        }
        return Ok(FileType::Jar);
    }

    // ZIP path: inspect the first record's filename/extension.
    let last_char = archive_data[FIRST_FILENAME_INDEX + filename_length - 1];

    let extension = match filename.rfind('.') {
        Some(dot_pos) => &filename[dot_pos + 1..],
        None => "?",
    };

    // Check for folders (entries ending with '/').
    if extension == "?" {
        return Ok(if last_char == b'/' {
            FileType::Folder
        } else {
            FileType::LinuxExecutable
        });
    }

    // A name with a dot could still be a folder if it ends with '/'.
    if last_char == b'/' {
        let second_last = archive_data[FIRST_FILENAME_INDEX + filename_length - 2];
        if second_last == b'.' {
            bail!("ZIP File Error: Invalid folder name within ZIP archive.");
        }
        return Ok(FileType::Folder);
    }

    // Match extension against the known list.
    let lower_ext = extension.to_ascii_lowercase();
    for (i, &ext) in EXTENSION_LIST.iter().enumerate() {
        if ext == lower_ext {
            // Indices 0..28 all map to VideoAudio; 29+ map 1:1 with the enum.
            let type_index = i.max(FileType::VideoAudio as usize);
            return Ok(FileType::from_index(type_index));
        }
    }

    Ok(FileType::UnknownFileType)
}

pub fn get_archive_first_filename(archive_data: &[u8]) -> String {
    let length = archive_data[FIRST_FILENAME_LENGTH_INDEX] as usize;
    archive_data[FIRST_FILENAME_INDEX..FIRST_FILENAME_INDEX + length]
        .iter()
        .map(|&b| b as char)
        .collect()
}
