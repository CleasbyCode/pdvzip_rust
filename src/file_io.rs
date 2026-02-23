use anyhow::{bail, Result};
use rand::Rng;
use std::fs;
use std::path::Path;

const MINIMUM_IMAGE_SIZE: u64 = 87;
const MAX_IMAGE_SIZE: u64 = 4 * 1024 * 1024;
const MINIMUM_ARCHIVE_SIZE: u64 = 30;
const MAX_ARCHIVE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

const IDAT_MARKER_BYTES: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x41, 0x54];
const IDAT_CRC_BYTES: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const ARCHIVE_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileTypeCheck {
    CoverImage,
    ArchiveFile,
}

pub fn has_valid_filename(p: &Path) -> bool {
    let Some(filename) = p.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if filename.is_empty() {
        return false;
    }
    filename.bytes().all(|c| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' || c == b'@' || c == b'%'
    })
}

pub fn has_file_extension(p: &Path, exts: &[&str]) -> bool {
    let Some(ext) = p.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let ext_lower = ext.to_ascii_lowercase();
    exts.iter().any(|e| {
        let e_lower = e.trim_start_matches('.').to_ascii_lowercase();
        ext_lower == e_lower
    })
}

pub fn read_file(path: &Path, file_type: FileTypeCheck) -> Result<Vec<u8>> {
    if !has_valid_filename(path) {
        bail!("Invalid Input Error: Unsupported characters in filename arguments.");
    }

    if !path.exists() || !path.is_file() {
        bail!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        );
    }

    let file_size = fs::metadata(path)?.len();

    if file_size == 0 {
        bail!("Error: File is empty.");
    }

    if file_type == FileTypeCheck::CoverImage {
        if !has_file_extension(path, &["png"]) {
            bail!("Image File Error: Invalid image extension. Only expecting \".png\".");
        }
        if file_size < MINIMUM_IMAGE_SIZE {
            bail!("Image File Error: Cover image too small. Not a valid PNG.");
        }
        if file_size > MAX_IMAGE_SIZE {
            bail!("Image File Error: Cover image exceeds the 4MB size limit.");
        }
    }

    if file_type == FileTypeCheck::ArchiveFile {
        if !has_file_extension(path, &["zip", "jar"]) {
            bail!("Archive File Error: Invalid file extension. Only expecting \".zip\" or \".jar\".");
        }
        if file_size < MINIMUM_ARCHIVE_SIZE {
            bail!("Archive File Error: Invalid file size.");
        }
        if file_size > MAX_ARCHIVE_SIZE {
            bail!("Archive File Error: File exceeds maximum size limit.");
        }
    }

    let mut vec = fs::read(path)?;

    if vec.len() != file_size as usize {
        bail!("Failed to read full file: partial read");
    }

    if file_type == FileTypeCheck::ArchiveFile {
        // Prepend IDAT chunk header.
        let mut prefixed = Vec::with_capacity(IDAT_MARKER_BYTES.len() + vec.len() + IDAT_CRC_BYTES.len());
        prefixed.extend_from_slice(&IDAT_MARKER_BYTES);
        prefixed.append(&mut vec);
        prefixed.extend_from_slice(&IDAT_CRC_BYTES);
        vec = prefixed;

        const INDEX_DIFF: usize = 8;
        if vec[INDEX_DIFF..INDEX_DIFF + 4] != ARCHIVE_SIG {
            bail!("Archive File Error: Signature check failure. Not a valid archive file.");
        }
    }

    Ok(vec)
}

pub fn write_polyglot_file(image_vec: &[u8], is_zip_file: bool) -> Result<()> {
    let mut rng = rand::rng();
    let suffix: u32 = rng.random_range(10000..100000);

    let prefix = if is_zip_file { "pzip_" } else { "pjar_" };
    let filename = format!("{}{}.png", prefix, suffix);

    fs::write(&filename, image_vec)?;

    let kind = if is_zip_file { "PNG-ZIP" } else { "PNG-JAR" };
    println!(
        "\nCreated {} polyglot image file: {} ({} bytes).\n\nComplete!\n",
        kind,
        filename,
        image_vec.len()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        if let Err(_) = fs::set_permissions(&filename, perms) {
            eprintln!(
                "\nWarning: Could not set executable permissions for {}.\n\
                 You will need to do this manually using chmod.",
                filename
            );
        }
    }

    Ok(())
}
