//  PNG Data Vehicle, ZIP/JAR Edition (PDVZIP v4.3)
//  Created by Nicholas Cleasby (@CleasbyCode) 6/08/2022

mod archive_analysis;
mod binary_utils;
mod display_info;
mod file_io;
mod image_processing;
mod polyglot_assembly;
mod program_args;
mod script_builder;
mod user_input;

use std::path::Path;

pub const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;
pub const MAX_SCRIPT_SIZE: usize = 1500;

/// Shell metacharacters that corrupt bash's parser state when encountered
/// in the PNG binary preamble before the extraction script.
pub const LINUX_PROBLEM_METACHARACTERS: [u8; 7] = [0x22, 0x27, 0x28, 0x29, 0x3B, 0x3E, 0x60];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    VideoAudio = 29,
    Pdf = 30,
    Python = 31,
    PowerShell = 32,
    BashShell = 33,
    WindowsExecutable = 34,
    UnknownFileType = 35,
    Folder = 36,
    LinuxExecutable = 37,
    Jar = 38,
}

impl FileType {
    pub fn from_index(index: usize) -> Self {
        match index {
            29 => FileType::VideoAudio,
            30 => FileType::Pdf,
            31 => FileType::Python,
            32 => FileType::PowerShell,
            33 => FileType::BashShell,
            34 => FileType::WindowsExecutable,
            35 => FileType::UnknownFileType,
            36 => FileType::Folder,
            37 => FileType::LinuxExecutable,
            38 => FileType::Jar,
            _ => FileType::UnknownFileType,
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{}\n", e);
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args = program_args::ProgramArgs::parse()?;

    if args.info_mode {
        display_info::display_info();
        return Ok(());
    }

    let image_path = args.image_file_path.as_ref().unwrap();
    let archive_path = args.archive_file_path.as_ref().unwrap();

    let mut image_vec = file_io::read_file(Path::new(image_path), file_io::FileTypeCheck::CoverImage)?;
    let mut archive_vec = file_io::read_file(Path::new(archive_path), file_io::FileTypeCheck::ArchiveFile)?;

    image_processing::optimize_image(&mut image_vec)?;

    let original_image_size = image_vec.len();
    let archive_file_size = archive_vec.len();

    let is_zip_file = file_io::has_file_extension(Path::new(archive_path), &["zip"]);

    // Update the IDAT chunk length to include the archive.
    binary_utils::update_value_be(
        &mut archive_vec,
        0,
        (archive_file_size - CHUNK_FIELDS_COMBINED_LENGTH) as u32,
        4,
    )?;

    // Determine what kind of file is embedded.
    let file_type = archive_analysis::determine_file_type(&archive_vec, is_zip_file)?;
    let first_filename = archive_analysis::get_archive_first_filename(&archive_vec);

    // Prompt for optional arguments (scripts, executables, JAR).
    let user_args = user_input::prompt_for_arguments(file_type)?;

    // Build the iCCP chunk containing the extraction script.
    let script_vec = script_builder::build_extraction_script(file_type, &first_filename, &user_args)?;

    // Assemble the polyglot: embed script + archive, fix offsets, finalize CRC.
    polyglot_assembly::embed_chunks(&mut image_vec, script_vec, archive_vec, original_image_size)?;

    // Write output.
    file_io::write_polyglot_file(&image_vec, is_zip_file)?;

    Ok(())
}
