use anyhow::{bail, Result};
use std::path::Path;

pub struct ProgramArgs {
    pub image_file_path: Option<String>,
    pub archive_file_path: Option<String>,
    pub info_mode: bool,
}

impl ProgramArgs {
    pub fn parse() -> Result<Self> {
        let args: Vec<String> = std::env::args().collect();

        if args.len() == 2 && args[1] == "--info" {
            return Ok(ProgramArgs {
                image_file_path: None,
                archive_file_path: None,
                info_mode: true,
            });
        }

        if args.len() != 3 {
            let prog = Path::new(&args[0])
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "pdvzip".to_string());
            bail!(
                "Usage: {} <cover_image> <zip/jar>\n       {} --info",
                prog,
                prog
            );
        }

        Ok(ProgramArgs {
            image_file_path: Some(args[1].clone()),
            archive_file_path: Some(args[2].clone()),
            info_mode: false,
        })
    }
}
