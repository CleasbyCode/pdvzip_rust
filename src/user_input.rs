use crate::FileType;
use anyhow::{bail, Result};
use std::io::{self, Write};

pub struct UserArguments {
    pub linux_args: String,
    pub windows_args: String,
}

pub fn has_balanced_quotes(s: &str) -> bool {
    let mut single_count: usize = 0;
    let mut double_count: usize = 0;
    let bytes = s.as_bytes();

    for i in 0..bytes.len() {
        let c = bytes[i];
        let escaped = i > 0 && bytes[i - 1] == b'\\';
        if c == b'\'' && !escaped {
            single_count += 1;
        } else if c == b'"' && !escaped {
            double_count += 1;
        }
    }
    single_count % 2 == 0 && double_count % 2 == 0
}

pub fn prompt_for_arguments(file_type: FileType) -> Result<UserArguments> {
    let mut args = UserArguments {
        linux_args: String::new(),
        windows_args: String::new(),
    };

    let needs_args = matches!(
        file_type,
        FileType::Python
            | FileType::PowerShell
            | FileType::BashShell
            | FileType::WindowsExecutable
            | FileType::LinuxExecutable
            | FileType::Jar
    );

    if !needs_args {
        return Ok(args);
    }

    println!("\nFor this file type, if required, you can provide command-line arguments here.");

    if file_type != FileType::WindowsExecutable {
        print!("\nLinux: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut args.linux_args)?;
        args.linux_args = args.linux_args.trim_end_matches('\n').trim_end_matches('\r').to_string();
    }
    if file_type != FileType::LinuxExecutable {
        print!("\nWindows: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut args.windows_args)?;
        args.windows_args = args.windows_args.trim_end_matches('\n').trim_end_matches('\r').to_string();
    }

    if !has_balanced_quotes(&args.linux_args) || !has_balanced_quotes(&args.windows_args) {
        bail!("Arguments Error: Quotes mismatch. Check arguments and try again.");
    }

    Ok(args)
}
