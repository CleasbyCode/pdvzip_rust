use crate::types::{FileType, UserArguments};
use crc32fast::Hasher;

pub type ScriptResult<T> = Result<T, String>;

const CHUNK_FIELDS_COMBINED_LENGTH: usize = 12;
const MAX_SCRIPT_SIZE: usize = 1500;
const CRLF: &str = "\r\n";

const TOKEN_LINUX_FILENAME_ARG: &str = "{{LINUX_FILENAME_ARG}}";
const TOKEN_WINDOWS_FILENAME_ARG: &str = "{{WINDOWS_FILENAME_ARG}}";
const TOKEN_LINUX_ARGS: &str = "{{LINUX_ARGS}}";
const TOKEN_WINDOWS_ARGS: &str = "{{WINDOWS_ARGS}}";
const TOKEN_LINUX_ARGS_COMBINED: &str = "{{LINUX_ARGS_COMBINED}}";
const TOKEN_WINDOWS_ARGS_COMBINED: &str = "{{WINDOWS_ARGS_COMBINED}}";

const LINUX_PROBLEM_METACHARACTERS: [u8; 7] = [0x22, 0x27, 0x28, 0x29, 0x3B, 0x3E, 0x60];

struct ScriptTemplate {
    linux_part: &'static str,
    windows_part: &'static str,
}

fn get_script_template(file_type: FileType) -> ScriptTemplate {
    match file_type {
        FileType::VideoAudio => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";NUL="/dev/null";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v mpv >$NUL 2>&1;then clear;mpv --quiet --geometry=50%:50% "$ITEM" &> $NUL;elif command -v vlc >$NUL 2>&1;then clear;vlc --play-and-exit --no-video-title-show "$ITEM" &> $NUL;elif command -v firefox >$NUL 2>&1;then clear;firefox "$ITEM" &> $NUL;else clear;fi;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&start "" {{WINDOWS_FILENAME_ARG}}&exit"#,
        },
        FileType::Pdf => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";NUL="/dev/null";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v evince >$NUL 2>&1;then clear;evince "$ITEM" &> $NUL;else firefox "$ITEM" &> $NUL;clear;fi;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&start "" {{WINDOWS_FILENAME_ARG}}&exit"#,
        },
        FileType::Python => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v python3 >/dev/null 2>&1;then clear;python3 "$ITEM" {{LINUX_ARGS}};else clear;fi;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "APP=python3"&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&where "!APP!" >nul 2>&1 && ("!APP!" {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}} ) || (cls&exit)&echo.&exit"#,
        },
        FileType::Powershell => ScriptTemplate {
            linux_part: r#"DIR="pdvzip_extracted";ITEM={{LINUX_FILENAME_ARG}};clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";hash -r;if command -v pwsh >/dev/null 2>&1;then clear;pwsh "$ITEM" {{LINUX_ARGS}};else clear;fi;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "PDIR=%SystemDrive%\Program Files\PowerShell\"&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&IF EXIST "!PDIR!" (pwsh -ExecutionPolicy Bypass -File {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&echo.&exit) ELSE (powershell -ExecutionPolicy Bypass -File {{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&echo.&exit)"#,
        },
        FileType::BashShell => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";chmod +x "$ITEM";./"$ITEM" {{LINUX_ARGS}};exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS}}&cls&exit"#,
        },
        FileType::WindowsExecutable => ScriptTemplate {
            linux_part: r#"DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";clear;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&{{WINDOWS_FILENAME_ARG}} {{WINDOWS_ARGS_COMBINED}}&echo.&exit"#,
        },
        FileType::Folder => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";xdg-open "$ITEM" &> /dev/null;clear;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&powershell "II '{{WINDOWS_FILENAME_ARG}}'"&cls&exit"#,
        },
        FileType::LinuxExecutable => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";chmod +x "$ITEM";./"$ITEM" {{LINUX_ARGS_COMBINED}};exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&cls&exit"#,
        },
        FileType::Jar => ScriptTemplate {
            linux_part: r#"clear;hash -r;if command -v java >/dev/null 2>&1;then clear;java -jar "$0" {{LINUX_ARGS}};else clear;fi;exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "APP=java"&cls&where "!APP!" >nul 2>&1 && ("!APP!" -jar "%~dpnx0" {{WINDOWS_ARGS}} ) || (cls)&ren "%~dpnx0" *.png&echo.&exit"#,
        },
        FileType::UnknownFileType => ScriptTemplate {
            linux_part: r#"ITEM={{LINUX_FILENAME_ARG}};DIR="pdvzip_extracted";clear;mkdir -p "$DIR";mv "$0" "$DIR";cd "$DIR";unzip -qo "$0";xdg-open "$ITEM";exit;"#,
            windows_part: r#"#&cls&setlocal EnableDelayedExpansion&set "DIR=pdvzip_extracted"&mkdir ".\!DIR!"&move "%~dpnx0" ".\!DIR!"&cd ".\!DIR!"&cls&tar -xf "%~n0%~x0"&ren "%~n0%~x0" *.png&start "" {{WINDOWS_FILENAME_ARG}}&echo.&exit"#,
        },
    }
}

fn replace_all_in_place(target: &mut String, from: &str, to: &str) {
    if from.is_empty() {
        return;
    }
    *target = target.replace(from, to);
}

fn validate_script_input(value: &str, field_name: &str) -> ScriptResult<()> {
    if value
        .bytes()
        .any(|b| b == b'\0' || b == b'\n' || b == b'\r')
    {
        return Err(format!(
            "Arguments Error: {field_name} contains unsupported control characters."
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

fn split_posix_arguments(input: &str, field_name: &str) -> ScriptResult<Vec<String>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let mut args = Vec::<String>::new();
    let mut current = String::new();
    let mut state = QuoteState::None;
    let mut escaped = false;
    let mut token_started = false;

    for ch in input.chars() {
        if state == QuoteState::Single {
            if ch == '\'' {
                state = QuoteState::None;
            } else {
                current.push(ch);
            }
            token_started = true;
            continue;
        }

        if escaped {
            current.push(ch);
            escaped = false;
            token_started = true;
            continue;
        }

        if state == QuoteState::Double {
            if ch == '"' {
                state = QuoteState::None;
            } else if ch == '\\' {
                escaped = true;
            } else {
                current.push(ch);
            }
            token_started = true;
            continue;
        }

        if ch.is_ascii_whitespace() {
            if token_started {
                args.push(std::mem::take(&mut current));
                token_started = false;
            }
            continue;
        }

        match ch {
            '\\' => {
                escaped = true;
                token_started = true;
            }
            '\'' => {
                state = QuoteState::Single;
                token_started = true;
            }
            '"' => {
                state = QuoteState::Double;
                token_started = true;
            }
            _ => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if escaped {
        return Err(syntax_error("end with an unfinished escape sequence."));
    }
    if state != QuoteState::None {
        return Err(syntax_error("contain unmatched quotes."));
    }
    if token_started {
        args.push(current);
    }

    Ok(args)
}

fn split_windows_arguments(input: &str, field_name: &str) -> ScriptResult<Vec<String>> {
    let syntax_error =
        |reason: &str| -> String { format!("Arguments Error: {field_name} {reason}") };

    let bytes = input.as_bytes();
    let mut args = Vec::<String>::new();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let mut current = String::new();
        let mut in_quotes = false;
        let mut backslashes = 0usize;

        while i < bytes.len() {
            let ch = bytes[i] as char;
            if ch == '\\' {
                backslashes += 1;
                i += 1;
                continue;
            }

            if ch == '"' {
                if backslashes % 2 == 0 {
                    current.push_str(&"\\".repeat(backslashes / 2));
                    backslashes = 0;

                    if in_quotes && (i + 1) < bytes.len() && bytes[i + 1] == b'"' {
                        current.push('"');
                        i += 2;
                        continue;
                    }

                    in_quotes = !in_quotes;
                    i += 1;
                    continue;
                }

                current.push_str(&"\\".repeat(backslashes / 2));
                current.push('"');
                backslashes = 0;
                i += 1;
                continue;
            }

            if backslashes > 0 {
                current.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
            }

            if !in_quotes && ch.is_ascii_whitespace() {
                break;
            }

            current.push(ch);
            i += 1;
        }

        if backslashes > 0 {
            current.push_str(&"\\".repeat(backslashes));
        }
        if in_quotes {
            return Err(syntax_error("contain unmatched double quotes."));
        }

        args.push(current);

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
    }

    Ok(args)
}

fn quote_posix_argument(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn quote_windows_argument_for_cmd(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() * 2 + 2);
    out.push('"');

    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if ch == '"' {
            out.push_str(&"\\".repeat(backslashes * 2 + 1));
            out.push('"');
            backslashes = 0;
            continue;
        }

        if backslashes > 0 {
            out.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
        }

        if ch == '%' {
            out.push_str("%%");
        } else {
            out.push(ch);
        }
    }

    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }

    out.push('"');
    out
}

fn render_posix_arguments(raw_args: &str, field_name: &str) -> ScriptResult<String> {
    let args = split_posix_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(String::new());
    }

    let mut rendered = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(' ');
        }
        rendered.push_str(&quote_posix_argument(arg));
    }
    Ok(rendered)
}

fn render_windows_arguments(raw_args: &str, field_name: &str) -> ScriptResult<String> {
    let args = split_windows_arguments(raw_args, field_name)?;
    if args.is_empty() {
        return Ok(String::new());
    }

    let mut rendered = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            rendered.push(' ');
        }
        rendered.push_str(&quote_windows_argument_for_cmd(arg));
    }
    Ok(rendered)
}

fn ensure_no_unresolved_placeholders(script_text: &str) -> ScriptResult<()> {
    let tokens = [
        TOKEN_LINUX_FILENAME_ARG,
        TOKEN_WINDOWS_FILENAME_ARG,
        TOKEN_LINUX_ARGS,
        TOKEN_WINDOWS_ARGS,
        TOKEN_LINUX_ARGS_COMBINED,
        TOKEN_WINDOWS_ARGS_COMBINED,
    ];

    if tokens.iter().any(|token| script_text.contains(token)) {
        return Err(
            "Script Error: Unresolved placeholder token in extraction script template.".to_string(),
        );
    }
    Ok(())
}

fn build_script_text(
    file_type: FileType,
    first_filename: &str,
    user_args: &UserArguments,
) -> ScriptResult<String> {
    let script_template = get_script_template(file_type);

    let mut script_text = String::with_capacity(
        script_template.linux_part.len() + CRLF.len() + script_template.windows_part.len() + 256,
    );
    script_text.push_str(script_template.linux_part);
    script_text.push_str(CRLF);
    script_text.push_str(script_template.windows_part);

    if script_text.contains(TOKEN_LINUX_FILENAME_ARG) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_LINUX_FILENAME_ARG,
            &quote_posix_argument(first_filename),
        );
    }
    if script_text.contains(TOKEN_WINDOWS_FILENAME_ARG) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_WINDOWS_FILENAME_ARG,
            &quote_windows_argument_for_cmd(first_filename),
        );
    }

    if script_text.contains(TOKEN_LINUX_ARGS) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_LINUX_ARGS,
            &render_posix_arguments(&user_args.linux_args, "Linux arguments")?,
        );
    }
    if script_text.contains(TOKEN_WINDOWS_ARGS) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_WINDOWS_ARGS,
            &render_windows_arguments(&user_args.windows_args, "Windows arguments")?,
        );
    }

    let args_combined_raw = if user_args.linux_args.is_empty() {
        user_args.windows_args.as_str()
    } else {
        user_args.linux_args.as_str()
    };

    if script_text.contains(TOKEN_LINUX_ARGS_COMBINED) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_LINUX_ARGS_COMBINED,
            &render_posix_arguments(args_combined_raw, "Combined Linux arguments")?,
        );
    }
    if script_text.contains(TOKEN_WINDOWS_ARGS_COMBINED) {
        replace_all_in_place(
            &mut script_text,
            TOKEN_WINDOWS_ARGS_COMBINED,
            &render_windows_arguments(args_combined_raw, "Combined Windows arguments")?,
        );
    }

    ensure_no_unresolved_placeholders(&script_text)?;
    Ok(script_text)
}

fn update_be_u32(data: &mut [u8], index: usize, value: usize) -> ScriptResult<()> {
    if value > u32::MAX as usize {
        return Err("Script Error: Value exceeds 32-bit range.".to_string());
    }
    if index > data.len() || 4 > (data.len() - index) {
        return Err("Script Error: Index out of bounds while writing 32-bit value.".to_string());
    }

    let value = value as u32;
    data[index..index + 4].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn build_extraction_script(
    file_type: FileType,
    first_filename: &str,
    user_args: &UserArguments,
) -> ScriptResult<Vec<u8>> {
    const SCRIPT_INDEX: usize = 0x16;
    const ICCP_CHUNK_NAME_INDEX: usize = 0x04;
    const ICCP_CHUNK_NAME_LENGTH: usize = 4;
    const ICCP_CRC_INDEX_DIFF: usize = 8;
    const LENGTH_FIRST_BYTE_INDEX: usize = 3;

    validate_script_input(first_filename, "Archive filename")?;
    validate_script_input(&user_args.linux_args, "Linux arguments")?;
    validate_script_input(&user_args.windows_args, "Windows arguments")?;

    let mut script_vec = vec![
        0x00, 0x00, 0x00, 0x00, 0x69, 0x43, 0x43, 0x50, 0x44, 0x56, 0x5A, 0x49, 0x50, 0x5F, 0x5F,
        0x00, 0x00, 0x0D, 0x52, 0x45, 0x4D, 0x3B, 0x0D, 0x0A, 0x00, 0x00, 0x00, 0x00,
    ];
    script_vec.reserve(script_vec.len() + MAX_SCRIPT_SIZE);

    let script_text = build_script_text(file_type, first_filename, user_args)?;
    script_vec.splice(SCRIPT_INDEX..SCRIPT_INDEX, script_text.bytes());

    let mut chunk_data_size = script_vec
        .len()
        .checked_sub(CHUNK_FIELDS_COMBINED_LENGTH)
        .ok_or_else(|| "Script Error: Invalid chunk size.".to_string())?;
    update_be_u32(&mut script_vec, 0, chunk_data_size)?;

    if LINUX_PROBLEM_METACHARACTERS.contains(&script_vec[LENGTH_FIRST_BYTE_INDEX]) {
        const PAD: &[u8] = b"........";
        const PAD_OFFSET: usize = 8;
        let pad_index = chunk_data_size + PAD_OFFSET;
        script_vec.splice(pad_index..pad_index, PAD.iter().copied());
        chunk_data_size = script_vec
            .len()
            .checked_sub(CHUNK_FIELDS_COMBINED_LENGTH)
            .ok_or_else(|| "Script Error: Invalid chunk size.".to_string())?;
        update_be_u32(&mut script_vec, 0, chunk_data_size)?;
    }

    if chunk_data_size > MAX_SCRIPT_SIZE {
        return Err("Script Size Error: Extraction script exceeds size limit.".to_string());
    }

    let iccp_chunk_length = chunk_data_size + ICCP_CHUNK_NAME_LENGTH;
    let crc_start = ICCP_CHUNK_NAME_INDEX;
    let crc_end = crc_start + iccp_chunk_length;
    if crc_end > script_vec.len() {
        return Err("Script Error: Invalid CRC range.".to_string());
    }

    let mut hasher = Hasher::new();
    hasher.update(&script_vec[crc_start..crc_end]);
    let crc = hasher.finalize();

    let crc_index = chunk_data_size + ICCP_CRC_INDEX_DIFF;
    update_be_u32(&mut script_vec, crc_index, crc as usize)?;
    Ok(script_vec)
}

#[cfg(test)]
mod tests {
    use super::build_extraction_script;
    use crate::types::{FileType, UserArguments};

    fn decode_hex(hex: &str) -> Vec<u8> {
        let trimmed = hex.trim();
        assert!(trimmed.len() % 2 == 0, "hex input must have even length");
        let mut out = Vec::with_capacity(trimmed.len() / 2);
        let bytes = trimmed.as_bytes();
        let to_nibble = |b: u8| -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex character: {}", b as char),
            }
        };
        for i in (0..bytes.len()).step_by(2) {
            let high = to_nibble(bytes[i]);
            let low = to_nibble(bytes[i + 1]);
            out.push((high << 4) | low);
        }
        out
    }

    fn fixture(name: &str) -> Vec<u8> {
        let hex = match name {
            "video_basic" => include_str!("../tests/fixtures/video_basic.hex"),
            "python_escaped" => include_str!("../tests/fixtures/python_escaped.hex"),
            "linux_combined" => include_str!("../tests/fixtures/linux_combined.hex"),
            "jar_args" => include_str!("../tests/fixtures/jar_args.hex"),
            _ => panic!("unknown fixture {name}"),
        };
        decode_hex(hex)
    }

    #[test]
    fn rejects_control_characters() {
        let args = UserArguments {
            linux_args: "--ok\n--bad".to_string(),
            windows_args: String::new(),
        };
        assert!(build_extraction_script(FileType::Python, "tool.py", &args).is_err());
    }

    #[test]
    fn parity_video_basic() {
        let args = UserArguments::default();
        let script =
            build_extraction_script(FileType::VideoAudio, "movie.mp4", &args).expect("script");
        assert_eq!(script, fixture("video_basic"));
    }

    #[test]
    fn parity_python_escaped() {
        let args = UserArguments {
            linux_args: r#"--alpha "two words" "O'Reilly""#.to_string(),
            windows_args: r#"%USERPROFILE% "C:\Path With Spaces\tool.exe""#.to_string(),
        };
        let script = build_extraction_script(FileType::Python, "tool.py", &args).expect("script");
        assert_eq!(script, fixture("python_escaped"));
    }

    #[test]
    fn parity_linux_combined() {
        let args = UserArguments {
            linux_args: String::new(),
            windows_args: "--combined".to_string(),
        };
        let script =
            build_extraction_script(FileType::LinuxExecutable, "runner", &args).expect("script");
        assert_eq!(script, fixture("linux_combined"));
    }

    #[test]
    fn parity_jar_args() {
        let args = UserArguments {
            linux_args: "--jar-arg".to_string(),
            windows_args: "--wjar".to_string(),
        };
        let script =
            build_extraction_script(FileType::Jar, "META-INF/MANIFEST.MF", &args).expect("script");
        assert_eq!(script, fixture("jar_args"));
    }
}
