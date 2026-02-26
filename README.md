# pdvzip Rust Port

This crate is the incremental Rust migration target for `pdvzip`.

Current scope:
- Architecture scaffold matching the C++ module split.
- Functional ports:
  - archive parsing/type detection/path validation
  - script builder with shell-escaping logic and chunk/CRC generation
  - polyglot assembly/ZIP offset fixups/final CRC rewrite
  - file IO validation/wrapping/output writing and CLI parsing flow
  - image chunk filtering + PNG compatibility checks

## Commands

```bash
cargo test
cargo run -- --info
cargo run -- <cover.png> <archive.zip|archive.jar>
```

Fuzzing (after `cargo install cargo-fuzz`):

```bash
bash fuzz/run_fuzz_smoke.sh
```

## Status

- Ported:
  - `archive_analysis.cpp` -> `src/archive.rs`
  - core integer read/write utilities -> `src/binary_utils.rs`
  - `script_builder.cpp` -> `src/script.rs`
  - `polyglot_assembly.cpp` -> `src/assembly.rs`
  - `file_io.cpp` -> `src/io.rs`
  - `program_args.cpp`/main flow -> `src/main.rs`
  - `image_processing.cpp` -> `src/image.rs` (decode/strip/palettize/resize pipeline)
  - parity fixtures for script chunk outputs in `tests/fixtures/*.hex`
  - parity fixtures for assembly outputs in `tests/fixtures/assembly_*`
  - image parity fixtures (`tests/fixtures/image_parity/*`) validated against C++ outputs
  - randomized robustness test coverage (`tests/robustness.rs`)
- Next major hardening work:
  - expand corpus depth + longer periodic fuzz campaigns
