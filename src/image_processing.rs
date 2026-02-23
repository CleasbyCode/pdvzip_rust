use crate::binary_utils::{get_value_be, search_sig};
use crate::LINUX_PROBLEM_METACHARACTERS;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Cursor;

const INDEXED_PLTE: u8 = 3;
const TRUECOLOR_RGB: u8 = 2;
const TRUECOLOR_RGBA: u8 = 6;

const PNG_HEADER_AND_IHDR_SIZE: usize = 33;
const CHUNK_OVERHEAD: usize = 12;
const LENGTH_FIELD_SIZE: usize = 4;
const IEND_CHUNK_SIZE: usize = 12;

const PLTE_SIG: [u8; 4] = [0x50, 0x4C, 0x54, 0x45];
const TRNS_SIG: [u8; 4] = [0x74, 0x52, 0x4E, 0x53];
const IDAT_SIG: [u8; 4] = [0x49, 0x44, 0x41, 0x54];
const IEND_SIG: [u8; 8] = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];

struct ColorStats {
    num_colors: usize,
    palette: Vec<[u8; 4]>, // RGBA
}

/// Count unique RGBA colors in the image. Stops early if >256 colors found.
fn compute_color_stats(rgba_image: &[u8]) -> ColorStats {
    let mut palette = Vec::new();
    let mut seen: HashMap<[u8; 4], usize> = HashMap::new();

    for chunk in rgba_image.chunks_exact(4) {
        let color: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
        if !seen.contains_key(&color) {
            if palette.len() >= 256 {
                return ColorStats {
                    num_colors: 257,
                    palette,
                };
            }
            seen.insert(color, palette.len());
            palette.push(color);
        }
    }

    ColorStats {
        num_colors: palette.len(),
        palette,
    }
}

// ============================================================================
// Decode a PNG from bytes to raw RGBA pixels + metadata
// ============================================================================

struct DecodedImage {
    pixels: Vec<u8>,     // Raw pixel data (format depends on transformation)
    width: u32,
    height: u32,
    color_type: png::ColorType,
    bit_depth: png::BitDepth,
    palette: Option<Vec<u8>>,  // RGB triplets
    trns: Option<Vec<u8>>,     // Alpha values for palette entries
}

fn decode_png_raw(data: &[u8]) -> Result<DecodedImage> {
    let decoder = png::Decoder::new(Cursor::new(data));
    let mut reader = decoder.read_info()?;
    let info = reader.info().clone();

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame_info = reader.next_frame(&mut buf)?;
    buf.truncate(frame_info.buffer_size());

    Ok(DecodedImage {
        pixels: buf,
        width: info.width,
        height: info.height,
        color_type: info.color_type,
        bit_depth: info.bit_depth,
        palette: info.palette.as_ref().map(|p| p.to_vec()),
        trns: info.trns.as_ref().map(|t| t.to_vec()),
    })
}

/// Decode PNG to RGBA8 pixels regardless of input format.
fn decode_to_rgba(data: &[u8]) -> Result<(Vec<u8>, u32, u32, png::ColorType)> {
    let decoded = decode_png_raw(data)?;
    let original_color_type = decoded.color_type;
    let w = decoded.width;
    let h = decoded.height;

    let rgba = match decoded.color_type {
        png::ColorType::Rgba => decoded.pixels,
        png::ColorType::Rgb => {
            decoded
                .pixels
                .chunks_exact(3)
                .flat_map(|c| [c[0], c[1], c[2], 255])
                .collect()
        }
        png::ColorType::Indexed => {
            let palette = decoded.palette.as_deref()
                .ok_or_else(|| anyhow::anyhow!("Indexed image missing palette"))?;
            let trns = decoded.trns.as_deref();

            // Unpack sub-byte indices if necessary.
            let indices = unpack_indices(&decoded.pixels, w, h, decoded.bit_depth);

            indices
                .iter()
                .map(|&idx| {
                    let i = idx as usize;
                    let r = palette.get(i * 3).copied().unwrap_or(0);
                    let g = palette.get(i * 3 + 1).copied().unwrap_or(0);
                    let b = palette.get(i * 3 + 2).copied().unwrap_or(0);
                    let a = trns.and_then(|t| t.get(i).copied()).unwrap_or(255);
                    [r, g, b, a]
                })
                .flatten()
                .collect()
        }
        png::ColorType::Grayscale => {
            decoded
                .pixels
                .iter()
                .flat_map(|&g| [g, g, g, 255])
                .collect()
        }
        png::ColorType::GrayscaleAlpha => {
            decoded
                .pixels
                .chunks_exact(2)
                .flat_map(|c| [c[0], c[0], c[0], c[1]])
                .collect()
        }
    };

    Ok((rgba, w, h, original_color_type))
}

/// Unpack sub-byte palette indices (1, 2, 4 bit) to one byte per pixel.
/// For 8-bit, returns the data unchanged.
fn unpack_indices(packed: &[u8], width: u32, height: u32, bit_depth: png::BitDepth) -> Vec<u8> {
    let bits = match bit_depth {
        png::BitDepth::One => 1,
        png::BitDepth::Two => 2,
        png::BitDepth::Four => 4,
        png::BitDepth::Eight => return packed.to_vec(),
        png::BitDepth::Sixteen => return packed.to_vec(),
    };

    let pixels_per_byte = 8 / bits;
    let mask = (1u8 << bits) - 1;
    let w = width as usize;
    let h = height as usize;
    let row_bytes = (w * bits + 7) / 8;

    let mut unpacked = Vec::with_capacity(w * h);

    for y in 0..h {
        let row_start = y * row_bytes;
        for x in 0..w {
            let byte_idx = row_start + x / pixels_per_byte;
            let bit_offset = (pixels_per_byte - 1 - (x % pixels_per_byte)) * bits;
            let idx = (packed[byte_idx] >> bit_offset) & mask;
            unpacked.push(idx);
        }
    }

    unpacked
}

/// Encode raw pixels back to a PNG byte vector.
fn encode_png(
    pixels: &[u8],
    width: u32,
    height: u32,
    color_type: png::ColorType,
    bit_depth: png::BitDepth,
    palette: Option<&[u8]>,
    trns: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, width, height);
        encoder.set_color(color_type);
        encoder.set_depth(bit_depth);
        encoder.set_compression(png::Compression::Best);
        encoder.set_adaptive_filter(png::AdaptiveFilterType::Adaptive);
        if let Some(pal) = palette {
            encoder.set_palette(pal);
        }
        if let Some(t) = trns {
            encoder.set_trns(t);
        }
        let mut writer = encoder.write_header()?;
        writer.write_image_data(pixels)?;
    }
    Ok(output)
}

// ============================================================================
// Resize image by 1 pixel in each dimension
// ============================================================================

fn resize_image(image_file_vec: &mut Vec<u8>) -> Result<()> {
    const MIN_DIMENSION: u32 = 68;
    const SAMPLING_OFFSET: f64 = 0.5;

    let decoded = decode_png_raw(image_file_vec)?;
    let width = decoded.width;
    let height = decoded.height;

    if width <= MIN_DIMENSION || height <= MIN_DIMENSION {
        bail!("Image dimensions too small to reduce.");
    }

    let is_palette = decoded.color_type == png::ColorType::Indexed;
    let bit_depth = decoded.bit_depth;

    // For sub-byte palette images, unpack to 8-bit indices.
    let (pixels, effective_bit_depth) = if is_palette && matches!(bit_depth, png::BitDepth::One | png::BitDepth::Two | png::BitDepth::Four) {
        (unpack_indices(&decoded.pixels, width, height, bit_depth), png::BitDepth::Eight)
    } else {
        (decoded.pixels, bit_depth)
    };

    let channels: usize = match decoded.color_type {
        png::ColorType::Indexed => 1,
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
    };

    let new_width = width - 1;
    let new_height = height - 1;

    let x_ratio = width as f64 / new_width as f64;
    let y_ratio = height as f64 / new_height as f64;

    let bytes_per_pixel = if is_palette { 1 } else { channels };
    let mut resized = vec![0u8; new_width as usize * new_height as usize * bytes_per_pixel];

    for y in 0..new_height {
        for x in 0..new_width {
            let src_x = ((x as f64 + SAMPLING_OFFSET) * x_ratio - SAMPLING_OFFSET)
                .clamp(0.0, (width - 1) as f64);
            let src_y = ((y as f64 + SAMPLING_OFFSET) * y_ratio - SAMPLING_OFFSET)
                .clamp(0.0, (height - 1) as f64);

            if is_palette {
                // Nearest-neighbor for palette images.
                let ix = src_x.round() as u32;
                let iy = src_y.round() as u32;
                resized[(y * new_width + x) as usize] =
                    pixels[(iy * width + ix) as usize];
            } else {
                // Bilinear interpolation for truecolor/greyscale.
                let x0 = src_x as u32;
                let y0 = src_y as u32;
                let x1 = (x0 + 1).min(width - 1);
                let y1 = (y0 + 1).min(height - 1);

                let dx = src_x - x0 as f64;
                let dy = src_y - y0 as f64;

                for c in 0..channels {
                    let val = (1.0 - dx) * (1.0 - dy) * pixels[(channels * (y0 * width + x0) as usize) + c] as f64
                        + (1.0 - dx) * dy * pixels[(channels * (y1 * width + x0) as usize) + c] as f64
                        + dx * (1.0 - dy) * pixels[(channels * (y0 * width + x1) as usize) + c] as f64
                        + dx * dy * pixels[(channels * (y1 * width + x1) as usize) + c] as f64;
                    resized[(channels * (y * new_width + x) as usize) + c] =
                        val.round().clamp(0.0, 255.0) as u8;
                }
            }
        }
    }

    // Re-encode with the same color type and palette.
    let output = encode_png(
        &resized,
        new_width,
        new_height,
        decoded.color_type,
        effective_bit_depth,
        decoded.palette.as_deref(),
        decoded.trns.as_deref(),
    )?;

    *image_file_vec = output;
    Ok(())
}

// ============================================================================
// Convert truecolor image to indexed palette
// ============================================================================

fn convert_to_palette(
    image_file_vec: &mut Vec<u8>,
    rgba_image: &[u8],
    width: u32,
    height: u32,
    stats: &ColorStats,
    channels: usize,
) -> Result<()> {
    if stats.num_colors == 0 {
        bail!("convertToPalette: Palette is empty.");
    }
    if stats.num_colors > 256 {
        bail!("convertToPalette: Palette has {} colors, exceeds maximum of 256.", stats.num_colors);
    }

    // Build lookup from RGBA key -> palette index.
    let mut color_to_index: HashMap<[u8; 4], u8> = HashMap::with_capacity(stats.num_colors);
    for (i, &color) in stats.palette.iter().enumerate() {
        color_to_index.insert(color, i as u8);
    }

    // Map each pixel to its palette index.
    let pixel_count = (width as usize) * (height as usize);
    let mut indexed_image = Vec::with_capacity(pixel_count);

    for i in 0..pixel_count {
        let offset = i * channels;
        let key = [
            rgba_image[offset],
            rgba_image[offset + 1],
            rgba_image[offset + 2],
            if channels == 4 { rgba_image[offset + 3] } else { 255 },
        ];
        let idx = color_to_index.get(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "convertToPalette: Pixel {} has color not found in palette.",
                i
            )
        })?;
        indexed_image.push(*idx);
    }

    // Build RGB palette and tRNS data.
    let mut palette_rgb = Vec::with_capacity(stats.num_colors * 3);
    let mut trns_alpha = Vec::with_capacity(stats.num_colors);
    let mut has_transparency = false;

    for color in &stats.palette {
        palette_rgb.extend_from_slice(&[color[0], color[1], color[2]]);
        trns_alpha.push(color[3]);
        if color[3] != 255 {
            has_transparency = true;
        }
    }

    let trns = if has_transparency {
        Some(trns_alpha.as_slice())
    } else {
        None
    };

    let output = encode_png(
        &indexed_image,
        width,
        height,
        png::ColorType::Indexed,
        png::BitDepth::Eight,
        Some(&palette_rgb),
        trns,
    )?;

    *image_file_vec = output;
    Ok(())
}

// ============================================================================
// Strip non-essential chunks, keeping only IHDR, PLTE, tRNS, IDAT, IEND
// ============================================================================

fn strip_and_copy_chunks(image_file_vec: &mut Vec<u8>, color_type: u8) -> Result<()> {
    let file_size = image_file_vec.len();

    if file_size < PNG_HEADER_AND_IHDR_SIZE + IEND_CHUNK_SIZE {
        bail!("PNG Error: File too small to contain valid PNG structure.");
    }

    // Truncate any trailing data after IEND.
    if let Some(pos) = search_sig(image_file_vec, &IEND_SIG, 0) {
        let end_index = pos + IEND_SIG.len();
        if end_index <= file_size {
            image_file_vec.truncate(end_index);
        }
    }

    let mut cleaned_png = Vec::with_capacity(image_file_vec.len());

    // Copy PNG signature + IHDR chunk.
    cleaned_png.extend_from_slice(&image_file_vec[..PNG_HEADER_AND_IHDR_SIZE]);

    // Copy all chunks of a given type.
    let mut copy_chunks_of_type = |chunk_sig: &[u8; 4]| -> Result<()> {
        let mut search_pos = PNG_HEADER_AND_IHDR_SIZE;

        while let Some(name_index) = search_sig(image_file_vec, chunk_sig, search_pos) {
            if name_index < LENGTH_FIELD_SIZE {
                bail!("PNG Error: Chunk found before valid length field.");
            }

            let chunk_start = name_index - LENGTH_FIELD_SIZE;
            let data_length = get_value_be(image_file_vec, chunk_start, 4)? as usize;
            let total_chunk_size = data_length + CHUNK_OVERHEAD;

            if chunk_start + total_chunk_size > image_file_vec.len() {
                bail!(
                    "PNG Error: Chunk at offset 0x{:X} claims length {} but exceeds file size.",
                    chunk_start,
                    data_length
                );
            }

            cleaned_png.extend_from_slice(
                &image_file_vec[chunk_start..chunk_start + total_chunk_size],
            );
            search_pos = chunk_start + total_chunk_size;
        }
        Ok(())
    };

    if color_type == INDEXED_PLTE {
        copy_chunks_of_type(&PLTE_SIG)?;
    }
    copy_chunks_of_type(&TRNS_SIG)?;
    copy_chunks_of_type(&IDAT_SIG)?;

    // Append IEND chunk.
    let iend_start = image_file_vec.len() - IEND_CHUNK_SIZE;
    cleaned_png.extend_from_slice(&image_file_vec[iend_start..]);

    *image_file_vec = cleaned_png;
    Ok(())
}

// ============================================================================
// Public: Optimize image for polyglot embedding
// ============================================================================

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> Result<()> {
    const MIN_RGB_COLORS: usize = 257;

    // Decode to RGBA for color analysis.
    let (rgba_image, width, height, original_color_type) = decode_to_rgba(image_file_vec)?;

    let stats = compute_color_stats(&rgba_image);

    let mut color_type = match original_color_type {
        png::ColorType::Indexed => INDEXED_PLTE,
        png::ColorType::Rgb => TRUECOLOR_RGB,
        png::ColorType::Rgba => TRUECOLOR_RGBA,
        other => bail!("Image File Error: Color type {:?} is not supported.", other),
    };

    let is_truecolor = color_type == TRUECOLOR_RGB || color_type == TRUECOLOR_RGBA;
    let can_palettize = is_truecolor && stats.num_colors < MIN_RGB_COLORS;

    if can_palettize {
        // decode_to_rgba always produces RGBA (4 channels).
        convert_to_palette(image_file_vec, &rgba_image, width, height, &stats, 4)?;
        color_type = INDEXED_PLTE;
    } else {
        strip_and_copy_chunks(image_file_vec, color_type)?;
    }

    // Check for problem metacharacters in IHDR width/height and CRC fields.
    // IHDR layout (offsets from start of file):
    //   0x10..0x17  Width + Height (8 bytes)
    //   0x1D..0x20  CRC (4 bytes)
    const WIDTH_START: usize = 0x10;
    const HEIGHT_END: usize = 0x18;
    const CRC_START: usize = 0x1D;
    const CRC_END: usize = 0x21;

    const MIN_DIMS: u32 = 68;
    const MAX_PLTE_DIMS: u32 = 4096;
    const MAX_RGB_DIMS: u32 = 900;
    const MAX_RESIZE_ITERATIONS: u32 = 200;

    let has_problem_character = |data: &[u8]| -> bool {
        let check = |start: usize, end: usize| -> bool {
            data[start..end]
                .iter()
                .any(|b| LINUX_PROBLEM_METACHARACTERS.contains(b))
        };
        check(WIDTH_START, HEIGHT_END) || check(CRC_START, CRC_END)
    };

    let mut iterations = 0u32;
    while has_problem_character(image_file_vec) {
        iterations += 1;
        if iterations > MAX_RESIZE_ITERATIONS {
            bail!(
                "Image Error: Could not eliminate problem characters from IHDR \
                 within the resize iteration limit."
            );
        }
        resize_image(image_file_vec)?;
    }

    // After potential resizing, RGBA may have been re-encoded as RGB by the encoder.
    if color_type == TRUECOLOR_RGBA {
        color_type = TRUECOLOR_RGB;
    }

    let has_valid_color_type = color_type == INDEXED_PLTE || color_type == TRUECOLOR_RGB;

    let check_dimensions = |target_color: u8, max_dims: u32| -> bool {
        color_type == target_color
            && width >= MIN_DIMS
            && width <= max_dims
            && height >= MIN_DIMS
            && height <= max_dims
    };

    let has_valid_dimensions =
        check_dimensions(TRUECOLOR_RGB, MAX_RGB_DIMS) || check_dimensions(INDEXED_PLTE, MAX_PLTE_DIMS);

    if !has_valid_color_type || !has_valid_dimensions {
        if !has_valid_color_type {
            eprint!(
                "\nImage File Error: Color type of cover image is not supported.\n\n\
                 Supported types: PNG-32/24 (Truecolor) or PNG-8 (Indexed-Color)."
            );
        } else {
            eprint!(
                "\nImage File Error: Dimensions of cover image are not within the supported range.\n\n\
                 Supported ranges:\n\
                 - PNG-32/24 Truecolor: [68 x 68] to [900 x 900]\n\
                 - PNG-8 Indexed-Color: [68 x 68] to [4096 x 4096]\n"
            );
        }
        bail!("Incompatible image. Aborting.");
    }

    Ok(())
}
