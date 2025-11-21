//! Steganography routines for extracting text from PNG images.
//!
//! Implements the logic for extracting text from a PNG image.
//!
//! # Errors
//!
//! Returns [`StegoError`] when extracting text fails.
use image::RgbaImage;

use super::{
    HEADER_BITS, MAX_REASONABLE_MESSAGE_SIZE, StegoError, channel_capacity_bits,
};

/// Extracts UTF-8 text previously embedded with [`embed_text`] from the
/// provided image.
///
/// # Errors
///
/// Returns [`StegoError::MissingHeader`] when the image does not contain enough
/// bits to recover the message length,
///
/// [`StegoError::UnreasonablePayloadSize`] when the payload size is too large
/// to fit in the image,
///
/// [`StegoError::DeclaredPayloadExceedsCapacity`] when the header is
/// invalid or the payload size is too large to fit in the image,
///
/// [`StegoError::IncompletePayload`] when the image data ends before the
/// payload could be fully reconstructed,
///
/// [`StegoError::InvalidUtf8`] when the resulting payload is not valid UTF-8.
///
/// # Panics
///
/// Panics if the length bits are too large to fit in a usize.
pub fn extract_text(image: &RgbaImage) -> Result<String, StegoError>
{
    let available_bits = channel_capacity_bits(image);
    if available_bits < usize::from(HEADER_BITS)
    {
        return Err(StegoError::MissingHeader { available_bits });
    }

    let mut bit_iter = image
        .pixels()
        // ignore alpha channel
        .flat_map(|pixel| pixel.0[..3].iter())
        // just the lsb
        .map(|channel| channel & 1);

    // Construct the length bits from the first HEADER_BITS bits
    let mut length_bits: u32 = 0;
    for _ in 0..HEADER_BITS
    {
        let bit = bit_iter
            .next()
            .ok_or(StegoError::MissingHeader { available_bits })?;

        length_bits = (length_bits << 1) | u32::from(bit);
    }

    let declared_bytes: usize = length_bits
        .try_into()
        .expect("length_bits is too large to fit in usize");

    if declared_bytes > MAX_REASONABLE_MESSAGE_SIZE
    {
        return Err(StegoError::UnreasonablePayloadSize { declared_bytes });
    }

    // Our data starts after the header, so we need to subtract the header
    let remaining_capacity_bits = available_bits - usize::from(HEADER_BITS);
    let remaining_capacity_bytes = remaining_capacity_bits / 8;

    if declared_bytes > remaining_capacity_bytes
    {
        return Err(StegoError::DeclaredPayloadExceedsCapacity {
            declared_bytes,
            available_bytes: remaining_capacity_bytes,
        });
    }

    let mut payload = Vec::with_capacity(declared_bytes);
    for _ in 0..declared_bytes
    {
        let mut value: u8 = 0; // A single byte in the unicode payload
        for _ in 0..u8::BITS
        {
            let bit = bit_iter
                .next()
                .ok_or(StegoError::IncompletePayload)?;
            value = (value << 1) | bit;
        }
        payload.push(value);
    }

    String::from_utf8(payload).map_err(StegoError::InvalidUtf8)
}
