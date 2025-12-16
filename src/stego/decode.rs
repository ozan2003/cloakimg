//! Steganography routines for extracting payload bytes from images.
//!
//! Implements the logic for extracting payload bytes from an image.
use image::{Pixel, RgbImage};

use super::{
    HEADER_BITS, MAX_REASONABLE_MSG_SIZE, StegoError, channel_capacity_bits,
};

/// Extracts the raw payload previously embedded with [`embed_text`] from the
/// provided image.
///
/// # Errors
///
/// Returns:
/// * [`StegoError::MissingHeader`] when the image does not contain enough bits
///   to recover the message length
/// * [`StegoError::UnreasonablePayloadSize`] when the payload size is too large
///   to fit in the image
/// * [`StegoError::DeclaredPayloadExceedsCapacity`] when the header is invalid
///   or the payload size is too large to fit in the image
/// * [`StegoError::IncompletePayload`] when the image data ends before the
///   payload could be fully reconstructed
/// * [`StegoError::PayloadLengthParseError`] when the length bits can't be
///   parsed into an integer
pub fn extract_data(image: &RgbImage) -> Result<Vec<u8>, StegoError>
{
    let available_bits = channel_capacity_bits(image)?;
    if available_bits < HEADER_BITS
    {
        return Err(StegoError::MissingHeader { available_bits });
    }

    let mut bit_iter = image
        .pixels()
        .flat_map(Pixel::channels)
        // just the lsb
        .map(|channel| channel & 1);

    let declared_bytes = {
        // Construct the length bits from the first HEADER_BITS bits
        let mut length_bits: u32 = 0;
        const {
            assert!(
                HEADER_BITS <= u32::BITS as _,
                "Header bit count must fit in a u32"
            );
        }

        for _ in 0..HEADER_BITS
        {
            let bit = bit_iter
                .next()
                .ok_or(StegoError::MissingHeader { available_bits })?;

            length_bits = (length_bits << 1) | u32::from(bit);
        }

        length_bits
            .try_into()
            .map_err(StegoError::PayloadLengthParseError)?
    };

    if declared_bytes > MAX_REASONABLE_MSG_SIZE
    {
        return Err(StegoError::UnreasonablePayloadSize { declared_bytes });
    }

    // Our data starts after the header, so we need to subtract the header
    let remaining_capacity_bytes = {
        let remaining_capacity_bits = available_bits - HEADER_BITS;
        remaining_capacity_bits / 8
    };

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
        let mut byte: u8 = 0;
        for _ in 0..u8::BITS
        {
            let bit = bit_iter
                .next()
                .ok_or(StegoError::IncompletePayload)?;
            byte = (byte << 1) | bit;
        }
        payload.push(byte);
    }

    Ok(payload)
}
