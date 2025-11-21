//! Steganography routines for embedding and extracting text from PNG images.
//!
//! Provides functions for embedding and extracting text from PNG images using
//! RGB LSB steganography.
//!
//! # Format
//!
//! - First 32 LSBs: message length as big-endian u32
//! - Remaining LSBs: message bytes, each byte encoded MSB-first (bit 7 to bit
//!   0)
//! - Pixels are read left-to-right, top-to-bottom, RGB channels only (alpha
//!   ignored)
//!
//! # Errors
//!
//! Returns [`StegoError`] when embedding or extracting text fails.
use image::RgbaImage;
use thiserror::Error;

mod decode;
mod encode;

pub use decode::extract_text;
pub use encode::embed_text;

/// Bit length of the payload length header
const HEADER_BITS: usize = 32;
/// Maximum value representable by the payload length header
const PAYLOAD_MAX_LEN: usize = (1_usize << HEADER_BITS) - 1;

/// Maximum reasonable message size in bytes
// Messages exceeding this size are considered unreasonable
const MAX_REASONABLE_MESSAGE_SIZE: usize = 100 * 1024 * 1024; // 100 MiB

/// Errors that can be emitted while embedding or extracting text
#[derive(Debug, Error)]
pub enum StegoError
{
    /// The payload is too large to fit in the image
    #[error(
        "payload length of {requested_bytes} bytes exceeds available capacity \
         of {available_bytes} bytes"
    )]
    MessageTooLarge
    {
        requested_bytes: usize,
        available_bytes: usize,
    },

    /// The payload length is too large to fit in the header
    #[error(
        "payload length of {requested_bytes} bytes exceeds 32-bit header limit"
    )]
    MessageExceedsHeaderLimit
    {
        requested_bytes: usize
    },

    /// The image does not contain enough data to decode the payload header
    #[error("image does not contain enough data to decode the payload header")]
    MissingHeader
    {
        available_bits: usize
    },

    #[error(
        "declared payload of {declared_bytes} bytes exceeds available \
         capacity of {available_bytes} bytes"
    )]
    DeclaredPayloadExceedsCapacity
    {
        declared_bytes: usize,
        available_bytes: usize,
    },

    /// The payload size is too large to fit in the image
    #[error(
        "declared payload size of {declared_bytes} bytes exceeds reasonable \
         limit of {MAX_REASONABLE_MESSAGE_SIZE} bytes"
    )]
    UnreasonablePayloadSize
    {
        declared_bytes: usize
    },

    /// The image data ended before the payload could be fully reconstructed
    #[error("image data ended before the payload could be fully reconstructed")]
    IncompletePayload,

    /// The decoded payload is not valid UTF-8
    #[error("decoded payload is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

/// Returns the maximum message size (in bytes) that can be embedded in the
/// given image.
#[must_use]
pub fn max_message_size(image: &RgbaImage) -> usize
{
    let available_bits = channel_capacity_bits(image);
    (available_bits.saturating_sub(HEADER_BITS)) / 8
}

/// Returns the number of bits available in the image for the payload
fn channel_capacity_bits(image: &RgbaImage) -> usize
{
    // 3 bits per pixel (RGB)
    (image.width() as usize) * (image.height() as usize) * 3
}

#[cfg(test)]
mod tests
{
    use image::Rgba;

    use super::*;

    #[test]
    fn round_trip_text()
    {
        let mut image =
            RgbaImage::from_pixel(32, 32, Rgba([255, 255, 255, 255]));
        let message = "Secret message!";
        embed_text(&mut image, message).expect("failed to embed text");
        let decoded = extract_text(&image).expect("failed to extract text");
        assert_eq!(message, decoded);
    }

    #[test]
    fn round_trip_with_random_pixels()
    {
        let mut rng_data = vec![0u8; 64 * 64 * 4];

        #[allow(clippy::cast_possible_truncation)]
        for (i, byte) in rng_data.iter_mut().enumerate()
        {
            *byte = ((i.wrapping_mul(123) ^ 87) % 256) as u8;
        }
        let mut image = RgbaImage::from_raw(64, 64, rng_data)
            .expect("failed to create image from raw data");
        let message = "Test with random pixel data!";

        embed_text(&mut image, message).expect("failed to embed text");
        let decoded = extract_text(&image).expect("failed to extract text");
        assert_eq!(message, decoded);
    }

    #[test]
    fn empty_message()
    {
        let mut image =
            RgbaImage::from_pixel(32, 32, Rgba([128, 128, 128, 255]));
        embed_text(&mut image, "").expect("failed to embed text");
        let decoded = extract_text(&image).expect("failed to extract text");
        assert_eq!("", decoded);
    }

    #[test]
    fn unicode_message()
    {
        let mut image =
            RgbaImage::from_pixel(64, 64, Rgba([100, 100, 100, 255]));
        let message = "Hello 世界 🦀";
        embed_text(&mut image, message).expect("failed to embed unicode text");
        let decoded = extract_text(&image).expect("failed to extract text");
        assert_eq!(message, decoded);
    }

    #[test]
    fn max_capacity_message()
    {
        let mut image = RgbaImage::from_pixel(32, 32, Rgba([0, 0, 0, 255]));
        // 32*32*3 = 3072 bits - 32 header = 3040 bits = 380 bytes
        let max_len = max_message_size(&image);
        assert_eq!(max_len, 380);

        let message = "a".repeat(max_len);
        embed_text(&mut image, &message)
            .expect("failed to embed max capacity text");

        let decoded =
            extract_text(&image).expect("failed to extract max capacity text");

        assert_eq!(message, decoded);
    }

    #[test]
    fn rejects_large_payload()
    {
        let mut image = RgbaImage::from_pixel(4, 4, Rgba([0, 0, 0, 255]));
        let message = "This is going to be too big for a 4x4 image";
        let error = embed_text(&mut image, message)
            .expect_err("should reject large payload");

        assert!(matches!(error, StegoError::MessageTooLarge { .. }));
    }
}
