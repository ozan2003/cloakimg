//! Steganography routines for embedding and extracting payload bytes from
//! images.
//!
//! Provides functions for embedding and extracting arbitrary bytes from images
//! using RGB LSB steganography.
//!
//! # Encoding Format
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
mod decode;
mod encode;

pub use decode::extract_data;
pub use encode::embed_data;
use image::RgbImage;
use thiserror::Error;

/// Bit length of the payload length header
const HEADER_BITS: usize = 30;
const _: () = const {
    // I couldn't find a way w/o hardcoding the type
    assert!(
        HEADER_BITS <= usize::BITS as _,
        "Bit count must fit in a usize"
    );
};

/// Maximum value representable by the payload length header in bytes
const PAYLOAD_MAX_LEN: usize = (1 << HEADER_BITS) - 1;

/// Maximum reasonable message size in bytes
// Messages exceeding this size are considered unreasonable
pub const MAX_REASONABLE_MSG_SIZE: usize = 100 * 1024 * 1024; // 100 MiB

// The reasonable message size cannot be enforced if it exceeds the payload
// max length
const _: () = const {
    assert!(
        MAX_REASONABLE_MSG_SIZE <= PAYLOAD_MAX_LEN,
        "Max reasonable message size is impossible to violate if it exceeds \
         the payload max length"
    );
};

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
         limit of {MAX_REASONABLE_MSG_SIZE} bytes"
    )]
    UnreasonablePayloadSize
    {
        declared_bytes: usize
    },

    /// The image data ended before the payload could be fully reconstructed
    #[error("image data ended before the payload could be fully reconstructed")]
    IncompletePayload,

    /// The payload length is too large to fit in a to an int
    #[error(transparent)]
    PayloadLengthParseError(#[from] std::num::TryFromIntError),

    /// The image dimensions overflow the supported channel capacity
    #[error(
        "image dimensions of {width}x{height} pixels exceed supported capacity"
    )]
    ImageCapacityOverflow
    {
        width: u32, height: u32
    },
}

/// Returns the maximum message size (in bytes) that can be embedded in the
/// given image.
///
/// # Errors
///
/// Returns [`StegoError::ImageCapacityOverflow`] when the image dimensions are
/// large enough to overflow the available channel count.
pub fn max_message_size(image: &RgbImage) -> Result<usize, StegoError>
{
    let available_bits = channel_capacity_bits(image)?;
    Ok((available_bits.saturating_sub(HEADER_BITS)) / 8)
}

/// Returns the number of bits available in the image for the payload
fn channel_capacity_bits(image: &RgbImage) -> Result<usize, StegoError>
{
    capacity_bits_for_dimensions(image.width(), image.height())
}

/// Computes the total number of LSB carrier bits for an image of the given
/// dimensions.
///
/// # Errors
///
/// Returns [`StegoError::ImageCapacityOverflow`] when the width/height
/// pair would overflow the RGB channel count.
// This function exists for testing purposes to avoid creating a new image
// object.
fn capacity_bits_for_dimensions(
    width: u32,
    height: u32,
) -> Result<usize, StegoError>
{
    (width as usize)
        .checked_mul(height as usize)
        // 3 bits per pixel (RGB)
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or(StegoError::ImageCapacityOverflow { width, height })
}

#[cfg(test)]
mod tests
{
    use image::Rgb;
    use rand::fill;

    use super::*;

    const ROUND_TRIP_FIXTURES: [&str; 6] = [
        "data/basi3p02.png",
        "data/png-example-file-download-2048x2048.png",
        "data/tp0n3p08.png",
        "data/Lenna_original.bmp",
        "data/coffee.tif",
        "data/sample_640x426.ppm",
    ];

    const OVERSIZE_FIXTURES: [&str; 4] = [
        "data/basi3p02.png",
        "data/Lenna_original.bmp",
        "data/coffee.tif",
        "data/sample_640x426.ppm",
    ];

    fn load_fixture_rgb(path: &str) -> RgbImage
    {
        image::open(path)
            .unwrap_or_else(|err| {
                panic!("failed to open fixture {path}: {err}")
            })
            .into_rgb8()
    }

    #[test]
    fn round_trip_text()
    {
        let mut image = RgbImage::from_pixel(32, 32, Rgb([255, 255, 255]));
        let message = b"Secret message!";
        embed_data(&mut image, message).expect("failed to embed text");
        let decoded = extract_data(&image).expect("failed to extract text");
        assert_eq!(message, decoded.as_slice());
    }

    #[test]
    fn round_trip_image()
    {
        let mut image = RgbImage::from_pixel(32, 32, Rgb([255, 255, 255]));
        // An image instead of text
        let payload = RgbImage::from_pixel(10, 10, Rgb([45, 45, 45]));
        embed_data(&mut image, &payload).expect("failed to embed image");
        let decoded = extract_data(&image).expect("failed to extract image");
        assert_eq!(payload.into_raw(), decoded);
    }

    #[test]
    fn round_trip_with_random_pixels()
    {
        const WIDTH: u32 = 64;
        const HEIGHT: u32 = 64;

        let mut rng_data = vec![0; WIDTH as usize * HEIGHT as usize * 3];
        fill(rng_data.as_mut_slice());

        let mut image = RgbImage::from_raw(WIDTH, HEIGHT, rng_data)
            .expect("failed to create image from raw data");
        let message = b"Test with random pixel data!";

        embed_data(&mut image, message).expect("failed to embed text");
        let decoded = extract_data(&image).expect("failed to extract text");
        assert_eq!(message, decoded.as_slice());
    }

    #[test]
    fn empty_message()
    {
        let mut image = RgbImage::from_pixel(32, 32, Rgb([128, 128, 128]));
        embed_data(&mut image, b"").expect("failed to embed text");
        let decoded = extract_data(&image).expect("failed to extract text");
        assert_eq!(b"", decoded.as_slice());
    }

    #[test]
    fn unicode_message()
    {
        let mut image = RgbImage::from_pixel(64, 64, Rgb([100, 100, 100]));
        let message = "Hello 世界 🦀";
        embed_data(&mut image, message.as_bytes())
            .expect("failed to embed unicode text");
        let decoded = extract_data(&image).expect("failed to extract text");
        assert_eq!(message.as_bytes(), decoded.as_slice());
    }

    #[test]
    fn max_capacity_message()
    {
        let mut image = RgbImage::from_pixel(32, 32, Rgb([0, 0, 0]));

        let max_len =
            max_message_size(&image).expect("failed to compute capacity");
        let capacity_bits =
            capacity_bits_for_dimensions(image.width(), image.height())
                .expect("failed to compute channel capacity");

        let expected_bytes = (capacity_bits.saturating_sub(HEADER_BITS)) / 8;
        assert_eq!(max_len, expected_bytes);

        let message = vec![b'a'; max_len];
        embed_data(&mut image, &message)
            .expect("failed to embed max capacity text");

        let decoded =
            extract_data(&image).expect("failed to extract max capacity text");

        assert_eq!(message, decoded);
    }

    #[test]
    fn rejects_large_payload()
    {
        let mut image = RgbImage::from_pixel(4, 4, Rgb([0, 0, 0]));
        let message = b"This is going to be too big for a 4x4 image";
        let error = embed_data(&mut image, message)
            .expect_err("should reject large payload");

        assert!(matches!(error, StegoError::MessageTooLarge { .. }));
    }

    #[test]
    fn round_trip_real_world_fixtures()
    {
        for path in ROUND_TRIP_FIXTURES
        {
            let mut rgb_image = load_fixture_rgb(path);
            let message = format!("Round trip validation for {path}");

            let capacity = max_message_size(&rgb_image)
                .expect("failed to compute capacity");
            assert!(
                capacity >= message.len(),
                "fixture {path} cannot store the test payload (capacity \
                 {capacity})"
            );

            embed_data(&mut rgb_image, message.as_bytes()).unwrap_or_else(
                |err| panic!("failed to embed using {path}: {err}"),
            );

            let decoded = extract_data(&rgb_image).unwrap_or_else(|err| {
                panic!("failed to extract using {path}: {err}")
            });
            assert_eq!(
                message.as_bytes(),
                decoded.as_slice(),
                "round trip failed for {path}"
            );
        }
    }

    #[test]
    fn fixtures_reject_oversized_payloads()
    {
        for path in OVERSIZE_FIXTURES
        {
            let mut rgb_image = load_fixture_rgb(path);
            let capacity = max_message_size(&rgb_image)
                .expect("failed to compute capacity");
            let oversized_len = capacity
                .checked_add(1)
                .expect("fixture capacity near usize::MAX");
            let message = vec![b'x'; oversized_len];

            let error = embed_data(&mut rgb_image, &message)
                .expect_err("over-capacity payload should be rejected");

            match error
            {
                StegoError::MessageTooLarge {
                    requested_bytes,
                    available_bytes,
                } =>
                {
                    assert_eq!(
                        requested_bytes, oversized_len,
                        "unexpected requested bytes for {path}"
                    );
                    assert_eq!(
                        available_bytes, capacity,
                        "unexpected available bytes for {path}"
                    );
                },
                other => panic!("unexpected error for {path}: {other:?}"),
            }
        }
    }

    #[test]
    fn capacity_bits_detects_overflow()
    {
        let error = capacity_bits_for_dimensions(u32::MAX, u32::MAX)
            .expect_err("overflow should be reported");
        assert!(matches!(
            error,
            StegoError::ImageCapacityOverflow { width, height }
            if width == u32::MAX && height == u32::MAX
        ));
    }

    #[test]
    fn capacity_bits_handles_reasonable_dimensions()
    {
        let bits = capacity_bits_for_dimensions(64, 32)
            .expect("capacity calculation should succeed");
        assert_eq!(bits, 64 * 32 * 3);
    }
}
