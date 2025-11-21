//! Steganography routines for embedding text into PNG images.
//!
//! Provides a function for embedding text into PNG images using RGB LSB
//! steganography.
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
//! Returns [`StegoError`] when embedding text fails.
use image::RgbaImage;

use super::{HEADER_BITS, PAYLOAD_MAX_LEN, StegoError, channel_capacity_bits};

/// Embeds UTF-8 text inside the RGB least-significant bits of the given RGBA
/// image.
///
/// # Format
///
/// - First 32 LSBs: message length as big-endian u32
/// - Remaining LSBs: message bytes, each byte encoded MSB-first (bit 7 to bit
///   0)
/// - Pixels are read left-to-right, top-to-bottom, RGB channels only (alpha
///   ignored)
///
/// # Errors
///
/// Returns [`StegoError::MessageExceedsHeaderLimit`] when the payload cannot
/// fit in the 32-bit length header or [`StegoError::MessageTooLarge`] when the
/// host image lacks sufficient RGB channels.
pub fn embed_text(
    image: &mut RgbaImage,
    message: &str,
) -> Result<(), StegoError>
{
    let payload = message.as_bytes();
    if payload.len() > PAYLOAD_MAX_LEN
    {
        return Err(StegoError::MessageExceedsHeaderLimit {
            requested_bytes: payload.len(),
        });
    }

    let total_available_bits = channel_capacity_bits(image);
    // HEADER_BITS is reserved for the payload length, the rest belongs to the
    // payload
    let payload_available_bytes =
        (total_available_bits.saturating_sub(HEADER_BITS.into())) / 8;
    // the total number of bits required for the length and the payload
    let total_required_bits = usize::from(HEADER_BITS) + payload.len() * 8;

    if total_required_bits > total_available_bits
    {
        return Err(StegoError::MessageTooLarge {
            requested_bytes: payload.len(),
            available_bytes: payload_available_bytes,
        });
    }

    let channels = image
        .pixels_mut()
        // ignore alpha channel
        .flat_map(|pixel| pixel.0[..3].iter_mut());
    let bits = PayloadBits::new(payload);

    for (channel, bit) in channels.zip(bits)
    {
        // set the least significant bit of the channel to the bit of the
        // payload
        *channel = (*channel & 0xFE) | bit;
    }

    Ok(())
}

/// Iterator over the bits of the payload, encoding the message length first
#[derive(Default)]
struct PayloadBits<'message>
{
    /// The message to embed
    message: &'message [u8],
    /// The length of the message
    msg_length: usize,
    /// The index of the next bit in the length
    msg_length_bit_index: u8,
    /// The index of the next byte across the message
    msg_byte_index: usize,
    /// The index of the next bit in the current byte
    bit_index: u8,
}

impl<'message> PayloadBits<'message>
{
    fn new(message: &'message [u8]) -> Self
    {
        Self {
            message,
            msg_length: message.len(),
            ..Default::default()
        }
    }

    fn next_bit(&mut self) -> Option<u8>
    {
        // encode the length
        if self.msg_length_bit_index < HEADER_BITS
        {
            let shift = HEADER_BITS - 1 - self.msg_length_bit_index;
            let bit = ((self.msg_length >> shift) & 1)
                .try_into()
                .ok()?;

            self.msg_length_bit_index += 1;
            return Some(bit);
        }

        if self.msg_byte_index >= self.message.len()
        {
            return None;
        }

        let byte = self.message[self.msg_byte_index];
        let shift = 7 - self.bit_index;
        let bit = (byte >> shift) & 1;

        self.bit_index += 1;
        if self.bit_index == 8
        {
            // reset the bit index and move to the next byte
            self.bit_index = 0;
            self.msg_byte_index += 1;
        }

        Some(bit)
    }
}

impl Iterator for PayloadBits<'_>
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item>
    {
        self.next_bit()
    }
}
