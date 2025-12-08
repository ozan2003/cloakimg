//! Steganography routines for embedding payload bytes into images.
//!
//! Provides a function for embedding arbitrary data into images using RGB LSB
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
use image::{Pixel, RgbImage};

use super::{HEADER_BITS, PAYLOAD_MAX_LEN, StegoError, channel_capacity_bits};

/// Embeds arbitrary bytes inside the RGB least-significant bits of the given
/// RGB image.
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
pub fn embed_data(
    image: &mut RgbImage,
    payload: &[u8],
) -> Result<(), StegoError>
{
    if payload.len() > PAYLOAD_MAX_LEN
    {
        return Err(StegoError::MessageExceedsHeaderLimit {
            requested_bytes: payload.len(),
        });
    }

    let total_available_bits = channel_capacity_bits(image)?;
    // HEADER_BITS is reserved for the payload length, the rest belongs to the
    // payload
    let payload_available_bytes =
        (total_available_bits.saturating_sub(HEADER_BITS)) / 8;
    // the total number of bits required for the length and the payload
    let total_required_bits = HEADER_BITS + payload.len() * 8;

    if total_required_bits > total_available_bits
    {
        return Err(StegoError::MessageTooLarge {
            requested_bytes: payload.len(),
            available_bytes: payload_available_bytes,
        });
    }

    let channels = image
        .pixels_mut()
        .flat_map(Pixel::channels_mut);

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
    msg_byte_len: usize,
    /// The index of the next bit in the length
    header_bit_index: usize,
    /// The index of the current byte across the message
    msg_byte_index: usize,
    /// The index of the current bit in the current byte
    curr_bit_index: u8,
}

impl<'message> PayloadBits<'message>
{
    fn new(message: &'message [u8]) -> Self
    {
        Self {
            message,
            msg_byte_len: message.len(),
            ..Default::default()
        }
    }

    fn next_bit(&mut self) -> Option<u8>
    {
        // encode the length
        if self.header_bit_index < HEADER_BITS
        {
            // lsb's index is 0
            let shift = (HEADER_BITS - 1) - self.header_bit_index;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "As we need only a single bit, we can shave off the \
                          excess zero bits"
            )]
            let bit = ((self.msg_byte_len >> shift) & 1) as _;

            self.header_bit_index += 1;
            return Some(bit);
        }

        if self.msg_byte_index >= self.message.len()
        {
            return None;
        }

        let byte = self.message[self.msg_byte_index];
        // lsb's index is 0
        #[allow(
            clippy::cast_possible_truncation,
            reason = "All integer bit lengths are less than u8::MAX"
        )]
        let shift_value = (u8::BITS as u8 - 1) - self.curr_bit_index;
        let bit = (byte >> shift_value) & 1;

        self.curr_bit_index += 1;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "All integer bit lengths are less than u8::MAX"
        )]
        if self.curr_bit_index == u8::BITS as _
        {
            // reset the bit index and move to the next byte
            self.curr_bit_index = 0;
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

    fn size_hint(&self) -> (usize, Option<usize>)
    {
        // The iterator will always yield at least HEADER_BITS bits
        (
            HEADER_BITS as _,
            self.msg_byte_len
                .checked_mul(8)
                .and_then(|l| l.checked_add(HEADER_BITS as _)),
        )
    }
}
