use image::RgbaImage;

use super::{HEADER_BITS, HEADER_MAX_VALUE, StegoError, channel_capacity_bits};

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
    if payload.len() > HEADER_MAX_VALUE
    {
        return Err(StegoError::MessageExceedsHeaderLimit {
            requested_bytes: payload.len(),
        });
    }

    let total_available_bits = channel_capacity_bits(image);
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

/// Iterator over the bits of the payload
#[derive(Default)]
struct PayloadBits<'message>
{
    message: &'message [u8],
    length: usize,
    length_bit_index: usize,
    byte_index: usize,
    bit_index: usize,
}

impl<'message> PayloadBits<'message>
{
    fn new(message: &'message [u8]) -> Self
    {
        Self {
            message,
            length: message.len(),
            ..Default::default()
        }
    }

    fn next_bit(&mut self) -> Option<u8>
    {
        if self.length_bit_index < HEADER_BITS
        {
            let shift = HEADER_BITS - 1 - self.length_bit_index;
            let bit = ((self.length >> shift) & 1)
                .try_into()
                .ok()?;

            self.length_bit_index += 1;
            return Some(bit);
        }

        if self.byte_index >= self.message.len()
        {
            return None;
        }

        let byte = self.message[self.byte_index];
        let shift = 7 - self.bit_index;
        let bit = (byte >> shift) & 1;

        self.bit_index += 1;
        if self.bit_index == 8
        {
            self.bit_index = 0;
            self.byte_index += 1;
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
