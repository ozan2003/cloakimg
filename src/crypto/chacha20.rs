//! `ChaCha20` stream cipher implementation as stated in RFC 7539.
use std::cmp::min;

use crate::crypto::Cipher;

/// Size of a `ChaCha20` key in bytes.
pub const KEY_SIZE: usize = 32;

/// Size of an IETF `ChaCha20` nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// `ChaCha20` block size in bytes.
const BLOCK_SIZE: usize = 64;

/// Number of words in a `ChaCha20` state.
const STATE_WORDS: usize = 16;

/// Defined in 2.3. The `ChaCha20` Block Function
const CONSTANTS: [u32; 4] =
    [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// `ChaCha20` stream cipher ready for incremental encryption.
///
/// The cipher keeps internal state that advances as keystream is consumed,
/// enabling callers to process arbitrarily sized buffers without manual block
/// management.
#[derive(Clone)]
pub struct ChaCha20
{
    base_state: [u32; STATE_WORDS],
    /// Block counter
    counter: u32,
    keystream: [u8; BLOCK_SIZE],
    position: usize,
}

impl ChaCha20
{
    /// Builds a new `ChaCha20` stream cipher.
    ///
    /// # Arguments
    /// * `key` - 256-bit key expressed as 32 bytes.
    /// * `nonce` - 96-bit nonce expressed as 12 bytes.
    /// * `counter` - Initial 32-bit block counter, usually zero or one.
    #[must_use]
    pub fn new(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        counter: u32,
    ) -> Self
    {
        let mut base_state = [0; STATE_WORDS];
        // the first 4 words are the constants
        base_state[..4].copy_from_slice(&CONSTANTS);
        // The next eight words (4-11) are taken from the 256-bit key by
        // reading the bytes in little-endian order, in 4-byte chunks.
        load_words(&mut base_state[4..=11], key);
        // Words 13-15 are a nonce, which should not be repeated for the same
        // key. The 13th word is the first 32 bits of the input nonce taken
        // as a little-endian integer, while the 15th word is the last 32
        // bits.
        load_words(&mut base_state[13..], nonce);

        Self {
            base_state,
            counter,
            keystream: [0; BLOCK_SIZE],
            position: BLOCK_SIZE,
        }
    }

    /// XORs the `ChaCha20` keystream into the provided buffer.
    ///
    /// # Arguments
    /// * `buffer` - Plaintext or ciphertext data to be transformed in place.
    fn apply_keystream(&mut self, buffer: &mut [u8])
    {
        let mut offset = 0;
        while offset < buffer.len()
        {
            if self.position == BLOCK_SIZE
            {
                self.refill_keystream();
            }

            let take = min(BLOCK_SIZE - self.position, buffer.len() - offset);
            for i in 0..take
            {
                buffer[offset + i] ^= self.keystream[self.position + i];
            }
            self.position += take;
            offset += take;
        }
    }

    fn refill_keystream(&mut self)
    {
        self.keystream = self.generate_block(self.counter);
        self.counter = self.counter.wrapping_add(1);
        self.position = 0;
    }

    fn generate_block(&self, counter: u32) -> [u8; BLOCK_SIZE]
    {
        let mut state = self.base_state;
        // word 12 is a block counter
        state[12] = counter;

        let mut working = state;

        // Chacha20 runs 20 rounds of quarter rounds, alternating between column
        // and diagonal rounds. 10 column rounds and 10 diagonal rounds.
        for _ in 0..10
        {
            // Column rounds
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);

            // Diagonal rounds
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        for i in 0..STATE_WORDS
        {
            working[i] = working[i].wrapping_add(state[i]);
        }

        serialize_block(&working)
    }
}

impl Cipher for ChaCha20
{
    #[allow(clippy::doc_markdown, reason = "XORed need not backticks")]
    /// Encrypts the supplied plaintext and returns the ciphertext.
    ///
    /// # Arguments
    /// * `plaintext` - Data that will be XORed with the `ChaCha20` keystream.
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8>
    {
        let mut output = plaintext.to_vec();
        self.apply_keystream(&mut output);
        output
    }

    /// Decrypts the supplied ciphertext and returns the plaintext.
    ///
    /// # Arguments
    /// * `ciphertext` - Data that was produced by `ChaCha20` encryption.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8>
    {
        // Decryption is done the same way as encryption
        self.encrypt(ciphertext)
    }
}

fn load_words(dst: &mut [u32], bytes: &[u8])
{
    for (word, chunk) in dst.iter_mut().zip(bytes.chunks_exact(4))
    {
        let mut tmp = [0; 4];
        tmp.copy_from_slice(chunk);
        *word = u32::from_le_bytes(tmp);
    }
}

/// The `ChaCha` block function transforms a `ChaCha` state by running multiple
/// quarter rounds
const fn quarter_round(
    state: &mut [u32; STATE_WORDS],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
)
{
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Sequence words one-by-one in little endian order.
fn serialize_block(words: &[u32; STATE_WORDS]) -> [u8; BLOCK_SIZE]
{
    let mut output = [0; BLOCK_SIZE];

    for (chunk, word) in (output.chunks_exact_mut(4)).zip(words)
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn generates_rfc8439_block_vector()
    {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
            0x00,
        ];

        let mut cipher = ChaCha20::new(&key, &nonce, 1);
        let mut buffer = [0; BLOCK_SIZE];
        cipher.apply_keystream(&mut buffer);

        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
            0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
            0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2,
            0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05,
            0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e,
            0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn matches_rfc8439_encryption_vector()
    {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
            0x00,
        ];

        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could \
            offer you only one tip for the future, sunscreen would be it.";

        let expected = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07,
            0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43,
            0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9,
            0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab,
            0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52,
            0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca,
            0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a,
            0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b,
            0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
            0x5e, 0x42, 0x87, 0x4d,
        ];

        let mut cipher = ChaCha20::new(&key, &nonce, 1);
        let ciphertext = cipher.encrypt(plaintext);

        assert_eq!(ciphertext, expected);

        let mut decipher = ChaCha20::new(&key, &nonce, 1);
        let recovered = decipher.decrypt(&ciphertext);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_random_lengths()
    {
        let key = [0x11; KEY_SIZE];
        let nonce = [0x22; NONCE_SIZE];

        for msg_len in [0, 1, 7, 64, 65, 128, 255]
        {
            let plaintext = vec![0x55; msg_len];
            let mut encryptor = ChaCha20::new(&key, &nonce, 0);
            let ciphertext = encryptor.encrypt(&plaintext);

            let mut decryptor = ChaCha20::new(&key, &nonce, 0);
            let recovered = decryptor.decrypt(&ciphertext);

            assert_eq!(plaintext, recovered);
        }
    }
}
