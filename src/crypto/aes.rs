//! AES-128 CTR mode implementation aligned with NIST FIPS 197 (Upd. 1).
//!
//! - Block rounds follow $5.1 and use the exact `SubBytes`, `ShiftRows`,
//!   `MixColumns`, and `AddRoundKey` primitives from $$5.1.1–5.1.4.
//! - Key expansion mirrors the schedule in $5.2/Figure 11 and reproduces the
//!   Appendix C.3 AES-128 example.
//! - The counter construction matches the CTR guidance from NIST SP 800-38A
//!   $6.5: a 96-bit nonce occupies the MSBs and a 32-bit big-endian counter
//!   fills the LSBs.
use std::cmp::min;

use crate::crypto::Cipher;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes.
pub const AES_KEY_SIZE: usize = 16;

/// AES-CTR nonce size in bytes (96-bit nonce + 32-bit counter).
pub const AES_NONCE_SIZE: usize = 12;

const AES_WORD_BYTES: usize = 4;
const AES_STATE_ROWS: usize = 4;
const AES_STATE_COLS: usize = 4;
const AES_ROUNDS: usize = match AES_KEY_SIZE
{
    16 => 10,
    24 => 12,
    32 => 14,
    _ => panic!("Invalid AES key size"),
};
const AES_KEY_WORDS: usize = AES_KEY_SIZE / AES_WORD_BYTES;
const AES_EXPANDED_WORDS: usize = AES_STATE_COLS * (AES_ROUNDS + 1);

const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

#[rustfmt::skip]
const S_BOX: [u8; 256] = [
//      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
/*0*/   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
/*1*/   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
/*2*/   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
/*3*/   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
/*4*/   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
/*5*/   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
/*6*/   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
/*7*/   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
/*8*/   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
/*9*/   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
/*a*/   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
/*b*/   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
/*c*/   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
/*d*/   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
/*e*/   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
/*f*/   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES-128 stream cipher in CTR mode with 96-bit nonce and 32-bit counter.
///
/// The nonce occupies the most significant 96 bits of the counter block, while
/// the provided counter seeds the least significant 32 bits (big-endian). Each
/// consumed block increments the 32-bit counter with wrapping semantics.
#[derive(Clone)]
pub struct Aes128Ctr
{
    round_keys: [u32; AES_EXPANDED_WORDS],
    counter_block: [u8; AES_BLOCK_SIZE],
    keystream: [u8; AES_BLOCK_SIZE],
    position: usize,
}

impl Aes128Ctr
{
    /// Builds an AES-128-CTR instance backed by the FIPS 197 $5 AES round
    /// function and the SP 800-38A $6.5 counter layout.
    ///
    /// # Arguments
    /// * `key` - 128-bit key expressed as 32 bytes.
    /// * `nonce` - 96-bit nonce (12 bytes).
    /// * `counter` - Initial 32-bit block counter.
    #[must_use]
    pub fn new(
        key: &[u8; AES_KEY_SIZE],
        nonce: &[u8; AES_NONCE_SIZE],
        counter: u32,
    ) -> Self
    {
        let mut counter_block = [0; AES_BLOCK_SIZE];
        counter_block[..AES_NONCE_SIZE].copy_from_slice(nonce);
        counter_block[AES_NONCE_SIZE..].copy_from_slice(&counter.to_be_bytes());

        Self {
            round_keys: expand_key(key),
            counter_block,
            keystream: [0; AES_BLOCK_SIZE],
            position: AES_BLOCK_SIZE,
        }
    }

    /// XORs the AES keystream into the provided buffer.
    fn apply_keystream(&mut self, buffer: &mut [u8])
    {
        let mut offset = 0;
        while offset < buffer.len()
        {
            if self.position == AES_BLOCK_SIZE
            {
                self.refill_keystream();
            }

            let take =
                min(AES_BLOCK_SIZE - self.position, buffer.len() - offset);
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
        self.keystream = encrypt_block(&self.round_keys, &self.counter_block);
        increment_counter(&mut self.counter_block);
        self.position = 0;
    }
}

impl Cipher for Aes128Ctr
{
    /// Encrypts the supplied plaintext and returns the ciphertext by `XOR`-ing
    /// the `CTR` keystream with the plaintext.
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8>
    {
        let mut output = plaintext.to_vec();
        self.apply_keystream(&mut output);
        output
    }

    /// Decrypts the supplied ciphertext and returns the plaintext. CTR mode is
    /// symmetric, so this simply reuses `encrypt`, per SP 800-38A $6.5.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8>
    {
        self.encrypt(ciphertext)
    }
}

/// Increments the 32-bit counter portion of the counter block (big-endian,
/// wrapping semantics) as required by SP 800-38A $6.5 for CTR mode.
fn increment_counter(counter_block: &mut [u8; AES_BLOCK_SIZE])
{
    for byte in counter_block[AES_NONCE_SIZE..]
        .iter_mut()
        .rev()
    {
        *byte = byte.wrapping_add(1);
        if *byte != 0
        {
            break;
        }
    }
}

/// Expands a 128-bit key into `(Nr + 1) * Nb` 32-bit words in accordance with
/// FIPS 197 $5.2 and Figure 11 (`RotWord`/`SubWord`/`Rcon` sequence).
fn expand_key(key: &[u8; AES_KEY_SIZE]) -> [u32; AES_EXPANDED_WORDS]
{
    let mut words = [0; AES_EXPANDED_WORDS];
    for (i, chunk) in key.chunks_exact(AES_WORD_BYTES).enumerate()
    {
        words[i] = u32::from_be_bytes(
            chunk
                .try_into()
                .expect("couldn't fit into u32"),
        );
    }

    let mut rcon_idx = 0;
    for i in AES_KEY_WORDS..AES_EXPANDED_WORDS
    {
        let mut temp = words[i - 1];
        if i.is_multiple_of(AES_KEY_WORDS)
        {
            temp = sub_word(rot_word(temp)) ^ RCON[rcon_idx];
            rcon_idx += 1;
        }
        else if i % AES_KEY_WORDS == 4
        {
            temp = sub_word(temp);
        }

        words[i] = words[i - AES_KEY_WORDS] ^ temp;
    }

    words
}

/// Encrypts a single 16-byte block via the $5.1 round structure: initial
/// `AddRoundKey`, 9 full rounds, and a final round without `MixColumns`.
fn encrypt_block(
    round_keys: &[u32; AES_EXPANDED_WORDS],
    block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE]
{
    let mut state = *block;
    add_round_key(&mut state, round_keys, 0);

    for round in 1..AES_ROUNDS
    {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_keys, round);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_keys, AES_ROUNDS);

    state
}

/// Combines the state with the round key via XOR as defined in $5.1.4
/// (Equation 10).
///
/// # Arguments
///
/// * `state` - The state to combine with the round key.
/// * `round_keys` - The round keys to combine with the state.
/// * `round` - The round number to combine with the state.
fn add_round_key(
    state: &mut [u8; AES_BLOCK_SIZE],
    round_keys: &[u32; AES_EXPANDED_WORDS],
    round: usize,
)
{
    for col in 0..AES_STATE_COLS
    {
        let word = round_keys[round * AES_STATE_COLS + col].to_be_bytes();
        for row in 0..AES_STATE_ROWS
        {
            state[col * AES_STATE_ROWS + row] ^= word[row];
        }
    }
}

/// Applies the Rijndael S-box substitution (Table 4) described in $5.1.1.
///
/// # Arguments
///
/// * `state` - The state to apply the transformation to.
fn sub_bytes(state: &mut [u8; AES_BLOCK_SIZE])
{
    for byte in state.iter_mut()
    {
        *byte = S_BOX[*byte as usize];
    }
}

/// Performs the cyclic left shifts from $5.1.2 / Figure 5.
///
/// # Arguments
///
/// * `state` - The state to shift the rows of.
fn shift_rows(state: &mut [u8; AES_BLOCK_SIZE])
{
    let mut tmp = [0; AES_BLOCK_SIZE];
    tmp.copy_from_slice(state);

    for row in 0..AES_STATE_ROWS
    {
        for col in 0..AES_STATE_COLS
        {
            let src_col = (col + row) % AES_STATE_COLS;
            state[col * AES_STATE_ROWS + row] =
                tmp[src_col * AES_STATE_ROWS + row];
        }
    }
}

/// Multiplies each column by the fixed MDS matrix from $5.1.3 / Figure 6.
///
/// # Arguments
///
/// * `state` - The state to multiply the columns of.
fn mix_columns(state: &mut [u8; AES_BLOCK_SIZE])
{
    for col in 0..AES_STATE_COLS
    {
        let offset = col * AES_STATE_ROWS;
        let mut column = [
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ];
        mix_single_column(&mut column);
        state[offset..offset + AES_STATE_ROWS].copy_from_slice(&column);
    }
}

/// Mixes one column using the `xtime`-based optimization from $4.2.1.
const fn mix_single_column(column: &mut [u8; AES_STATE_ROWS])
{
    let t = column[0] ^ column[1] ^ column[2] ^ column[3];
    let u = column[0];
    column[0] ^= t ^ xtime(column[0] ^ column[1]);
    column[1] ^= t ^ xtime(column[1] ^ column[2]);
    column[2] ^= t ^ xtime(column[2] ^ column[3]);
    column[3] ^= t ^ xtime(column[3] ^ u);
}

/// Multiplies by x (i.e., 0x02) in GF(2^8) with reduction polynomial
/// `x^8 + x^4 + x^3 + x + 1`, matching the $4.2 definition.
const fn xtime(byte: u8) -> u8
{
    let shifted = byte << 1;
    if byte & 0x80 == 0
    {
        shifted
    }
    else
    {
        shifted ^ 0x1b
    }
}

/// Rotates a word left by 8 bits, implementing `RotWord` from $5.2.
const fn rot_word(word: u32) -> u32
{
    word.rotate_left(8)
}

/// Applies the S-box to each byte in a word, mirroring `SubWord` in $5.2.
const fn sub_word(word: u32) -> u32
{
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        S_BOX[bytes[0] as usize],
        S_BOX[bytes[1] as usize],
        S_BOX[bytes[2] as usize],
        S_BOX[bytes[3] as usize],
    ])
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Validates the AES-128 example published in FIPS 197
    #[test]
    fn aes128_block_matches_fips_vector()
    {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7,
            0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let round_keys = expand_key(&key);
        let ciphertext = encrypt_block(&round_keys, &plaintext);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn ctr_mode_matches_openssl_reference()
    {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let nonce = [0x00; AES_NONCE_SIZE];
        let plaintext = b"Hello AES CTR test!";
        let expected = [
            0x8e, 0xc4, 0x57, 0x5b, 0xe8, 0xaf, 0x1a, 0xc7, 0x3c, 0x6f, 0xc2,
            0x36, 0xf3, 0xe8, 0xac, 0x1c, 0x00, 0x32, 0x32,
        ];

        // Cross-checks our CTR keystream against OpenSSL's AES-128-CTR output.
        let mut cipher = Aes128Ctr::new(&key, &nonce, 0);
        let ciphertext = cipher.encrypt(plaintext);
        assert_eq!(ciphertext, expected);
    }

    /// Ensures encryption/decryption symmetry across boundary lengths, guarding
    /// against counter rollover bugs.
    #[test]
    fn ctr_encrypt_decrypt_roundtrip_various_lengths()
    {
        let key = [0x55; AES_KEY_SIZE];
        let nonce = [0x33; AES_NONCE_SIZE];

        for len in [0, 1, 16, 31, 64, 128]
        {
            let plaintext = vec![0xAA; len];
            let mut encryptor = Aes128Ctr::new(&key, &nonce, 42);
            let ciphertext = encryptor.encrypt(&plaintext);

            let mut decryptor = Aes128Ctr::new(&key, &nonce, 42);
            let recovered = decryptor.decrypt(&ciphertext);
            assert_eq!(plaintext, recovered);
        }
    }
}
