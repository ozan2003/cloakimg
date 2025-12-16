//! Wrapper over the `chacha20poly1305` AEAD.
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::{Cipher, CryptoError};

/// ChaCha20-Poly1305 key size in bytes.
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size in bytes.
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 authentication tag size in bytes.
pub const CHACHA20_TAG_SIZE: usize = 16;

/// A thin wrapper over the `chacha20poly1305` AEAD to satisfy the
/// [`Cipher`] trait.
#[derive(Clone)]
pub struct ChaCha20Cipher
{
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
}

impl ChaCha20Cipher
{
    /// Builds a new ChaCha20-Poly1305 instance from raw key/nonce bytes.
    #[must_use]
    pub fn new(
        key: &[u8; CHACHA20_KEY_SIZE],
        nonce: &[u8; CHACHA20_NONCE_SIZE],
    ) -> Self
    {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = *Nonce::from_slice(nonce);

        Self { cipher, nonce }
    }

    /// Generates a fresh nonce using the OS RNG.
    #[must_use]
    pub fn generate_nonce() -> [u8; CHACHA20_NONCE_SIZE]
    {
        ChaCha20Poly1305::generate_nonce(&mut OsRng).into()
    }
}

impl Cipher for ChaCha20Cipher
{
    /// Encrypts the supplied plaintext and returns ciphertext + tag.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [`CryptoError::AeadEncryptFailed`] when encryption fails
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>
    {
        self.cipher
            .encrypt(&self.nonce, plaintext)
            .map_err(|_| CryptoError::AeadEncryptFailed)
    }

    /// Decrypts and authenticates the supplied ciphertext.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [`CryptoError::AeadDecryptFailed`] when decryption fails
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>
    {
        self.cipher
            .decrypt(&self.nonce, ciphertext)
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }
}
