//! Provides a trait for cryptographic ciphers.
//!
//! All ciphers implemented must adhere to this trait.
use super::CryptoError;

/// A trait for cryptographic ciphers for encryption/decryption.
pub trait Cipher
{
    /// Encrypts the supplied plaintext and returns the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data that will be encrypted accordingly to the cipher.
    ///
    /// # Returns
    ///
    /// `Ok(Vec<u8>)` containing the ciphertext on success
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [`CryptoError::EncryptionFailed`] when encryption fails
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypts the supplied ciphertext and returns the plaintext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Data that was produced by the cipher's encryption.
    ///
    /// # Returns
    ///
    /// `Ok(Vec<u8>)` containing the decrypted plaintext on success
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [`CryptoError::DecryptionFailed`] when decryption fails
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
