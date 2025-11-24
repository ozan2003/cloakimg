//! Provides a trait for cryptographic ciphers.
//!
//! All ciphers implemented must adhere to this trait.

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
    /// The ciphertext.
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8>;
    /// Decrypts the supplied ciphertext and returns the plaintext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Data that was produced by the cipher's encryption.
    ///
    /// # Returns
    ///
    /// The plaintext.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8>;
}
