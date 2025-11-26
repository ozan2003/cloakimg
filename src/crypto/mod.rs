//! Crypto routines for the steganography tool.
mod aes;
mod cipher;

use std::path::PathBuf;

pub use aes::{AES_BLOCK_SIZE, AES_KEY_SIZE, AES_NONCE_SIZE, Aes128Ctr};
pub use cipher::Cipher;
use thiserror::Error;

/// Errors that can be emitted while performing cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError
{
    /// A hex string contained invalid characters
    #[error("invalid {field} hex string")]
    InvalidHex
    {
        /// Name of the offending field
        field: Box<str>,
        #[source]
        source: hex::FromHexError,
    },

    /// A parsed hex string has the wrong length
    #[error("{field} must be {expected} bytes but was {actual}")]
    InvalidLength
    {
        /// Name of the offending field
        field: Box<str>,
        /// Expected number of bytes
        expected: usize,
        /// Actual number of bytes
        actual: usize,
    },

    /// Encryption was requested without providing all required parameters
    #[error("missing encryption argument: {field}")]
    MissingEncryptionField
    {
        /// Name of the missing argument
        field: Box<str>,
    },

    /// Base64 decoding of the ciphertext payload failed
    #[error("ciphertext payload is not valid Base64")]
    InvalidBase64(#[from] base64::DecodeError),

    /// Decrypted plaintext contained invalid UTF-8 data
    #[error("decrypted payload is not valid UTF-8")]
    InvalidDecryptedUtf8(#[from] std::string::FromUtf8Error),

    /// Reading key/nonce material from disk failed
    #[error("failed to read {field} file at {path}: {source}")]
    KeyMaterialIo
    {
        /// Name of the offending field
        field: Box<str>,
        /// Path to the file that could not be read
        path: PathBuf,
        /// Source I/O error
        #[source]
        source: std::io::Error,
    },
}
