//! Crypto routines for the steganography tool.
mod chacha20;
mod cipher;

use std::path::Path;

pub use chacha20::{
    CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE, CHACHA20_TAG_SIZE, ChaCha20Cipher,
};
pub use cipher::Cipher;
use thiserror::Error;

/// Errors that can be emitted while performing cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError
{
    /// A hex string is invalid
    #[error("invalid {field} hex string: {source}")]
    InvalidHex
    {
        /// Name of the offending field
        field: Box<str>,
        /// Source hex error
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

    /// Reading key/nonce material from disk failed
    #[error("failed to read {field} file at {path}: {source}")]
    KeyMaterialIo
    {
        /// Name of the offending field
        field: Box<str>,
        /// Path to the file that could not be read
        path: Box<Path>,
        /// Source I/O error
        #[source]
        source: std::io::Error,
    },

    /// AEAD encryption failed
    #[error("encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed
    #[error("decryption failed")]
    DecryptionFailed,
}
