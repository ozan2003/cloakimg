//! Crypto routines for the steganography tool.
mod aes;
mod cipher;

use std::path::Path;

pub use aes::{AES_BLOCK_SIZE, AES_KEY_SIZE, AES_NONCE_SIZE, AesCtr};
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
}
