//! CLI encryption plumbing.
//!
//! Defines the shared encryption flag group plus helpers that load and validate
//! key/nonce material.
use std::path::Path;

use clap::Args;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{CHACHA20_KEY_SIZE as KEY_SIZE, CryptoError};

/// Encryption arguments shared by encode/decode commands.
#[derive(Args)]
pub(super) struct EncryptionArgs
{
    /// File containing a raw (32-byte) or hex-encoded key.
    #[arg(long = "key-file", value_name = "PATH", required = false)]
    pub(super) key_file: Option<Box<Path>>,
}

impl EncryptionArgs
{
    /// Gets the encryption context.
    ///
    /// # Returns
    ///
    /// The encryption context.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * [`CryptoError::MissingEncryptionField`] when the key file is not
    ///   provided
    /// * [`CryptoError::InvalidHex`] when the key file is not a valid hex
    ///   string
    pub(super) fn context(&self) -> Result<EncryptionContext, CryptoError>
    {
        let key_path = self.key_file.as_ref().ok_or_else(|| {
            CryptoError::MissingEncryptionField {
                field: "--key-file".into(),
            }
        })?;

        let key = parse_crypto_file::<KEY_SIZE>("--key-file", key_path)?;
        Ok(EncryptionContext { key })
    }
}

/// Encryption context.
///
/// Encryption context contains the necessary information to perform encryption
/// and decryption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct EncryptionContext
{
    pub(super) key: [u8; KEY_SIZE],
}

// Don't leak the encryption context to the console
impl std::fmt::Debug for EncryptionContext
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        f.debug_struct("EncryptionContext")
            .field("key", &"[..]")
            .finish()
    }
}

/// Parses a hex string into a raw byte array.
///
/// # Arguments
///
/// * `field` - The field name.
/// * `hex_value` - The hex string.
///
/// # Returns
///
/// The raw byte array.
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::InvalidHex`] when the hex string is not a valid hex string
/// * [`CryptoError::InvalidLength`] when the hex string length is not equal to
///   the expected length
fn parse_hex_array<const N: usize>(
    field: &str,
    hex_value: &str,
) -> Result<[u8; N], CryptoError>
{
    let bytes =
        hex::decode(hex_value).map_err(|source| CryptoError::InvalidHex {
            field: field.into(),
            source,
        })?;

    if bytes.len() != N
    {
        return Err(CryptoError::InvalidLength {
            field: field.into(),
            expected: N,
            actual: bytes.len(),
        });
    }

    let mut array = [0; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Parses a crypto file into a byte array.
///
/// A crypto file is either a key or a nonce file.
///
/// # Arguments
///
/// * `field` - The field name.
/// * `path` - The path to the file.
///
/// # Returns
///
/// The byte array.
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::KeyMaterialIo`] when the file cannot be read
/// * [`CryptoError::InvalidLength`] when the file length is not equal to the
///   expected length
fn parse_crypto_file<const N: usize>(
    field: &str,
    path: impl AsRef<Path>,
) -> Result<[u8; N], CryptoError>
{
    let bytes = std::fs::read(path.as_ref()).map_err(|source| {
        CryptoError::KeyMaterialIo {
            field: field.into(),
            path: path.as_ref().into(),
            source,
        }
    })?;

    // Treat the bytes as binaty first.
    if bytes.len() == N
    {
        let mut array = [0; N];
        array.copy_from_slice(&bytes);
        return Ok(array);
    }

    // If the bytes are not a valid binary, try to parse them as a hex string.
    if let Ok(ascii) = std::str::from_utf8(&bytes)
    {
        let looks_textual = ascii
            .chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace());

        let hex: String = ascii.split_whitespace().collect();
        if looks_textual && !hex.is_empty()
        {
            return parse_hex_array(field, &hex);
        }
    }

    Err(CryptoError::InvalidLength {
        field: field.into(),
        expected: N,
        actual: bytes.len(),
    })
}

#[cfg(test)]
mod tests
{
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn rejects_invalid_file_length()
    {
        let short_key = TempMaterial::from_bytes(&[0x00]);

        let encryption = EncryptionArgs {
            key_file: Some(short_key.boxed_path()),
        };

        let error = encryption
            .context()
            .expect_err("expected invalid key length error");

        assert!(matches!(
            error,
            CryptoError::InvalidLength {
                field,
                expected: KEY_SIZE,
                actual: 1
            } if field.as_ref() == "--key-file"
        ));
    }

    #[test]
    fn rejects_non_hex_utf8_material()
    {
        let invalid_key = TempMaterial::from_bytes(b"not a valid hex string");

        let encryption = EncryptionArgs {
            key_file: Some(invalid_key.boxed_path()),
        };

        let error = encryption
            .context()
            .expect_err("expected invalid hex key error");

        assert!(matches!(
            error,
            CryptoError::InvalidHex { field, source: _ }
                if field.as_ref() == "--key-file"
        ));
    }

    struct TempMaterial
    {
        path: PathBuf,
        _dir: TempDir,
    }

    impl TempMaterial
    {
        fn from_bytes(bytes: &[u8]) -> Self
        {
            let dir = TempDir::new().expect("failed to create tempdir");
            let path = dir.path().join("material.bin");
            std::fs::write(&path, bytes)
                .expect("failed to write temp material");
            Self { path, _dir: dir }
        }

        fn boxed_path(&self) -> Box<Path>
        {
            self.path.clone().into_boxed_path()
        }
    }
}
