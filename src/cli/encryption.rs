//! CLI encryption plumbing.
//!
//! Defines the shared encryption flag group plus helpers that load and validate
//! key/nonce material.
use std::path::Path;

use clap::Args;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{CryptoError, KEY_SIZE, NONCE_SIZE};

/// `ChaCha20` encryption arguments shared by encode/decode commands.
#[derive(Args, Clone, Debug)]
pub(super) struct EncryptionArgs
{
    /// File containing a raw (32-byte) or hex-encoded `ChaCha20` key.
    #[arg(long = "key-file", value_name = "PATH", requires = "nonce_file")]
    pub(super) key_file: Box<Path>,
    /// File containing a raw (12-byte) or hex-encoded `ChaCha20` nonce.
    #[arg(long = "nonce-file", value_name = "PATH", requires = "key_file")]
    pub(super) nonce_file: Box<Path>,
    /// Initial `ChaCha20` block counter. Defaults to zero.
    #[arg(
        long = "counter",
        value_name = "NUMBER",
        default_value_t = 0,
        requires_all = ["key_file", "nonce_file"]
    )]
    pub(super) counter: u32,
}

impl EncryptionArgs
{
    pub(super) fn config(&self) -> Result<EncryptionConfig, CryptoError>
    {
        let key = parse_crypto_file::<KEY_SIZE>("--key-file", &self.key_file)?;
        let nonce =
            parse_crypto_file::<NONCE_SIZE>("--nonce-file", &self.nonce_file)?;

        Ok(EncryptionConfig {
            key,
            nonce,
            counter: self.counter,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct EncryptionConfig
{
    pub(super) key: [u8; KEY_SIZE],
    pub(super) nonce: [u8; NONCE_SIZE],
    pub(super) counter: u32,
}

// Don't leak the encryption configuration to the console
impl std::fmt::Debug for EncryptionConfig
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(
            f,
            "EncryptionConfig {{ key: [..], nonce: [..], counter: {} }}",
            self.counter
        )
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
/// Returns [`CryptoError`] when the hex string is not a valid or
/// when the hex string length is not equal to the expected length.
fn parse_hex_array<const N: usize>(
    field: &str,
    hex_value: &str,
) -> Result<[u8; N], CryptoError>
{
    let bytes =
        hex::decode(hex_value).map_err(|_| CryptoError::InvalidHex {
            field: field.into(),
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
/// Returns [`CryptoError`] when the file is not a valid hex string or
/// when the file length is not equal to the expected length.
fn parse_crypto_file<const N: usize>(
    field: &str,
    path: &Path,
) -> Result<[u8; N], CryptoError>
{
    let bytes =
        std::fs::read(path).map_err(|source| CryptoError::KeyMaterialIo {
            field: field.into(),
            path: path.to_path_buf(),
            source,
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
        let hex: String = ascii.split_whitespace().collect();
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
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
        let valid_nonce = TempMaterial::from_bytes(b"000000000000004a00000000");

        let encryption = EncryptionArgs {
            key_file: short_key.boxed_path(),
            nonce_file: valid_nonce.boxed_path(),
            counter: 0,
        };

        let error = encryption
            .config()
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
