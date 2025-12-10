//! CLI payload orchestration.
//!
//! Covers everything that turns user input into bytes suitable for
//! steganography operations, embedding back and forth:
//! * resolves CLI payload sources
//! * applies optional encryption
//! * converts between inline/file sources and raw payload bytes for the embed
//!   and extract paths.
use std::fs;

use super::encryption::EncryptionArgs;
use super::{AppError, EncodingArgs};
use crate::crypto::{ChaCha20Cipher, Cipher, CryptoError};

/// Resolves the payload to embed from the command line arguments.
///
/// # Errors
///
/// Returns [`AppError`] when reading the payload file, or when both text and
/// file are provided.
pub(super) fn resolve_message(
    args: &mut EncodingArgs,
) -> Result<Vec<u8>, AppError>
{
    match (args.text.take(), &args.payload_file)
    {
        // take the ownership of the text
        (Some(text), None) => Ok(text.into_bytes()),
        (None, Some(path)) => Ok(fs::read(path)?),
        // this shouldn't happen because of the mutually exclusive group
        (None, None) | (Some(_), Some(_)) => unreachable!(
            "mutually exclusive group should ensure that either text or \
             payload_file is provided"
        ),
    }
}

/// Tries to encrypt the message using the provided encryption arguments.
///
/// # Arguments
///
/// * `message` - The message to encrypt.
/// * `encryption` - The encryption arguments.
///
/// # Returns
///
/// The encrypted message bytes.
///
/// # Errors
///
/// Returns [`CryptoError`] when encrypting the message fails.
pub(super) fn try_encrypt_message(
    message: &[u8],
    encryption: &EncryptionArgs,
) -> Result<Vec<u8>, CryptoError>
{
    let context = encryption.context()?;
    let mut cipher = ChaCha20Cipher::new(&context.key, &context.nonce);
    encrypt_with_cipher(message, &mut cipher)
}

/// Tries to decrypt the message using the provided encryption arguments.
///
/// # Arguments
///
/// * `payload` - The encrypted message bytes.
/// * `encryption` - The encryption arguments.
///
/// # Returns
///
/// The decrypted message.
///
/// # Errors
///
/// Returns [`CryptoError`] when decrypting the message fails.
pub(super) fn try_decrypt_message(
    payload: &[u8],
    encryption: &EncryptionArgs,
) -> Result<Vec<u8>, CryptoError>
{
    let context = encryption.context()?;
    let mut cipher = ChaCha20Cipher::new(&context.key, &context.nonce);
    decrypt_with_cipher(payload, &mut cipher)
}

/// Encrypts a message using an arbitrary `Cipher` implementation.
///
/// This helper is independent of the concrete algorithm; callers are
/// responsible for constructing the appropriate cipher instance.
///
/// # Arguments
///
/// * `message` - The message to encrypt.
/// * `cipher` - The cipher to use.
///
/// # Returns
///
/// The encrypted message bytes.
fn encrypt_with_cipher<C: Cipher>(
    message: &[u8],
    cipher: &mut C,
) -> Result<Vec<u8>, CryptoError>
{
    cipher.encrypt(message)
}

/// Decrypts a message using an arbitrary `Cipher` implementation.
///
/// This helper is independent of the concrete algorithm; callers are
/// responsible for constructing the appropriate cipher instance.
///
/// # Arguments
///
/// * `payload` - The encrypted message bytes.
/// * `cipher` - The cipher to use.
///
/// # Returns
///
/// The decrypted message.
fn decrypt_with_cipher<C: Cipher>(
    ciphertext: &[u8],
    cipher: &mut C,
) -> Result<Vec<u8>, CryptoError>
{
    cipher.decrypt(ciphertext)
}

#[cfg(test)]
mod tests
{
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_via_cli_helpers()
    {
        let key_file = TempMaterial::from_bytes(
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let nonce_file = TempMaterial::from_bytes(b"000000000000004a00000000");

        let encryption = EncryptionArgs {
            key_file: key_file.boxed_path(),
            nonce_file: nonce_file.boxed_path(),
        };

        let plaintext = b"Hello encrypted world!";
        let encrypted = try_encrypt_message(plaintext, &encryption)
            .expect("encrypt failed");
        assert_ne!(plaintext.as_slice(), encrypted.as_slice());

        let decrypted = try_decrypt_message(&encrypted, &encryption)
            .expect("decrypt failed");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn encryption_args_are_optional()
    {
        let encryption: Option<EncryptionArgs> = None;
        let plaintext = b"No crypto involved.";

        let mut payload = plaintext.to_vec();
        if let Some(ref encryption) = encryption
        {
            payload = try_encrypt_message(&payload, encryption)
                .expect("encrypt failed");
        }
        assert_eq!(plaintext.as_slice(), payload.as_slice());

        if let Some(ref encryption) = encryption
        {
            payload = try_decrypt_message(&payload, encryption)
                .expect("decrypt failed");
        }
        assert_eq!(plaintext.as_slice(), payload.as_slice());
    }

    #[test]
    fn resolve_message_prefers_inline_text()
    {
        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output_file: Some(Path::new("output.png").into()),
            text: Some("payload".into()),
            payload_file: None,
            encryption: None,
        };

        let resolved = resolve_message(&mut args).expect("should resolve text");
        assert_eq!(resolved, b"payload");
    }

    #[test]
    fn resolve_message_reads_from_file()
    {
        let dir = TempDir::new().expect("failed to create tempdir");
        let text_path = dir.path().join("message.txt");
        fs::write(&text_path, "from file").expect("failed to write message");

        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output_file: Some(Path::new("output.png").into()),
            text: None,
            payload_file: Some(text_path.into_boxed_path()),
            encryption: None,
        };

        let resolved = resolve_message(&mut args).expect("should resolve file");
        assert_eq!(resolved, b"from file");
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
            fs::write(&path, bytes).expect("failed to write temp material");
            Self { path, _dir: dir }
        }

        fn boxed_path(&self) -> Box<Path>
        {
            self.path.clone().into_boxed_path()
        }
    }
}
