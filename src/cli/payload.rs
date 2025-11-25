//! CLI payload orchestration.
//!
//! Covers everything that turns user input into bytes suitable for
//! steganography operations, embedding back and forth:
//! * resolves CLI text sources
//! * applies optional encryption
//! * converts between UTF-8/plaintext and steganography-ready Base64 bytes for
//!   both encode and decode paths.
use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use super::encryption::EncryptionArgs;
use super::{AppError, EncodingArgs};
use crate::crypto::{ChaCha20, Cipher, CryptoError};

/// Resolves the message to embed from the command line arguments.
///
/// # Errors
///
/// Returns [`AppError`] when reading the text file, or when both text and text
/// file are provided.
pub(super) fn resolve_message(
    args: &mut EncodingArgs,
) -> Result<String, AppError>
{
    match (args.text.take(), &args.text_file)
    {
        // take the ownership of the text
        (Some(text), None) => Ok(text),
        (None, Some(path)) => Ok(fs::read_to_string(path)?),
        // this shouldn't happen because of the mutually exclusive group
        (None, None) | (Some(_), Some(_)) => Err(AppError::MissingMessage),
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
/// The Base64 encoded encrypted message.
///
/// # Errors
///
/// Returns [`CryptoError`] when encrypting the message fails.
pub(super) fn try_encrypt_message(
    message: &str,
    encryption: &EncryptionArgs,
) -> Result<String, CryptoError>
{
    // Currently this constructs a `ChaCha20` cipher
    let context = encryption.context()?;
    let mut cipher =
        ChaCha20::new(&context.key, &context.nonce, context.counter);
    Ok(encrypt_with_cipher(message, &mut cipher))
}

/// Tries to decrypt the message using the provided encryption arguments.
///
/// # Arguments
///
/// * `payload` - The Base64 encoded encrypted message.
/// * `encryption` - The encryption arguments.
///
/// # Returns
///
/// The decrypted message.
///
/// # Errors
///
/// Returns [`CryptoError`] when decoding the Base64 encoded message, or when
/// decrypting the message fails.
pub(super) fn try_decrypt_message(
    payload: &str,
    encryption: &EncryptionArgs,
) -> Result<String, CryptoError>
{
    let context = encryption.context()?;
    let mut cipher =
        ChaCha20::new(&context.key, &context.nonce, context.counter);
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
/// The Base64 encoded encrypted message.
fn encrypt_with_cipher<C: Cipher>(message: &str, cipher: &mut C) -> String
{
    let ciphertext = cipher.encrypt(message.as_bytes());
    // Encrypting the message gives us some garbled bytes that are not UTF-8
    // encoded, since the steganography layer works on valid UTF-8 encoded bytes
    // we need to encode it to Base64 to make it suitable for embedding.
    BASE64_STANDARD.encode(ciphertext)
}

/// Decrypts a message using an arbitrary `Cipher` implementation.
///
/// This helper is independent of the concrete algorithm; callers are
/// responsible for constructing the appropriate cipher instance.
///
/// # Arguments
///
/// * `payload` - The Base64 encoded encrypted message.
/// * `cipher` - The cipher to use.
///
/// # Returns
///
/// The decrypted message.
///
/// # Errors
///
/// Returns [`CryptoError`] when decoding the Base64 encoded message fails, or
/// when the decrypted payload is not valid UTF-8.
fn decrypt_with_cipher<C: Cipher>(
    payload: &str,
    cipher: &mut C,
) -> Result<String, CryptoError>
{
    // Remove the base64 encoding to get the ciphertext.
    let ciphertext = BASE64_STANDARD
        .decode(payload.as_bytes())
        .map_err(CryptoError::InvalidBase64)?;

    let plaintext = cipher.decrypt(&ciphertext);
    String::from_utf8(plaintext).map_err(CryptoError::InvalidDecryptedUtf8)
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
            b"000102030405060708090a0b0c0d0e0f\
              101112131415161718191a1b1c1d1e1f",
        );
        let nonce_file = TempMaterial::from_bytes(b"000000000000004a00000000");

        let encryption = EncryptionArgs {
            key_file: key_file.boxed_path(),
            nonce_file: nonce_file.boxed_path(),
            counter: 1,
        };

        let plaintext = "Hello encrypted world!";
        let encrypted = try_encrypt_message(plaintext, &encryption)
            .expect("encrypt failed");
        assert_ne!(plaintext, encrypted);

        let decrypted = try_decrypt_message(&encrypted, &encryption)
            .expect("decrypt failed");
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn encryption_args_are_optional()
    {
        let encryption: Option<EncryptionArgs> = None;
        let plaintext = "No crypto involved.";

        let mut payload = plaintext.to_owned();
        if let Some(ref encryption) = encryption
        {
            payload = try_encrypt_message(&payload, encryption)
                .expect("encrypt failed");
        }
        assert_eq!(plaintext, payload);

        if let Some(ref encryption) = encryption
        {
            payload = try_decrypt_message(&payload, encryption)
                .expect("decrypt failed");
        }
        assert_eq!(plaintext, payload);
    }

    #[test]
    fn resolve_message_prefers_inline_text()
    {
        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output: Path::new("output.png").into(),
            text: Some("payload".into()),
            text_file: None,
            encryption: None,
        };

        let resolved = resolve_message(&mut args).expect("should resolve text");
        assert_eq!(resolved, "payload");
    }

    #[test]
    fn resolve_message_reads_from_file()
    {
        let dir = TempDir::new().expect("failed to create tempdir");
        let text_path = dir.path().join("message.txt");
        fs::write(&text_path, "from file").expect("failed to write message");

        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output: Path::new("output.png").into(),
            text: None,
            text_file: Some(text_path.into_boxed_path()),
            encryption: None,
        };

        let resolved = resolve_message(&mut args).expect("should resolve file");
        assert_eq!(resolved, "from file");
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
