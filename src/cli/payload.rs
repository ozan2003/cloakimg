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
use crate::crypto::{
    AUTH_TAG_SIZE,
    ChaCha20Cipher,
    Cipher,
    CryptoError,
    NONCE_SIZE,
};
use crate::hash::{DEFAULT_DIGEST_LEN, hash};

/// Resolves the payload to embed from the command line arguments.
///
/// # Arguments
///
/// * `args` - The encoding arguments containing payload source.
///
/// # Errors
///
/// * [`AppError::Read`] when the payload file cannot be read
pub(super) fn resolve_message(
    args: &mut EncodingArgs,
) -> Result<Vec<u8>, AppError>
{
    match (args.text.take(), &args.payload_file)
    {
        // clap's ArgGroup guarantees at least one source, so the `(None, None)`
        // arm is defensive only.
        (Some(text), _) => Ok(text.into_bytes()),
        (None, Some(path)) =>
        {
            fs::read(path.as_ref()).map_err(|source| AppError::Read {
                path: path.as_ref().into(),
                source,
            })
        },
        (None, None) => Err(AppError::MissingMessage),
    }
}

/// Appends a hash of the message to the end of the message bytes.
///
/// The hash is used for integrity verification during extraction.
///
/// The output format is: `[N-byte message][``DEFAULT_DIGEST_LEN``-byte hash]`.
///
/// # Arguments
/// * `message` - The message bytes to which the hash will be appended.
///
/// # Returns
/// A new vector containing the original message followed by its hash digest.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "capacity math on in-memory buffers cannot overflow"
)]
pub(super) fn append_hash(message: &[u8]) -> Vec<u8>
{
    let mut output = Vec::with_capacity(message.len() + DEFAULT_DIGEST_LEN);
    output.extend_from_slice(message);
    output.extend_from_slice(&hash(message));
    output
}

/// Verifies the integrity of the payload by checking the appended hash and
/// returns the original message if the hash is valid.
///
/// The input format is expected to be: `[N-byte
/// message][``DEFAULT_DIGEST_LEN``-byte hash]`.
///
/// # Arguments
/// * `payload` - The payload bytes containing the message followed by its hash.
///
/// # Errors
/// * [`AppError::IntegrityPayloadTooShort`] if the payload is shorter than the
///   expected hash length.
/// * [`AppError::IntegrityCheckFailed`] if the computed hash does not match the
///   expected hash.
///
/// # Returns
/// A vector containing the original message bytes if the integrity check
/// passes.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "splitting an in-memory payload cannot overflow"
)]
pub(super) fn verify_and_strip_hash(payload: &[u8])
-> Result<Vec<u8>, AppError>
{
    if payload.len() < DEFAULT_DIGEST_LEN
    {
        return Err(AppError::IntegrityPayloadTooShort {
            needed_minimum: DEFAULT_DIGEST_LEN,
            actual: payload.len(),
        });
    }

    let (message, expected_hash) =
        payload.split_at(payload.len() - DEFAULT_DIGEST_LEN);

    let actual_hash = hash(message);
    if actual_hash.as_slice() != expected_hash
    {
        return Err(AppError::IntegrityCheckFailed);
    }

    Ok(message.to_vec())
}

/// Tries to encrypt the message using the provided encryption arguments.
///
/// Generates a fresh nonce for each encryption and embeds it at the start
/// of the payload: `[12-byte nonce][N-byte ciphertext][16-byte tag]`.
///
/// # Arguments
///
/// * `message` - The message to encrypt.
/// * `encryption` - The encryption arguments.
///
/// # Returns
///
/// The encrypted message bytes with embedded nonce.
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::AeadEncryptFailed`] when encrypting the message fails
#[expect(
    clippy::arithmetic_side_effects,
    reason = "sizing an in-memory output buffer cannot overflow"
)]
pub(super) fn try_encrypt_message(
    message: &[u8],
    encryption: &EncryptionArgs,
) -> Result<Vec<u8>, CryptoError>
{
    let context = encryption.context()?;

    // Generated every encryption session.
    let nonce = ChaCha20Cipher::generate_nonce();
    let mut cipher = ChaCha20Cipher::new(&context.key, &nonce);
    let mut ciphertext = encrypt_with_cipher(message, &mut cipher)?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce); // Prepend nonce as it is safe to do so.
    out.append(&mut ciphertext);
    Ok(out)
}

/// Tries to decrypt the message using the provided encryption arguments.
///
/// Expects the payload format: `[12-byte nonce][N-byte ciphertext][16-byte
/// tag]`. The nonce is extracted from the start of the payload.
///
/// # Arguments
///
/// * `payload` - The encrypted message bytes with embedded nonce.
/// * `encryption` - The encryption arguments.
///
/// # Returns
///
/// The decrypted message.
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::NonceExtractionFailed`] when the nonce cannot be extracted
/// * [`CryptoError::AeadDecryptFailed`] when decrypting the message fails
pub(super) fn try_decrypt_message(
    payload: &[u8],
    encryption: &EncryptionArgs,
) -> Result<Vec<u8>, CryptoError>
{
    {
        let minimum = NONCE_SIZE + AUTH_TAG_SIZE;
        if payload.len() < minimum
        {
            return Err(CryptoError::PayloadTooShort {
                needed_minimum: minimum,
                actual: payload.len(),
            });
        }
    }

    let context = encryption.context()?;
    let (nonce, ciphertext) = payload
        .split_first_chunk::<NONCE_SIZE>()
        .ok_or(CryptoError::NonceExtractionFailed)?;

    let mut cipher = ChaCha20Cipher::new(&context.key, nonce);
    decrypt_with_cipher(ciphertext, &mut cipher)
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
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::AeadEncryptFailed`] when encrypting the message fails
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
///
/// # Errors
///
/// Returns:
/// * [`CryptoError::AeadDecryptFailed`] when decrypting the message fails
fn decrypt_with_cipher<C: Cipher>(
    ciphertext: &[u8],
    cipher: &mut C,
) -> Result<Vec<u8>, CryptoError>
{
    cipher.decrypt(ciphertext)
}

#[cfg(test)]
#[expect(clippy::panic, reason = "test code isn't production code")]
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

        let encryption = EncryptionArgs {
            key_file: Some(key_file.boxed_path()),
        };

        let plaintext = b"Hello encrypted world!";
        let encrypted = try_encrypt_message(plaintext, &encryption)
            .expect("encrypt failed");
        assert_ne!(plaintext.as_slice(), encrypted.as_slice());

        // Verify the payload starts with a 12-byte nonce and has a 16-byte tag.
        assert!(encrypted.len() >= NONCE_SIZE + AUTH_TAG_SIZE);

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

    #[test]
    fn hash_roundtrip_and_validation()
    {
        let message = b"cloakimg message";
        let payload = append_hash(message);
        let restored =
            verify_and_strip_hash(&payload).expect("hash verification failed");
        assert_eq!(message.as_slice(), restored.as_slice());
    }

    #[test]
    fn hash_validation_fails_on_tamper()
    {
        let message = b"cloakimg message";
        let mut payload = append_hash(message);
        if let Some(last_byte) = payload.last_mut()
        {
            *last_byte ^= 0b0000_0001; // flip a bit
        }

        let err = verify_and_strip_hash(&payload)
            .expect_err("expected integrity error");

        match err
        {
            AppError::IntegrityCheckFailed =>
            {},
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn hash_validation_fails_on_short_payload()
    {
        let payload = vec![0; DEFAULT_DIGEST_LEN - 1];
        let err = verify_and_strip_hash(&payload)
            .expect_err("expected integrity error");

        match err
        {
            AppError::IntegrityPayloadTooShort { .. } =>
            {},
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
