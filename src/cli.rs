//! Command line interface for the application.
//!
//! Provides an entry point for the application and handles the CLI arguments
//! as well as the encryption/decryption helpers and steganography routines.
use std::fs;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use clap::{ArgGroup, Args, Parser, Subcommand};
use image::codecs::bmp::BmpEncoder;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::codecs::pnm::{PnmEncoder, PnmSubtype, SampleEncoding};
use image::codecs::tiff::TiffEncoder;
use image::{ExtendedColorType, ImageEncoder, RgbImage};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{ChaCha20, Cipher, CryptoError, KEY_SIZE, NONCE_SIZE};
use crate::stego::{StegoError, embed_text, extract_text};

/// Parses CLI arguments and executes the requested operation.
///
/// # Errors
///
/// Returns [`AppError`] when reading or writing files, decoding images, or
/// running steganography routines fails.
pub fn run() -> Result<(), AppError>
{
    let cli = Cli::parse();
    match cli.command
    {
        Command::Encode(mut args) => handle_encode(&mut args),
        Command::Decode(args) => handle_decode(args),
    }
}

/// Errors that can be emitted while handling the CLI
#[derive(Debug, Error)]
pub enum AppError
{
    /// An I/O error occurred
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An image error occurred
    #[error(transparent)]
    Image(#[from] image::ImageError),

    /// A steganography error occurred
    #[error(transparent)]
    Stego(#[from] StegoError),

    /// The message is missing
    #[error("provide a message")]
    MissingMessage,

    /// The format is unsupported
    #[error("unsupported image format")]
    UnsupportedFormat,

    /// Input and output formats are different
    #[error(
        "input and output formats are different, both must be \
         {input_extension}"
    )]
    DifferentFormats
    {
        /// Extension detected on the input file
        input_extension: Box<str>,
        /// Extension detected on the output file
        output_extension: Box<str>,
    },

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The main CLI parser
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Encode and decode text with RGB LSB steganography for  files"
)]
struct Cli
{
    #[command(subcommand)]
    command: Command,
}

/// The main command
#[derive(Subcommand)]
enum Command
{
    Encode(EncodingArgs),
    Decode(DecodingArgs),
}

/// Arguments for the encoding
#[derive(Args)]
#[command(group(
    ArgGroup::new("message")
        .required(true)
        .args(["text", "text_file"])
))]
struct EncodingArgs
{
    /// Image that will receive the hidden text.
    input: Box<Path>,
    /// Destination path for the modified image.
    output: Box<Path>,
    /// Text to embed. Mutually exclusive with --text-file.
    #[arg(short = 'i', long = "input", value_name = "TEXT")]
    text: Option<String>,
    /// Path to a UTF-8 text file to embed.
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    text_file: Option<Box<Path>>,
    /// Optional encryption parameters.
    #[command(flatten)]
    encryption: Option<EncryptionArgs>,
}

/// Arguments for the decoding
#[derive(Args)]
struct DecodingArgs
{
    /// Image that contains hidden text.
    input: Box<Path>,
    /// Optional file to write the decoded text. Prints to stdout when omitted.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    output_text: Option<Box<Path>>,
    /// Optional encryption parameters.
    #[command(flatten)]
    encryption: Option<EncryptionArgs>,
}

/// `ChaCha20` encryption arguments shared by encode/decode commands.
#[derive(Args, Clone, Debug)]
struct EncryptionArgs
{
    /// File containing a raw (32-byte) or hex-encoded `ChaCha20` key.
    #[arg(long = "key-file", value_name = "PATH", requires = "nonce_file")]
    key_file: Box<Path>,
    /// File containing a raw (12-byte) or hex-encoded `ChaCha20` nonce.
    #[arg(long = "nonce-file", value_name = "PATH", requires = "key_file")]
    nonce_file: Box<Path>,
    /// Initial `ChaCha20` block counter. Defaults to zero.
    #[arg(
        long = "counter",
        value_name = "NUMBER",
        default_value_t = 0,
        requires_all = ["key_file", "nonce_file"]
    )]
    counter: u32,
}

impl EncryptionArgs
{
    fn config(&self) -> Result<EncryptionConfig, CryptoError>
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
struct EncryptionConfig
{
    key: [u8; KEY_SIZE],
    nonce: [u8; NONCE_SIZE],
    counter: u32,
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

/// Normalizes the extension of a path to lowercase.
fn normalized_extension<P: AsRef<Path>>(path: P) -> Option<String>
{
    path.as_ref()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

/// Handles the encoding of a message into an image.
///
/// # Errors
///
/// Returns [`AppError`] when reading or writing files, or encoding the image.
fn handle_encode(args: &mut EncodingArgs) -> Result<(), AppError>
{
    let input_ext = normalized_extension(&args.input);
    let output_ext = normalized_extension(&args.output);

    if input_ext != output_ext
    {
        return Err(AppError::DifferentFormats {
            input_extension: input_ext
                .as_deref()
                .unwrap_or("<unknown>")
                .into(),
            output_extension: output_ext
                .as_deref()
                .unwrap_or("<unknown>")
                .into(),
        });
    }

    let mut image = load_image(&args.input)?;
    let payload = {
        let mut payload = resolve_message(args)?;
        if let Some(encryption) = args.encryption.as_ref()
        {
            payload = try_encrypt_message(&payload, encryption)?;
        }
        payload
    };

    // Embedding the message happens here
    embed_text(&mut image, &payload)?;

    // Output the modified image to the specified path
    let mut file = fs::File::create(&args.output)?;

    match input_ext.as_deref()
    {
        Some("png") =>
        {
            let encoder = PngEncoder::new_with_quality(
                &mut file,
                CompressionType::Default,
                FilterType::Adaptive,
            );
            encoder.write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                ExtendedColorType::Rgb8,
            )?;
        },

        Some("bmp") =>
        {
            let mut encoder = BmpEncoder::new(&mut file);
            encoder.encode(
                image.as_raw(),
                image.width(),
                image.height(),
                ExtendedColorType::Rgb8,
            )?;
        },

        Some("tiff") =>
        {
            let encoder = TiffEncoder::new(&mut file);
            encoder.write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                ExtendedColorType::Rgb8,
            )?;
        },

        Some("ppm") =>
        {
            let mut encoder = PnmEncoder::with_subtype(
                PnmEncoder::new(&mut file),
                PnmSubtype::Pixmap(SampleEncoding::Binary),
            );
            encoder.encode(
                image.as_raw().as_slice(),
                image.width(),
                image.height(),
                ExtendedColorType::Rgb8,
            )?;
        },

        _ => return Err(AppError::UnsupportedFormat),
    }

    Ok(())
}

/// Handles the decoding of a message from an image.
///
/// # Errors
///
/// Returns [`AppError`] when reading or writing files, or decoding the image.
fn handle_decode(args: DecodingArgs) -> Result<(), AppError>
{
    let image = load_image(&args.input)?;
    // Extract the hidden message and decrypt it only when encryption flags were
    // provided.
    let message = {
        let mut message = extract_text(&image)?;
        if let Some(encryption) = args.encryption.as_ref()
        {
            message = try_decrypt_message(&message, encryption)?;
        }
        message
    };

    if let Some(path) = args.output_text
    {
        fs::write(path, message.as_bytes())?;
    }
    else
    {
        // Write the message to stdout if no file path is provided
        println!("{message}");
    }

    Ok(())
}

/// Loads an image from the specified path and converts it to an RGB buffer.
///
/// # Errors
///
/// Returns [`AppError`] when reading the file, or converting the image.
fn load_image<P: AsRef<Path>>(path: P) -> Result<RgbImage, AppError>
{
    Ok(image::open(path.as_ref())?.into_rgb8())
}

/// Resolves the message to embed from the command line arguments.
///
/// # Errors
///
/// Returns [`AppError`] when reading the text file, or when both text and text
/// file are provided.
fn resolve_message(args: &mut EncodingArgs) -> Result<String, AppError>
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
fn try_encrypt_message(
    message: &str,
    encryption: &EncryptionArgs,
) -> Result<String, CryptoError>
{
    // Currently this constructs a `ChaCha20` cipher
    let config = encryption.config()?;
    let mut cipher = ChaCha20::new(&config.key, &config.nonce, config.counter);
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
fn try_decrypt_message(
    payload: &str,
    encryption: &EncryptionArgs,
) -> Result<String, CryptoError>
{
    let config = encryption.config()?;
    let mut cipher = ChaCha20::new(&config.key, &config.nonce, config.counter);
    decrypt_with_cipher(payload, &mut cipher)
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
        fs::read(path).map_err(|source| CryptoError::KeyMaterialIo {
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
#[allow(
    unused_imports,
    reason = "when removed, it wont compile; most likely false positive"
)]
mod tests
{
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn should_reject_different_input_formats()
    {
        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output: Path::new("output.bmp").into(),
            text: Some("payload".into()),
            text_file: None,
            encryption: None,
        };

        let error = handle_encode(&mut args)
            .expect_err("should reject different input formats");

        assert!(matches!(
            error,
            AppError::DifferentFormats {
                input_extension,
                output_extension
            } if input_extension.as_ref() == "png"
                && output_extension.as_ref() == "bmp"
        ));
    }

    #[test]
    fn encrypt_decrypt_roundtrip_via_cli_helpers()
    {
        let key_file = TempMaterial::from_bytes(
            "key",
            b"000102030405060708090a0b0c0d0e0f\
              101112131415161718191a1b1c1d1e1f",
        );
        let nonce_file =
            TempMaterial::from_bytes("nonce", b"000000000000004a00000000");

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
    fn rejects_invalid_file_length()
    {
        let short_key = TempMaterial::from_bytes("short-key", &[0x00]);
        let valid_nonce = TempMaterial::from_bytes(
            "valid-nonce",
            b"000000000000004a00000000",
        );

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
        fn from_bytes(prefix: &str, bytes: &[u8]) -> Self
        {
            let dir = TempDir::new().expect("failed to create tempdir");
            let path = dir.path().join(format!("{prefix}.material"));
            fs::write(&path, bytes).expect("failed to write temp material");
            Self { path, _dir: dir }
        }

        fn boxed_path(&self) -> Box<Path>
        {
            self.path.clone().into_boxed_path()
        }
    }
}
