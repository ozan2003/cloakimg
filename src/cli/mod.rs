//! Command line interface for the application.
//!
//! Provides an entry point for the application and handles the CLI arguments.
mod encryption;
mod image_io;
mod payload;

use std::fs;
use std::path::{Path, PathBuf};

use clap::{ArgGroup, Args, Parser, Subcommand};
use const_format::formatcp;
use thiserror::Error;

use self::encryption::EncryptionArgs;
use self::image_io::{load_image, normalized_extension, write_image};
use self::payload::{
    resolve_message, try_decrypt_message, try_encrypt_message,
};
use crate::crypto::CryptoError;
use crate::stego::{
    MAX_REASONABLE_MSG_SIZE, StegoError, embed_data, extract_data,
    max_message_size,
};

/// Errors that can be emitted while handling the CLI
#[derive(Debug, Error)]
pub enum AppError
{
    /// Failed to read a file from disk
    #[error("failed to read {path}: {source}")]
    Read
    {
        path: Box<Path>,
        #[source]
        source: std::io::Error,
    },

    /// Failed to write a file to disk
    #[error("failed to write {path}: {source}")]
    Write
    {
        path: Box<Path>,
        #[source]
        source: std::io::Error,
    },

    /// Failed to decode an input image
    #[error("failed to decode image {path}: {source}")]
    ImageOpen
    {
        path: Box<Path>,
        #[source]
        source: image::ImageError,
    },

    /// Failed to encode an output image
    #[error("failed to encode image {path} as {target_format}: {source}")]
    ImageEncode
    {
        path: Box<Path>,
        target_format: Box<str>,
        #[source]
        source: image::ImageError,
    },

    /// A steganography error occurred
    #[error(transparent)]
    Stego(#[from] StegoError),

    /// The message is missing
    #[error("provide a message")]
    MissingMessage,

    /// The format is unsupported
    #[error("unsupported image format {extension}")]
    UnsupportedFormat
    {
        /// Detected extension
        extension: Box<str>,
    },

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

    /// Something went wrong with the crypto operations
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The main CLI parser
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Encode and decode data into images using RGB LSB steganography",
    after_help = formatcp!(
        "Maximum supported payload size is {} MiB",
        MAX_REASONABLE_MSG_SIZE / (1024 * 1024)
    )
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
    Cap(CapacityArgs),
}

/// Embed data into an image.
#[derive(Args)]
#[command(group(
    ArgGroup::new("message")
        .required(true)
        .args(["text", "payload_file"])
))]
struct EncodingArgs
{
    /// Image that will receive the payload.
    input: Box<Path>,
    /// Optional output path for the embedded image. Defaults to `a.<ext>` when
    /// omitted.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output_file: Option<Box<Path>>,
    /// Payload to embed.
    #[arg(short = 't', long = "text", value_name = "TEXT")]
    text: Option<String>,
    /// Path to a payload file to embed.
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    payload_file: Option<Box<Path>>,
    /// Optional encryption parameters.
    #[command(flatten)]
    encryption: Option<EncryptionArgs>,
}

/// Extract data from an image.
#[derive(Args)]
struct DecodingArgs
{
    /// Image that contains the embedded data.
    input: Box<Path>,
    /// Optional file to write the extracted data. Prints to stdout when
    /// omitted.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    output_file: Option<Box<Path>>,
    /// Optional encryption parameters.
    #[command(flatten)]
    encryption: Option<EncryptionArgs>,
}

/// Calculate the maximum possible payload size for an image.
#[derive(Args)]
struct CapacityArgs
{
    /// Image to calculate the possible payload size for.
    input: Box<Path>,
}

/// Parses CLI arguments and executes the requested operation.
///
/// # Errors
///
/// Returns:
/// * [`AppError::DifferentFormats`] when the input and output formats are
///   different.
/// * [`AppError::Write`] when the output file cannot be written
/// * [`AppError::Read`] when the input file cannot be read
/// * [`AppError::ImageOpen`] when the input image cannot be loaded
/// * [`StegoError::ImageCapacityOverflow`] when the image dimensions are large
///   enough to overflow the available channel count.
pub fn run() -> Result<(), AppError>
{
    let cli = Cli::parse();
    match cli.command
    {
        Command::Encode(mut args) => handle_encode(&mut args),
        Command::Decode(args) => handle_decode(args),
        Command::Cap(args) => handle_capacity(&args),
    }
}

/// Handles the encoding of a message into an image.
///
/// # Errors
///
/// Returns:
/// * [`AppError::DifferentFormats`] when the input and output formats are
///   different.
fn handle_encode(args: &mut EncodingArgs) -> Result<(), AppError>
{
    let input_ext = normalized_extension(&args.input);
    let output_path = resolve_output_path(args, input_ext.as_deref());

    {
        let output_ext = normalized_extension(&output_path);
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
    embed_data(&mut image, &payload)?;

    write_image(&image, input_ext.as_deref(), &output_path)
}

/// Resolves a default output path for the embedded image.
///
/// The default path is `a.<ext>`, where `<ext>` matches the input's extension.
///
/// # Arguments
///
/// * `args` - The encoding arguments.
/// * `input_ext` - The extension of the input image.
///
/// # Returns
///
/// The copy of the resolved path if provided, otherwise the default path.
fn resolve_output_path(args: &EncodingArgs, input_ext: Option<&str>)
-> PathBuf
{
    const DEFAULT_OUTPUT_NAME: &str = "a";

    // If provided, use it.
    if let Some(path) = args.output_file.as_deref()
    {
        return PathBuf::from(path);
    }

    let mut default_path = PathBuf::from(DEFAULT_OUTPUT_NAME);
    if let Some(extension) = input_ext
    {
        default_path.set_extension(extension);
    }

    default_path
}

/// Handles the decoding of a message from an image.
///
/// # Errors
///
/// Returns:
/// * [`AppError::Write`] when the output file cannot be written
fn handle_decode(args: DecodingArgs) -> Result<(), AppError>
{
    let image = load_image(&args.input)?;
    // Extract the hidden message and decrypt it only when encryption flags were
    // provided.
    let message = {
        let mut message = extract_data(&image)?;
        if let Some(encryption) = args.encryption.as_ref()
        {
            message = try_decrypt_message(&message, encryption)?;
        }
        message
    };

    if let Some(path) = args.output_file
    {
        fs::write(path.as_ref(), &message).map_err(|source| {
            AppError::Write {
                path: path.as_ref().into(),
                source,
            }
        })?;
    }
    else
    {
        // Write the message to stdout if no file path is provided.
        // We fall back to lossy UTF-8 to avoid panicking on arbitrary payload
        // bytes.
        println!("{}", String::from_utf8_lossy(&message));
    }

    Ok(())
}

/// Handles the capacity calculation of a message for an image.
///
/// # Errors
///
/// Returns:
/// * [`AppError::Read`] when the input file cannot be read
/// * [`AppError::ImageOpen`] when the input image cannot be loaded
/// * [`StegoError::ImageCapacityOverflow`] when the image dimensions are large
///   enough to overflow the available channel count.
fn handle_capacity(args: &CapacityArgs) -> Result<(), AppError>
{
    let image = load_image(&args.input)?;
    let capacity = max_message_size(&image)?;
    println!("Maximum possible payload size: {} bytes", capacity);
    if capacity > MAX_REASONABLE_MSG_SIZE
    {
        println!(
            "Warning: payload size will be capped at the maximum supported \
             size of {} MiB",
            MAX_REASONABLE_MSG_SIZE / (1024 * 1024)
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests
{
    use std::fmt::{Debug, Formatter, Result};
    use std::path::Path;

    use clap::{CommandFactory, Parser};

    use super::*;
    use crate::crypto::{CHACHA20_NONCE_SIZE, CHACHA20_TAG_SIZE};

    // Debug impls are only needed in tests
    impl Debug for Cli
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("Cli")
                .field("command", &self.command)
                .finish()
        }
    }

    impl Debug for Command
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            match self
            {
                Self::Encode(args) => f
                    .debug_tuple("Command::Encode")
                    .field(args)
                    .finish(),
                Self::Decode(args) => f
                    .debug_tuple("Command::Decode")
                    .field(args)
                    .finish(),
                Self::Cap(args) => f
                    .debug_tuple("Command::Cap")
                    .field(args)
                    .finish(),
            }
        }
    }

    impl Debug for EncryptionArgs
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("EncryptionArgs")
                .field("key_file", &self.key_file)
                .finish()
        }
    }

    impl Debug for EncodingArgs
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("EncodingArgs")
                .field("input", &self.input)
                .field("output", &self.output_file)
                .field("text", &self.text)
                .field("payload_file", &self.payload_file)
                .field("encryption", &self.encryption)
                .finish()
        }
    }

    impl Debug for DecodingArgs
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("DecodingArgs")
                .field("input", &self.input)
                .field("output_data", &self.output_file)
                .field("encryption", &self.encryption)
                .finish()
        }
    }

    impl Debug for CapacityArgs
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("CapacityArgs")
                .field("input", &self.input)
                .finish()
        }
    }

    #[test]
    fn should_reject_different_input_formats()
    {
        let mut args = EncodingArgs {
            input: Path::new("input.png").into(),
            output_file: Some(Path::new("output.bmp").into()),
            text: Some("payload".into()),
            payload_file: None,
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
    fn clap_configuration_is_sound()
    {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_encode_with_inline_text()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "-o",
            "output.png",
            "--text",
            "secret",
        ])
        .expect("expected encode command");

        match cli.command
        {
            Command::Encode(args) =>
            {
                assert_eq!(args.input.as_ref(), Path::new("input.png"));
                assert_eq!(
                    args.output_file.as_deref(),
                    Some(Path::new("output.png"))
                );
                assert_eq!(args.text.as_deref(), Some("secret"));
                assert!(args.payload_file.is_none());
                assert!(args.encryption.is_none());
            },
            other => panic!("expected encode command, got {other:?}"),
        }
    }

    #[test]
    fn test_default_output_path()
    {
        let args = EncodingArgs {
            input: Path::new("input.png").into(),
            output_file: None,
            text: Some("secret".into()),
            payload_file: None,
            encryption: None,
        };
        let output_path = resolve_output_path(&args, Some("png"));
        assert_eq!(output_path, Path::new("a.png"));
    }

    #[test]
    fn parses_encode_with_payload_file()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "-o",
            "output.png",
            "--file",
            "message.txt",
        ])
        .expect("expected encode command");

        match cli.command
        {
            Command::Encode(args) =>
            {
                assert_eq!(args.input.as_ref(), Path::new("input.png"));
                assert_eq!(
                    args.output_file.as_deref(),
                    Some(Path::new("output.png"))
                );
                assert!(args.text.is_none());
                assert_eq!(
                    args.payload_file.as_deref(),
                    Some(Path::new("message.txt"))
                );
            },
            other => panic!("expected encode command, got {other:?}"),
        }
    }

    #[test]
    fn parses_encode_with_encryption_flags()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "-o",
            "output.png",
            "--text",
            "secret",
            "--key-file",
            "key.bin",
        ])
        .expect("expected encode command");

        match cli.command
        {
            Command::Encode(mut args) =>
            {
                let encryption = args
                    .encryption
                    .take()
                    .expect("encryption flags should be parsed");
                assert_eq!(
                    encryption.key_file.as_deref(),
                    Some(Path::new("key.bin"))
                );
            },
            other => panic!("expected encode command, got {other:?}"),
        }
    }

    #[test]
    fn encode_requires_message_source()
    {
        Cli::try_parse_from(["cloakpng", "encode", "input.png", "output.png"])
            .expect_err("missing message source must error");
    }

    #[test]
    fn encryption_requires_key_file()
    {
        // Since encryption is optional, we need to test that if we try to use
        // the encryption context without providing a key file, it errors
        // properly
        let encryption = EncryptionArgs { key_file: None };

        let error = encryption
            .context()
            .expect_err("encryption context should require key file");

        assert!(matches!(
            error,
            CryptoError::MissingEncryptionField { field }
                if field.as_ref() == "--key-file"
        ));
    }

    #[test]
    fn encryption_accepts_hex_encoded_key()
    {
        use tempfile::TempDir;

        let dir = TempDir::new().expect("failed to create tempdir");
        let key_path = dir.path().join("key.txt");

        // 32 bytes = 64 hex chars
        let hex_key =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(&key_path, hex_key).expect("failed to write key file");

        let encryption = EncryptionArgs {
            key_file: Some(key_path.into_boxed_path()),
        };

        encryption
            .context()
            .expect("hex-encoded key should be accepted");
    }

    #[test]
    fn encryption_accepts_raw_binary_key()
    {
        use tempfile::TempDir;

        let dir = TempDir::new().expect("failed to create tempdir");
        let key_path = dir.path().join("key.bin");

        // 32 random bytes
        let raw_key = [0x42; 32];
        std::fs::write(&key_path, raw_key).expect("failed to write key file");

        let encryption = EncryptionArgs {
            key_file: Some(key_path.into_boxed_path()),
        };

        encryption
            .context()
            .expect("raw binary key should be accepted");
    }

    #[test]
    fn encryption_roundtrip_generates_nonce()
    {
        use tempfile::TempDir;

        let dir = TempDir::new().expect("failed to create tempdir");
        let key_path = dir.path().join("key.bin");

        // Create a valid key
        let raw_key = [0x42; 32];
        std::fs::write(&key_path, raw_key).expect("failed to write key file");

        let encryption = EncryptionArgs {
            key_file: Some(key_path.into_boxed_path()),
        };

        let original_message = b"test message";

        // Encrypt
        let encrypted = try_encrypt_message(original_message, &encryption)
            .expect("encryption should succeed");

        // Verify nonce is embedded (12 bytes nonce + ciphertext + 16 bytes tag)
        assert!(
            encrypted.len() > CHACHA20_NONCE_SIZE + CHACHA20_TAG_SIZE,
            "encrypted payload should include nonce and tag"
        );

        // Decrypt
        let decrypted = try_decrypt_message(&encrypted, &encryption)
            .expect("decryption should succeed");

        assert_eq!(decrypted, original_message);
    }

    #[test]
    fn encryption_generates_different_nonces()
    {
        use tempfile::TempDir;

        let dir = TempDir::new().expect("failed to create tempdir");
        let key_path = dir.path().join("key.bin");

        let raw_key = [0x42u8; 32];
        std::fs::write(&key_path, raw_key).expect("failed to write key file");

        let encryption = EncryptionArgs {
            key_file: Some(key_path.into_boxed_path()),
        };

        let message = b"test message";

        // Encrypt the same message twice
        let encrypted1 = try_encrypt_message(message, &encryption)
            .expect("encryption should succeed");
        let encrypted2 = try_encrypt_message(message, &encryption)
            .expect("encryption should succeed");

        // Extract nonces (first 12 bytes)
        let nonce1 = &encrypted1[..CHACHA20_NONCE_SIZE];
        let nonce2 = &encrypted2[..CHACHA20_NONCE_SIZE];

        // Nonces should be different even with same message and key
        assert_ne!(
            nonce1, nonce2,
            "encrypting the same message twice should use different nonces"
        );
    }

    #[test]
    fn parses_decode_with_output_file()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "decode",
            "payload.png",
            "--output",
            "message.txt",
        ])
        .expect("expected decode command");

        match cli.command
        {
            Command::Decode(args) =>
            {
                assert_eq!(args.input.as_ref(), Path::new("payload.png"));
                assert_eq!(
                    args.output_file.as_deref(),
                    Some(Path::new("message.txt"))
                );
                assert!(args.encryption.is_none());
            },
            other => panic!("expected decode command, got {other:?}"),
        }
    }

    #[test]
    fn parses_decode_with_encryption()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "decode",
            "payload.png",
            "--key-file",
            "key.bin",
        ])
        .expect("expected decode command");

        match cli.command
        {
            Command::Decode(args) =>
            {
                let encryption = args
                    .encryption
                    .as_ref()
                    .expect("encryption flags should be parsed");
                assert_eq!(
                    encryption.key_file.as_deref(),
                    Some(Path::new("key.bin"))
                );
            },
            other => panic!("expected decode command, got {other:?}"),
        }
    }

    #[test]
    fn parses_capacity_command()
    {
        let cli = Cli::try_parse_from(["cloakpng", "cap", "image.png"])
            .expect("expected capacity command");

        match cli.command
        {
            Command::Cap(args) =>
            {
                assert_eq!(args.input.as_ref(), Path::new("image.png"));
            },
            other => panic!("expected capacity command, got {other:?}"),
        }
    }
}
