//! Command line interface for the application.
//!
//! Provides an entry point for the application and handles the CLI arguments.
mod encryption;
mod image_io;
mod payload;

use std::fs;
use std::path::Path;

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
    MAX_REASONABLE_MSG_SIZE, StegoError, embed_text, extract_text,
    max_message_size,
};

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

    /// Something went wrong with the crypto operations
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The main CLI parser
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Encode and decode text with RGB LSB steganography into images",
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

/// Embed a message into an image.
#[derive(Args)]
#[command(group(
    ArgGroup::new("message")
        .required(true)
        .args(["text", "text_file"])
))]
struct EncodingArgs
{
    /// Image that will receive the text.
    input: Box<Path>,
    /// Output path for the embedded image.
    output: Box<Path>,
    /// Text to embed.
    #[arg(short = 'i', long = "input", value_name = "TEXT")]
    text: Option<String>,
    /// Path to an UTF-8 text file to embed.
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    text_file: Option<Box<Path>>,
    /// Optional encryption parameters.
    #[command(flatten)]
    encryption: Option<EncryptionArgs>,
}

/// Extract a message from an image.
#[derive(Args)]
struct DecodingArgs
{
    /// Image that contains the text.
    input: Box<Path>,
    /// Optional file to write the decoded text. Prints to stdout when omitted.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    output_text: Option<Box<Path>>,
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
/// Returns [`AppError`] when reading or writing files, decoding images, or
/// running steganography routines fails.
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

    write_image(&image, input_ext.as_deref(), &args.output)
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

/// Handles the capacity calculation of a message for an image.
///
/// # Errors
///
/// Returns [`AppError`] when reading the image.
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
                .field("nonce_file", &self.nonce_file)
                .field("counter", &self.counter)
                .finish()
        }
    }

    impl Debug for EncodingArgs
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result
        {
            f.debug_struct("EncodingArgs")
                .field("input", &self.input)
                .field("output", &self.output)
                .field("text", &self.text)
                .field("text_file", &self.text_file)
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
                .field("output_text", &self.output_text)
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
            "output.png",
            "--input",
            "secret",
        ])
        .expect("expected encode command");

        match cli.command
        {
            Command::Encode(args) =>
            {
                assert_eq!(args.input.as_ref(), Path::new("input.png"));
                assert_eq!(args.output.as_ref(), Path::new("output.png"));
                assert_eq!(args.text.as_deref(), Some("secret"));
                assert!(args.text_file.is_none());
                assert!(args.encryption.is_none());
            },
            other => panic!("expected encode command, got {other:?}"),
        }
    }

    #[test]
    fn parses_encode_with_text_file()
    {
        let cli = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
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
                assert_eq!(args.output.as_ref(), Path::new("output.png"));
                assert!(args.text.is_none());
                assert_eq!(
                    args.text_file.as_deref(),
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
            "output.png",
            "--input",
            "secret",
            "--key-file",
            "key.bin",
            "--nonce-file",
            "nonce.bin",
            "--counter",
            "42",
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
                assert_eq!(encryption.key_file.as_ref(), Path::new("key.bin"));
                assert_eq!(
                    encryption.nonce_file.as_ref(),
                    Path::new("nonce.bin")
                );
                assert_eq!(encryption.counter, 42);
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
    fn encryption_flags_require_pairs()
    {
        let err = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "output.png",
            "--input",
            "secret",
            "--key-file",
            "key.bin",
        ]);
        assert!(
            err.is_err(),
            "providing --key-file without --nonce-file must error"
        );

        let err = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "output.png",
            "--input",
            "secret",
            "--nonce-file",
            "nonce.bin",
        ]);
        assert!(
            err.is_err(),
            "providing --nonce-file without --key-file must error"
        );

        let err = Cli::try_parse_from([
            "cloakpng",
            "encode",
            "input.png",
            "output.png",
            "--input",
            "secret",
            "--counter",
            "10",
        ]);
        assert!(err.is_err(), "--counter without key/nonce must error");
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
                    args.output_text.as_deref(),
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
            "--nonce-file",
            "nonce.bin",
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
                assert_eq!(encryption.key_file.as_ref(), Path::new("key.bin"));
                assert_eq!(
                    encryption.nonce_file.as_ref(),
                    Path::new("nonce.bin")
                );
                assert_eq!(encryption.counter, 0);
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
