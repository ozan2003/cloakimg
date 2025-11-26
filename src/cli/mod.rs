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
    MAX_REASONABLE_MESSAGE_SIZE, StegoError, embed_text, extract_text,
};

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

    /// Something went wrong with the crypto operations
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The main CLI parser
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Encode and decode text with RGB LSB steganography for files",
    after_help = formatcp!(
        "Maximum reasonable message size is {} MiB",
        MAX_REASONABLE_MESSAGE_SIZE / (1024 * 1024)
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

#[cfg(test)]
mod tests
{
    use std::path::Path;

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
}
