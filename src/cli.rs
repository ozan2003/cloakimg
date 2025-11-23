//! Command line interface for the application.
//!
//! Provides an entry point for the application and handles the CLI arguments.
use std::fs;
use std::path::Path;

use clap::{ArgGroup, Args, Parser, Subcommand};
use image::codecs::bmp::BmpEncoder;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::codecs::pnm::{PnmEncoder, PnmSubtype, SampleEncoding};
use image::codecs::tiff::TiffEncoder;
use image::{ExtendedColorType, ImageEncoder, RgbImage};
use thiserror::Error;

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
    let message = resolve_message(args)?;

    // Embedding the message happens here
    embed_text(&mut image, &message)?;

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
    // Extracting the message happens here
    let message = extract_text(&image)?;

    if let Some(path) = args.output_text
    {
        fs::write(path, message)?;
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

#[allow(
    unused_imports,
    reason = "when removed, it wont compile; most likely false positive"
)]
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
