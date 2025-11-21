//! Command line interface for the application.
//!
//! Provides an entry point for the application and handles the CLI arguments.
use std::fs;
use std::path::Path;

use clap::{ArgGroup, Args, Parser, Subcommand};
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{ExtendedColorType, ImageEncoder, RgbaImage};
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
    #[error("provide text with --text or --text-file")]
    MissingMessage,
}

/// The main CLI parser
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Encode and decode text with RGB LSB steganography for PNG files"
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
    /// PNG image that will receive the hidden text.
    input: Box<Path>,
    /// Destination path for the modified PNG image.
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
    /// PNG image that contains hidden text.
    input: Box<Path>,
    /// Optional file to write the decoded text. Prints to stdout when omitted.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    output_text: Option<Box<Path>>,
}

/// Handles the encoding of a message into a PNG image.
///
/// # Errors
///
/// Returns [`AppError`] when reading or writing files, or encoding the image.
fn handle_encode(args: &mut EncodingArgs) -> Result<(), AppError>
{
    let mut image = load_png(&args.input)?;
    let message = resolve_message(args)?;

    // Embedding the message happens here
    embed_text(&mut image, &message)?;

    // Output the modified image to the specified path with
    // compression and filtering
    let file = fs::File::create(&args.output)?;
    let encoder = PngEncoder::new_with_quality(
        file,
        CompressionType::Default,
        FilterType::Adaptive,
    );
    encoder.write_image(
        image.as_raw(),
        image.width(),
        image.height(),
        ExtendedColorType::Rgba8,
    )?;

    Ok(())
}

/// Handles the decoding of a message from a PNG image.
///
/// # Errors
///
/// Returns [`AppError`] when reading or writing files, or decoding the image.
fn handle_decode(args: DecodingArgs) -> Result<(), AppError>
{
    let image = load_png(&args.input)?;
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

/// Loads a PNG image from the specified path and converts it to an RGBA image.
///
/// # Errors
///
/// Returns [`AppError`] when reading the file, or converting the image.
fn load_png<P: AsRef<Path>>(path: P) -> Result<RgbaImage, AppError>
{
    Ok(image::open(path.as_ref())?.into_rgba8())
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
