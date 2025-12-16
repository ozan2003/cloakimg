//! CLI image helpers.
//!
//! Normalizes extensions, loads RGB buffers, and writes files with the
//! appropriate encoder.
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::path::Path;

use image::codecs::bmp::BmpEncoder;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::codecs::pnm::{PnmEncoder, PnmSubtype, SampleEncoding};
use image::codecs::tiff::TiffEncoder;
use image::{DynamicImage, ExtendedColorType, ImageEncoder, RgbImage};

use super::AppError;

/// Normalizes the extension of a path to lowercase.
pub(super) fn normalized_extension<P: AsRef<Path>>(path: P) -> Option<String>
{
    path.as_ref()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

/// Loads an image from the specified path and converts it to an RGB buffer.
///
/// # Arguments
///
/// * `path` - The path to the image to load.
///
/// # Errors
///
/// Returns:
/// * [`AppError::Read`] when the path is a directory
/// * [`AppError::ImageOpen`] when the image cannot be loaded
pub(super) fn load_image<P: AsRef<Path>>(path: P)
-> Result<RgbImage, AppError>
{
    if path.as_ref().is_dir()
    {
        let message = format!("{} is a directory", path.as_ref().display());
        return Err(AppError::Read {
            path: path.as_ref().into(),
            source: Error::new(ErrorKind::IsADirectory, message),
        });
    }

    image::open(path.as_ref())
        .map_err(|source| AppError::ImageOpen {
            path: path.as_ref().into(),
            source,
        })
        .map(DynamicImage::into_rgb8)
}

/// Writes the provided image using the encoder defined by the extension.
///
/// # Arguments
///
/// * `image` - The image to write.
/// * `extension` - The extension of the output file.
/// * `output` - The path to the output file.
///
/// # Errors
///
/// Returns:
/// * [`AppError::Write`] when the file cannot be created
/// * [`AppError::ImageEncode`] when the image cannot be encoded
/// * [`AppError::UnsupportedFormat`] when the extension is not supported
pub(super) fn write_image<P: AsRef<Path>>(
    image: &RgbImage,
    extension: Option<&str>,
    output: P,
) -> Result<(), AppError>
{
    let mut file =
        File::create(output.as_ref()).map_err(|source| AppError::Write {
            path: output.as_ref().into(),
            source,
        })?;

    match extension
    {
        Some(ext @ "png") =>
        {
            let encoder = PngEncoder::new_with_quality(
                &mut file,
                CompressionType::Default,
                FilterType::Adaptive,
            );
            encoder
                .write_image(
                    image.as_raw(),
                    image.width(),
                    image.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|source| AppError::ImageEncode {
                    path: output.as_ref().into(),
                    target_format: ext.into(),
                    source,
                })?;
        },
        Some(ext @ "bmp") =>
        {
            let mut encoder = BmpEncoder::new(&mut file);
            encoder
                .encode(
                    image.as_raw(),
                    image.width(),
                    image.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|source| AppError::ImageEncode {
                    path: output.as_ref().into(),
                    target_format: ext.into(),
                    source,
                })?;
        },
        Some(ext @ ("tiff" | "tif")) =>
        {
            let encoder = TiffEncoder::new(&mut file);
            encoder
                .write_image(
                    image.as_raw(),
                    image.width(),
                    image.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|source| AppError::ImageEncode {
                    path: output.as_ref().into(),
                    target_format: ext.into(),
                    source,
                })?;
        },
        Some(ext @ "ppm") =>
        {
            let mut encoder = PnmEncoder::with_subtype(
                PnmEncoder::new(&mut file),
                PnmSubtype::Pixmap(SampleEncoding::Binary),
            );
            encoder
                .encode(
                    image.as_raw().as_slice(),
                    image.width(),
                    image.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|source| AppError::ImageEncode {
                    path: output.as_ref().into(),
                    target_format: ext.into(),
                    source,
                })?;
        },
        _ =>
        {
            let extension = extension.unwrap_or("<unknown>").into();
            return Err(AppError::UnsupportedFormat { extension });
        },
    }

    Ok(())
}
