use std::fs::File;
use std::path::Path;

use image::codecs::bmp::BmpEncoder;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::codecs::pnm::{PnmEncoder, PnmSubtype, SampleEncoding};
use image::codecs::tiff::TiffEncoder;
use image::{ExtendedColorType, ImageEncoder, RgbImage};

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
/// # Errors
///
/// Returns [`AppError`] when reading the file, or converting the image.
pub(super) fn load_image<P: AsRef<Path>>(path: P)
-> Result<RgbImage, AppError>
{
    Ok(image::open(path.as_ref())?.into_rgb8())
}

/// Writes the provided image using the encoder defined by the extension.
pub(super) fn write_image<P: AsRef<Path>>(
    image: &RgbImage,
    extension: Option<&str>,
    output: P,
) -> Result<(), AppError>
{
    let mut file = File::create(output)?;

    match extension
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
