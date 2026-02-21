use std::io::Cursor;

use image::ImageFormat;
use qr_code::QrCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QrRenderError {
    #[error("pixel_per_module must be >= 1")]
    InvalidPixelPerModule,

    #[error("failed to encode qr content: {0}")]
    Qr(#[from] qr_code::types::QrError),

    #[error("failed to render qr bitmap: {0}")]
    Bmp(#[from] qr_code::bmp_monochrome::BmpError),

    #[error("failed to write qr bitmap: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to decode or encode image: {0}")]
    Image(#[from] image::ImageError),
}

pub fn render_text_qr(content: &str) -> Result<String, QrRenderError> {
    let qr = QrCode::new(content)?;
    Ok(qr.to_string(true, 3))
}

pub fn render_png_qr(content: &str, pixel_per_module: u8) -> Result<Vec<u8>, QrRenderError> {
    if pixel_per_module == 0 {
        return Err(QrRenderError::InvalidPixelPerModule);
    }

    let qr = QrCode::new(content)?;
    let mut bmp = qr.to_bmp().add_white_border(2)?;
    if pixel_per_module > 1 {
        bmp = bmp.mul(pixel_per_module)?;
    }

    let mut bmp_bytes = Vec::new();
    bmp.write(&mut bmp_bytes)?;

    let image = image::load_from_memory_with_format(&bmp_bytes, ImageFormat::Bmp)?;

    let mut out = Cursor::new(Vec::new());
    image.write_to(&mut out, ImageFormat::Png)?;

    Ok(out.into_inner())
}
