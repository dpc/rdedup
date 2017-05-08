use flate2;
use sg::SGBuf;
use std::io;

use std::io::Write;
use std::sync::Arc;

pub type ArcCompression = Arc<Compression + Send + Sync>;

pub trait Compression {
    fn compress(&self, buf: SGBuf) -> io::Result<SGBuf>;
    fn decompress(&self, bug: SGBuf) -> io::Result<SGBuf>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    fn compress(&self, buf: SGBuf) -> io::Result<SGBuf> {
        Ok(buf)
    }
    fn decompress(&self, buf: SGBuf) -> io::Result<SGBuf> {
        Ok(buf)
    }
}

pub struct Deflate;

impl Compression for Deflate {
    fn compress(&self, buf: SGBuf) -> io::Result<SGBuf> {
        let mut compressor =
            flate2::write::DeflateEncoder::new(
                Vec::with_capacity(buf.total_len()),
                flate2::Compression::Default);

        for sg_part in &*buf {
            compressor.write_all(sg_part).unwrap();
        }

        Ok(SGBuf::from_single(compressor.finish().unwrap()))
    }

    fn decompress(&self, buf: SGBuf) -> io::Result<SGBuf> {
        let mut decompressor =
            flate2::write::DeflateDecoder::new(Vec::with_capacity(buf.total_len()));

        for part in &*buf {
            decompressor.write_all(&part)?;
        }
        Ok(SGBuf::from_single(decompressor.finish()?))
    }
}
