use bzip2;
use flate2;
use lzma;
use sgdata::SGData;
use std::io;

use std::io::Write;
use std::sync::Arc;

pub type ArcCompression = Arc<Compression + Send + Sync>;

pub trait Compression {
    fn compress(&self, buf: SGData) -> io::Result<SGData>;
    fn decompress(&self, bug: SGData) -> io::Result<SGData>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        Ok(buf)
    }
    fn decompress(&self, buf: SGData) -> io::Result<SGData> {
        Ok(buf)
    }
}

pub struct Deflate;

impl Compression for Deflate {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut compressor = flate2::write::DeflateEncoder::new(
            Vec::with_capacity(buf.len()),
            flate2::Compression::Default,
        );

        for sg_part in buf.as_parts() {
            compressor.write_all(sg_part).unwrap();
        }

        Ok(SGData::from_single(compressor.finish().unwrap()))
    }

    fn decompress(&self, buf: SGData) -> io::Result<SGData> {
        let mut decompressor =
            flate2::write::DeflateDecoder::new(Vec::with_capacity(buf.len()));

        for part in buf.as_parts() {
            decompressor.write_all(&part)?;
        }
        Ok(SGData::from_single(decompressor.finish()?))
    }
}

pub struct Bzip2;

impl Compression for Bzip2 {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut compressor = bzip2::write::BzEncoder::new(
            Vec::with_capacity(buf.len()),
            bzip2::Compression::Default,
        );

        for sg_part in buf.as_parts() {
            compressor.write_all(sg_part).unwrap();
        }

        Ok(SGData::from_single(compressor.finish().unwrap()))
    }

    fn decompress(&self, buf: SGData) -> io::Result<SGData> {
        let mut decompressor =
            bzip2::write::BzDecoder::new(Vec::with_capacity(buf.len()));

        for sg_part in buf.as_parts() {
            decompressor.write_all(&sg_part)?;
        }
        Ok(SGData::from_single(decompressor.finish()?))
    }
}

pub struct Xz2;

impl Compression for Xz2 {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut backing: Vec<u8> = Vec::with_capacity(buf.len());
        {
            let mut compressor =
                lzma::LzmaWriter::new_compressor(&mut backing, 6).unwrap();
            for sg_part in buf.as_parts() {
                // compressor.write can sometimes return zero, so we can't just
                // use write_all; see
                // https://github.com/fpgaminer/rust-lzma/issues/13
                let todo = sg_part.len();
                let mut index = 0;
                while {
                    let bytes = compressor.write(&sg_part[index..]).unwrap();
                    index += bytes;

                    index < todo
                } {}
            }
            compressor.finish().unwrap();
        }
        Ok(SGData::from_single(backing))
    }

    fn decompress(&self, buf: SGData) -> io::Result<SGData> {
        let mut backing: Vec<u8> = Vec::with_capacity(buf.len());
        {
            let mut decompressor =
                lzma::LzmaWriter::new_decompressor(&mut backing).unwrap();
            for sg_part in buf.as_parts() {
                // compressor.write can sometimes return zero, so we can't just
                // use write_all; see
                // https://github.com/fpgaminer/rust-lzma/issues/13
                let todo = sg_part.len();
                let mut index = 0;
                while {
                    let bytes = decompressor.write(&sg_part[index..]).unwrap();
                    index += bytes;

                    index < todo
                } {}
            }
            decompressor.finish().unwrap();
        }
        Ok(SGData::from_single(backing))
    }
}
