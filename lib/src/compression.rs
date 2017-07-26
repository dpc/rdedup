use bzip2;
use flate2;
use lzma;
use owning_ref::ArcRef;
use sgdata::SGData;
use std;
use std::io;

use std::io::{Write, Read};
use std::sync::Arc;
use zstd;

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


pub struct Zstd;

struct SGReader<'a> {
    parts: &'a [ArcRef<Vec<u8>, [u8]>],
    parts_i: usize,
    part_offset: usize,
}

impl<'a> SGReader<'a> {
    fn new(parts: &'a SGData) -> Self {
        SGReader {
            parts: parts.as_parts(),
            parts_i: 0,
            part_offset: 0,
        }
    }
}

impl<'a> io::Read for SGReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.parts_i >= self.parts.len() {
                return Ok(0);
            }
            let cur_slice = &self.parts[self.parts_i][self.part_offset..];
            if cur_slice.is_empty() {
                self.parts_i += 1;
                self.part_offset = 0;
                continue;
            }
            let to_copy = std::cmp::min(buf.len(), cur_slice.len());

            buf[..to_copy].clone_from_slice(&cur_slice[..to_copy]);
            self.part_offset += to_copy;

            return Ok(to_copy);
        }
    }
}

impl Compression for Zstd {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut backing: Vec<u8> = Vec::with_capacity(buf.len());
        {
            let mut compressor = zstd::Encoder::new(&mut backing, 5).unwrap();
            for sg_part in buf.as_parts() {
                compressor.write_all(&sg_part).unwrap()
            }
            compressor.finish().unwrap();
        }
        Ok(SGData::from_single(backing))
    }

    fn decompress(&self, buf: SGData) -> io::Result<SGData> {
        let mut backing: Vec<u8> = Vec::with_capacity(buf.len());
        {
            // Ehh... https://github.com/gyscos/zstd-rs/issues/34
            let mut reader = SGReader::new(&buf);
            let mut decompressor = zstd::Decoder::new(&mut reader).unwrap();
            let _ = decompressor.read_to_end(&mut backing)?;
        }
        Ok(SGData::from_single(backing))
    }
}
