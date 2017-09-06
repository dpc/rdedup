use bzip2;
use flate2;
use lzma;
use owning_ref::ArcRef;
use sgdata::SGData;
use std;
use std::{cmp, io};

use std::io::{Read, Write};
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

pub struct Deflate {
    level: flate2::Compression,
}

impl Deflate {
    pub fn new(level: i32) -> Self {
        let level = if level < 0 {
            flate2::Compression::Fast
        } else if level > 0 {
            flate2::Compression::Best
        } else {
            flate2::Compression::Default
        };

        Deflate { level: level }
    }
}

impl Compression for Deflate {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut compressor = flate2::write::DeflateEncoder::new(
            Vec::with_capacity(buf.len()),
            self.level,
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
            decompressor.write_all(part)?;
        }
        Ok(SGData::from_single(decompressor.finish()?))
    }
}

pub struct Bzip2 {
    level: bzip2::Compression,
}

impl Bzip2 {
    pub fn new(level: i32) -> Self {
        let level = if level < 0 {
            bzip2::Compression::Fastest
        } else if level > 0 {
            bzip2::Compression::Best
        } else {
            bzip2::Compression::Default
        };

        Bzip2 { level: level }
    }
}

impl Compression for Bzip2 {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut compressor = bzip2::write::BzEncoder::new(
            Vec::with_capacity(buf.len()),
            self.level,
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
            decompressor.write_all(sg_part)?;
        }
        Ok(SGData::from_single(decompressor.finish()?))
    }
}

pub struct Xz2 {
    level: u32,
}

impl Xz2 {
    pub fn new(level: i32) -> Self {
        let level = cmp::min(cmp::max(level + 6, 0), 10) as u32;

        Xz2 { level: level }
    }
}

impl Compression for Xz2 {
    fn compress(&self, buf: SGData) -> io::Result<SGData> {
        let mut backing: Vec<u8> = Vec::with_capacity(buf.len());
        {
            let mut compressor =
                lzma::LzmaWriter::new_compressor(&mut backing, self.level)
                    .unwrap();
            for sg_part in buf.as_parts() {
                // compressor.write can sometimes return zero, so we can't just
                // use write_all; see
                // https://github.com/fpgaminer/rust-lzma/issues/13
                let todo = sg_part.len();
                let mut index = 0;
                while index < todo {
                    let bytes = compressor.write(&sg_part[index..]).unwrap();
                    index += bytes;
                }
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
                while index < todo {
                    let bytes = decompressor.write(&sg_part[index..]).unwrap();
                    index += bytes;
                }
            }
            decompressor.finish().unwrap();
        }
        Ok(SGData::from_single(backing))
    }
}


pub struct Zstd {
    level: i32,
}

impl Zstd {
    pub fn new(level: i32) -> Self {
        Zstd { level: level }
    }
}

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
            let mut compressor =
                zstd::Encoder::new(&mut backing, self.level).unwrap();
            for sg_part in buf.as_parts() {
                compressor.write_all(sg_part).unwrap()
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
