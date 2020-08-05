use owning_ref::ArcRef;
use sgdata::SGData;
use std;
use std::io;

#[cfg(feature = "with-xz2")]
use std::cmp;
#[cfg(feature = "with-zstd")]
use std::io::Read;
#[cfg(any(
    feature = "with-bzip2",
    feature = "with-deflate",
    feature = "with-xz2",
    feature = "with-zstd"
))]
use std::io::Write;
use std::sync::Arc;

#[cfg(feature = "with-bzip2")]
use bzip2;
#[cfg(feature = "with-deflate")]
use flate2;
#[cfg(feature = "with-xz2")]
use lzma;
#[cfg(feature = "with-zstd")]
use zstd;

pub type ArcCompression = Arc<dyn Compression + Send + Sync>;

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

#[cfg(feature = "with-deflate")]
pub struct Deflate {
    level: flate2::Compression,
}
#[cfg(feature = "with-deflate")]
impl Deflate {
    pub fn new(level: i32) -> Self {
        let level = if level < 0 {
            flate2::Compression::fast()
        } else if level > 0 {
            flate2::Compression::best()
        } else {
            flate2::Compression::default()
        };

        Deflate { level }
    }
}
#[cfg(feature = "with-deflate")]
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

#[cfg(feature = "with-bzip2")]
pub struct Bzip2 {
    level: bzip2::Compression,
}
#[cfg(feature = "with-bzip2")]
impl Bzip2 {
    pub fn new(level: i32) -> Self {
        let level = if level < 0 {
            bzip2::Compression::Fastest
        } else if level > 0 {
            bzip2::Compression::Best
        } else {
            bzip2::Compression::Default
        };

        Bzip2 { level }
    }
}
#[cfg(feature = "with-bzip2")]
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

#[cfg(feature = "with-xz2")]
pub struct Xz2 {
    level: u32,
}
#[cfg(feature = "with-xz2")]
impl Xz2 {
    pub fn new(level: i32) -> Self {
        let level = cmp::min(cmp::max(level + 6, 0), 10) as u32;

        Xz2 { level }
    }
}
#[cfg(feature = "with-xz2")]
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

#[cfg(feature = "with-zstd")]
pub struct Zstd {
    level: i32,
}
#[cfg(feature = "with-zstd")]
impl Zstd {
    pub fn new(level: i32) -> Self {
        Zstd { level }
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

#[cfg(feature = "with-zstd")]
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
