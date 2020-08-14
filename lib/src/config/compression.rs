use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::compression;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Compression {
    #[cfg(feature = "with-deflate")]
    #[serde(rename = "deflate")]
    Deflate(Deflate),
    #[cfg(feature = "with-xz2")]
    #[serde(rename = "xz2")]
    Xz2(Xz2),
    #[cfg(feature = "with-bzip2")]
    #[serde(rename = "bzip2")]
    Bzip2(Bzip2),
    #[cfg(feature = "with-zstd")]
    #[serde(rename = "zstd")]
    Zstd(Zstd),
    #[serde(rename = "none")]
    None,
}

impl Default for Compression {
    fn default() -> Compression {
        #[cfg(feature = "with-deflate")]
        return Compression::Deflate(Deflate { level: 0 });
        #[cfg(not(feature = "with-deflate"))]
        return Compression::None;
    }
}

impl Compression {
    pub(crate) fn to_engine(&self) -> compression::ArcCompression {
        match *self {
            Compression::None => Arc::new(compression::NoCompression),
            #[cfg(feature = "with-deflate")]
            Compression::Deflate(d) => {
                Arc::new(compression::Deflate::new(d.level))
            }
            #[cfg(feature = "with-xz2")]
            Compression::Xz2(d) => Arc::new(compression::Xz2::new(d.level)),
            #[cfg(feature = "with-bzip2")]
            Compression::Bzip2(d) => Arc::new(compression::Bzip2::new(d.level)),
            #[cfg(feature = "with-zstd")]
            Compression::Zstd(d) => Arc::new(compression::Zstd::new(d.level)),
        }
    }
}
#[cfg(feature = "with-deflate")]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Deflate {
    #[serde(rename = "level")]
    level: i32,
}
#[cfg(feature = "with-deflate")]
impl Deflate {
    pub fn new(level: i32) -> Self {
        Deflate { level }
    }
}
#[cfg(feature = "with-bzip2")]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Bzip2 {
    #[serde(rename = "level")]
    level: i32,
}
#[cfg(feature = "with-bzip2")]
impl Bzip2 {
    pub fn new(level: i32) -> Self {
        Bzip2 { level }
    }
}

#[cfg(feature = "with-zstd")]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Zstd {
    #[serde(rename = "level")]
    level: i32,
}
#[cfg(feature = "with-zstd")]
impl Zstd {
    pub fn new(level: i32) -> Self {
        Zstd { level }
    }
}

#[cfg(feature = "with-xz2")]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Xz2 {
    #[serde(rename = "level")]
    level: i32,
}
#[cfg(feature = "with-xz2")]
impl Xz2 {
    pub fn new(level: i32) -> Self {
        Xz2 { level }
    }
}
