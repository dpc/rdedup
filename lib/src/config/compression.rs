use compression;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Compression {
    #[serde(rename = "deflate")]
    Deflate(Deflate),
    #[serde(rename = "xz2")]
    Xz2(Xz2),
    #[serde(rename = "bzip2")]
    Bzip2(Bzip2),
    #[serde(rename = "zstd")]
    Zstd(Zstd),
    #[serde(rename = "none")]
    None,
}

impl Default for Compression {
    fn default() -> Compression {
        Compression::Deflate(Deflate { level: 0 })
    }
}

impl Compression {
    pub(crate) fn to_engine(&self) -> compression::ArcCompression {
        match *self {
            Compression::None => Arc::new(compression::NoCompression),
            Compression::Deflate(d) => {
                Arc::new(compression::Deflate::new(d.level))
            }
            Compression::Xz2(d) => Arc::new(compression::Xz2::new(d.level)),
            Compression::Bzip2(d) => Arc::new(compression::Bzip2::new(d.level)),
            Compression::Zstd(d) => Arc::new(compression::Zstd::new(d.level)),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Deflate {
    #[serde(rename = "level")]
    level:                        i32,
}

impl Deflate {
    pub fn new(level: i32) -> Self {
        Deflate { level: level }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Bzip2 {
    #[serde(rename = "level")]
    level:                        i32,
}

impl Bzip2 {
    pub fn new(level: i32) -> Self {
        Bzip2 { level: level }
    }
}


#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Zstd {
    #[serde(rename = "level")]
    level:                        i32,
}

impl Zstd {
    pub fn new(level: i32) -> Self {
        Zstd { level: level }
    }
}


#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Xz2 {
    #[serde(rename = "level")]
    level:                        i32,
}

impl Xz2 {
    pub fn new(level: i32) -> Self {
        Xz2 { level: level }
    }
}
