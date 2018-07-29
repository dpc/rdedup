//! Settings: options that user can pick

use config;
use std::io;

#[derive(Clone)]
pub enum Compression {
    #[cfg(feature = "with-deflate")]
    Deflate,
    #[cfg(feature = "with-xz2")]
    Xz2,
    #[cfg(feature = "with-bzip2")]
    Bzip2,
    #[cfg(feature = "with-zstd")]
    Zstd,
    None,
}

impl Default for Compression {
    fn default() -> Self {
        #[cfg(feature = "with-deflate")]
        return Compression::Deflate;
        #[cfg(not(feature = "with-deflate"))]
        return Compression::None;
    }
}

impl Compression {
    pub fn to_config(&self, _level: i32) -> config::Compression {
        match *self {
            #[cfg(feature = "with-deflate")]
            Compression::Deflate => {
                config::Compression::Deflate(config::Deflate::new(_level))
            }
            #[cfg(feature = "with-xz2")]
            Compression::Xz2 => {
                config::Compression::Xz2(config::Xz2::new(_level))
            }
            #[cfg(feature = "with-bzip2")]
            Compression::Bzip2 => {
                config::Compression::Bzip2(config::Bzip2::new(_level))
            }
            #[cfg(feature = "with-zstd")]
            Compression::Zstd => {
                config::Compression::Zstd(config::Zstd::new(_level))
            }
            Compression::None => config::Compression::None,
        }
    }
}

#[derive(Clone)]
pub enum Encryption {
    Curve25519,
    None,
}

impl Default for Encryption {
    fn default() -> Self {
        Encryption::Curve25519
    }
}

// Unlike encryption, settings == config here
#[derive(Clone, Default)]
pub struct Chunking(pub(crate) config::Chunking);

#[derive(Clone)]
pub enum PWHash {
    Weak,
    Interactive,
    Strong,
}

impl Default for PWHash {
    fn default() -> Self {
        PWHash::Strong
    }
}

impl<'a> From<&'a str> for PWHash {
    fn from(s: &str) -> Self {
        match s {
            "weak" => PWHash::Weak,
            "interactive" => PWHash::Interactive,
            "strong" => PWHash::Strong,
            _ => panic!("Wrong pwhash strenght string"),
        }
    }
}

#[derive(Clone)]
pub struct Nesting(u8);
impl Default for Nesting {
    fn default() -> Self {
        Nesting(2)
    }
}

impl Nesting {
    pub fn to_config(&self) -> config::Nesting {
        config::Nesting(self.0)
    }
}

#[derive(Clone)]
pub enum Hashing {
    Sha256,
    Blake2b,
}

impl Hashing {
    pub fn to_config(&self) -> config::Hashing {
        match *self {
            Hashing::Sha256 => config::Hashing::Sha256,
            Hashing::Blake2b => config::Hashing::Blake2b,
        }
    }
}

impl Default for Hashing {
    fn default() -> Self {
        Hashing::Blake2b
    }
}

#[derive(Clone, Default)]
pub struct Repo {
    pub(crate) pwhash: PWHash,
    pub(crate) encryption: Encryption,
    pub(crate) compression: Compression,
    pub(crate) compression_level: i32,
    pub(crate) chunking: Chunking,
    pub(crate) nesting: Nesting,
    pub(crate) hashing: Hashing,
}

impl Repo {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_encryption(&mut self, encryption: Encryption) -> io::Result<()> {
        self.encryption = encryption;
        Ok(())
    }

    pub fn set_compression(
        &mut self,
        compression: Compression,
    ) -> io::Result<()> {
        self.compression = compression;
        Ok(())
    }

    pub fn set_pwhash(&mut self, pwhash: PWHash) {
        self.pwhash = pwhash;
    }

    pub fn set_compression_level(&mut self, level: i32) {
        self.compression_level = level;
    }

    pub fn set_hashing(&mut self, hashing: Hashing) -> io::Result<()> {
        self.hashing = hashing;
        Ok(())
    }

    pub fn use_bup_chunking(&mut self, bits: Option<u32>) -> super::Result<()> {
        let bits = bits.unwrap_or(config::DEFAULT_BUP_CHUNK_BITS);
        let chunking = config::Chunking::Bup { chunk_bits: bits };

        if !chunking.valid() {
            return Err(super::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid chunking algorithm defined",
            ));
        }
        self.chunking = Chunking(chunking);
        Ok(())
    }

    pub fn use_fastcdc_chunking(
        &mut self,
        bits: Option<u32>,
    ) -> super::Result<()> {
        let bits = bits.unwrap_or(config::DEFAULT_BUP_CHUNK_BITS);
        let chunking = config::Chunking::FastCDC { chunk_bits: bits };

        if !chunking.valid() {
            return Err(super::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid chunking algorithm defined",
            ));
        }
        self.chunking = Chunking(chunking);
        Ok(())
    }

    pub fn use_gear_chunking(
        &mut self,
        bits: Option<u32>,
    ) -> super::Result<()> {
        let bits = bits.unwrap_or(config::DEFAULT_BUP_CHUNK_BITS);
        let chunking = config::Chunking::Gear { chunk_bits: bits };

        if !chunking.valid() {
            return Err(super::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid chunking algorithm defined",
            ));
        }
        self.chunking = Chunking(chunking);
        Ok(())
    }

    pub fn set_nesting(&mut self, level: u8) -> super::Result<()> {
        if level > 31 {
            return Err(super::Error::new(
                io::ErrorKind::InvalidInput,
                "nesting can't be greater than or equal to 32",
            ));
        }
        self.nesting = Nesting(level);
        Ok(())
    }
}
