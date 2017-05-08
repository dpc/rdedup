//! Settings: options that user can pick

use config;
use std::io;

#[derive(Clone)]
pub enum Compression {
    Deflate,
    None,
}

impl Default for Compression {
    fn default() -> Self {
        Compression::Deflate
    }
}

impl Compression {
    pub fn to_config(&self) -> config::Compression {
        match *self {
            Compression::Deflate => config::Compression::Deflate,
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

#[derive(Clone, Default)]
pub struct Repo {
    pub(crate) encryption: Encryption,
    pub(crate) compression: Compression,
    pub(crate) chunking: Chunking,
}

impl Repo {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_encryption(&mut self, encryption: Encryption) -> io::Result<()> {

        self.encryption = encryption;
        Ok(())
    }

    pub fn set_compression(&mut self,
                           compression: Compression)
                           -> io::Result<()> {
        self.compression = compression;
        Ok(())
    }

    pub fn use_bup_chunking(&mut self, bits: Option<u32>) -> super::Result<()> {
        let bits = bits.unwrap_or(config::DEFAULT_BUP_CHUNK_BITS);
        let bup = config::Chunking::Bup { chunk_bits: bits };

        if !bup.valid() {
            return Err(super::Error::new(io::ErrorKind::InvalidInput,
                                         "invalid chunking algorithm defined"));
        }
        self.chunking = Chunking(bup);
        Ok(())
    }
}
