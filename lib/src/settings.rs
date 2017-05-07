//! Settings: options that user can pick

use config;
use std::io;

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

    pub fn use_bup_chunking(&mut self, bits: u32) -> super::Result<()> {
        let bup = config::Chunking::Bup { chunk_bits: bits };

        if !bup.valid() {
            return Err(super::Error::new(io::ErrorKind::InvalidInput,
                                         "invalid chunking algorithm defined"));
        }
        self.chunking = Chunking(bup);
        Ok(())
    }
}
