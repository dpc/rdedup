use std::io;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::PassphraseFn;
use crate::{config, encryption};

/// Types of supported encryption
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub(crate) enum Encryption {
    /// No encryption
    #[serde(rename = "none")]
    None,
    /// `Curve25519Blake2BSalsa20Poly1305`
    #[serde(rename = "curve25519_blake2b_salsa20_poly1305")]
    Curve25519(encryption::Curve25519),
}

impl encryption::EncryptionEngine for Encryption {
    fn change_passphrase(
        &mut self,
        old_p: PassphraseFn<'_>,
        new_p: PassphraseFn<'_>,
        pwhash: &config::PWHash,
    ) -> io::Result<()> {
        match *self {
            Encryption::None => Ok(()),
            Encryption::Curve25519(ref mut c) => {
                c.change_passphrase(old_p, new_p, pwhash)
            }
        }
    }

    fn encrypter(
        &self,
        pass: PassphraseFn<'_>,
        pwhash: &config::PWHash,
    ) -> io::Result<encryption::ArcEncrypter> {
        match *self {
            Encryption::None => Ok(Arc::new(encryption::NopEncrypter)),
            Encryption::Curve25519(ref c) => c.encrypter(pass, pwhash),
        }
    }
    fn decrypter(
        &self,
        pass: PassphraseFn<'_>,
        pwhash: &config::PWHash,
    ) -> io::Result<encryption::ArcDecrypter> {
        match *self {
            Encryption::None => Ok(Arc::new(encryption::NopDecrypter)),
            Encryption::Curve25519(ref c) => c.decrypter(pass, pwhash),
        }
    }
}
