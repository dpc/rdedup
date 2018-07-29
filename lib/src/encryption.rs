use hex;
use pwhash::PWHash;
use PassphraseFn;
use {as_base64, box_, from_base64, pwhash, secretbox};

use sgdata::SGData;

use config;
use std::io;
use std::sync::Arc;

pub type ArcEncrypter = Arc<Encrypter + Send + Sync>;
pub type ArcDecrypter = Arc<Decrypter + Send + Sync>;

pub(crate) trait EncryptionEngine {
    fn change_passphrase(
        &mut self,
        old_p: PassphraseFn,
        new_p: PassphraseFn,
        pwhash: &config::PWHash,
    ) -> io::Result<()>;

    fn encrypter(
        &self,
        passphrase_f: PassphraseFn,
        pwhash: &config::PWHash,
    ) -> io::Result<ArcEncrypter>;
    fn decrypter(
        &self,
        passphrase_f: PassphraseFn,

        pwhash: &config::PWHash,
    ) -> io::Result<ArcDecrypter>;
}

pub trait Encrypter {
    fn encrypt(&self, buf: SGData, digest: &[u8]) -> super::Result<SGData>;
}

pub trait Decrypter {
    fn decrypt(&self, buf: SGData, digest: &[u8]) -> io::Result<SGData>;
}

pub struct NopEncrypter;

impl Encrypter for NopEncrypter {
    fn encrypt(&self, buf: SGData, _digest: &[u8]) -> io::Result<SGData> {
        Ok(buf)
    }
}

pub struct NopDecrypter;

impl Decrypter for NopDecrypter {
    fn decrypt(&self, buf: SGData, _digest: &[u8]) -> io::Result<SGData> {
        Ok(buf)
    }
}

/// Configuration of repository encryption
#[derive(Serialize, Deserialize, Clone)]
pub struct Curve25519 {
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    pub sealed_sec_key: Vec<u8>,
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    pub pub_key: box_::PublicKey,
    #[serde(
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    pub nonce: secretbox::Nonce,
}

impl Curve25519 {
    pub(crate) fn new(
        passphrase_f: PassphraseFn,
        pwhash: &pwhash::PWHash,
    ) -> super::Result<Self> {
        let (pk, sk) = box_::gen_keypair();
        let passphrase = passphrase_f()?;

        let nonce = secretbox::gen_nonce();

        let sealed_sk = {
            let derived_key = secretbox::Key::from_slice(
                &pwhash.derive_key(&passphrase)?[..32],
            ).unwrap();

            secretbox::seal(&sk.0, &nonce, &derived_key)
        };

        Ok(Curve25519 {
            sealed_sec_key: sealed_sk,
            pub_key: pk,
            nonce: nonce,
        })
    }

    fn unseal_decrypt(
        &self,
        passphrase_f: &Fn() -> io::Result<String>,
        pwhash: &config::PWHash,
    ) -> io::Result<box_::SecretKey> {
        let passphrase = passphrase_f()?;

        let derived_key = secretbox::Key::from_slice(
            &pwhash.derive_key(&passphrase)?[..32],
        ).unwrap();
        let plain_seckey =
            secretbox::open(&self.sealed_sec_key, &self.nonce, &derived_key)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "can't decrypt key using given passphrase",
                    )
                })?;

        Ok(box_::SecretKey::from_slice(&plain_seckey).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "plain secret key in a wrong format",
            )
        })?)
    }

    fn unseal_encrypt(&self) -> super::Result<box_::PublicKey> {
        Ok(self.pub_key)
    }
}

impl EncryptionEngine for Curve25519 {
    fn change_passphrase(
        &mut self,
        old_p: PassphraseFn,
        new_p: PassphraseFn,
        pwhash: &config::PWHash,
    ) -> io::Result<()> {
        let sec_key = self.unseal_decrypt(old_p, pwhash)?;

        let new_passphrase = new_p()?;

        let sealed_sk = {
            let derived_key = secretbox::Key::from_slice(
                &pwhash.derive_key(&new_passphrase)?[..32],
            ).unwrap();
            secretbox::seal(&sec_key.0, &self.nonce, &derived_key)
        };

        self.sealed_sec_key = sealed_sk;

        Ok(())
    }
    fn encrypter(
        &self,
        _pass: PassphraseFn,
        _pwhash: &config::PWHash,
    ) -> io::Result<ArcEncrypter> {
        let key = self.unseal_encrypt()?;

        Ok(Arc::new(Curve25519Encrypter { pub_key: key }))
    }
    fn decrypter(
        &self,
        pass: &Fn() -> io::Result<String>,
        pwhash: &config::PWHash,
    ) -> io::Result<ArcDecrypter> {
        let key = self.unseal_decrypt(pass, pwhash)?;
        Ok(Arc::new(Curve25519Decrypter { sec_key: key }))
    }
}

struct Curve25519Encrypter {
    pub_key: box_::PublicKey,
}

impl Encrypter for Curve25519Encrypter {
    fn encrypt(&self, buf: SGData, digest: &[u8]) -> super::Result<SGData> {
        let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES])
            .expect("Nonce::from_slice failed");

        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
        let cipher =
            box_::seal(&buf.to_linear(), &nonce, &self.pub_key, &ephemeral_sec);
        Ok(SGData::from_many(vec![ephemeral_pub.0.to_vec(), cipher]))
    }
}

struct Curve25519Decrypter {
    sec_key: box_::SecretKey,
}
impl Decrypter for Curve25519Decrypter {
    fn decrypt(&self, buf: SGData, digest: &[u8]) -> io::Result<SGData> {
        let nonce =
            box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES]).unwrap();

        let buf = buf.to_linear();

        if buf.len() < box_::PUBLICKEYBYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "chunk {} too short to even contain a public key",
                    hex::encode(digest)
                ),
            ));
        }

        let ephemeral_pub = box_::PublicKey::from_slice(
            &buf[..box_::PUBLICKEYBYTES],
        ).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Can't read ephemeral public key from chunk: {}",
                    hex::encode(digest)
                ),
            )
        })?;

        Ok(SGData::from_single(
            box_::open(
                &buf[box_::PUBLICKEYBYTES..],
                &nonce,
                &ephemeral_pub,
                &self.sec_key,
            ).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("can't decrypt chunk: {}", hex::encode(digest)),
                )
            })?,
        ))
    }
}
