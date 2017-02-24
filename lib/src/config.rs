//! Repository config and metadata


use {base64, serde_yaml};
use serde::{self, Deserialize};
use serialize::hex::ToHex;

use sodiumoxide::crypto::{pwhash, secretbox, box_};
use std::{io, fs};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const REPO_VERSION_LOWEST: u32 = 0;
pub const REPO_VERSION_CURRENT: u32 = 1;

pub const DATA_SUBDIR: &'static str = "chunk";
pub const NAME_SUBDIR: &'static str = "name";
pub const INDEX_SUBDIR: &'static str = "index";

pub const LOCK_FILE: &'static str = ".lock";
pub const PUBKEY_FILE: &'static str = "pub_key";
pub const SECKEY_FILE: &'static str = "sec_key";
pub const VERSION_FILE: &'static str = "version";
pub const CONFIG_YML_FILE: &'static str = "config.yml";

pub fn lock_file_path(path: &Path) -> PathBuf {
    path.join(LOCK_FILE)
}

pub fn pub_key_file_path(path: &Path) -> PathBuf {
    path.join(PUBKEY_FILE)
}

pub fn sec_key_file_path(path: &Path) -> PathBuf {
    path.join(SECKEY_FILE)
}

pub fn version_file_path(path: &Path) -> PathBuf {
    path.join(VERSION_FILE)
}

pub fn config_yml_file_path(path: &Path) -> PathBuf {
    path.join(CONFIG_YML_FILE)
}

pub fn write_seckey_file(path: &Path,
                         encrypted_seckey: &[u8],
                         nonce: &secretbox::Nonce,
                         salt: &pwhash::Salt)
                         -> io::Result<()> {
    let mut seckey_file = fs::File::create(path)?;
    let mut writer = &mut seckey_file as &mut Write;
    writer.write_all(encrypted_seckey.to_hex().as_bytes())?;
    writer.write_all(nonce.0.to_hex().as_bytes())?;
    writer.write_all(salt.0.to_hex().as_bytes())?;
    writer.flush()?;
    Ok(())
}

pub fn write_version_file(repo_path: &Path, version: u32) -> super::Result<()> {
    let path = version_file_path(repo_path);
    let path_tmp = path.with_extension("tmp");
    let mut file = fs::File::create(&path_tmp)?;
    {
        let mut writer = &mut file as &mut Write;
        write!(writer, "{}", version)?;
    }

    file.flush()?;
    file.sync_data()?;

    fs::rename(path_tmp, &path)?;

    Ok(())
}

pub fn write_config_v0(repo_path: &Path,
                       pk: box_::PublicKey,
                       sk: box_::SecretKey,
                       passphrase: &str)
                       -> super::Result<()> {
    {
        let pubkey_path = pub_key_file_path(repo_path);

        let mut pubkey_file = fs::File::create(pubkey_path)?;


        (&mut pubkey_file as &mut Write).write_all(pk.0.to_hex().as_bytes())?;
        pubkey_file.flush()?;
    }
    {
        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();

        let derived_key = super::derive_key(passphrase, &salt)?;

        let encrypted_seckey = secretbox::seal(&sk.0, &nonce, &derived_key);

        let seckey_path = sec_key_file_path(repo_path);
        write_seckey_file(&seckey_path, &encrypted_seckey, &nonce, &salt)?;
    }
    write_version_file(repo_path, 0)?;

    Ok(())
}

pub fn write_config_v1(repo_path: &Path,
                       pk: &box_::PublicKey,
                       sk: &box_::SecretKey,
                       passphrase: &str,
                       chunking: ChunkingAlgorithm)
                       -> super::Result<()> {

    let salt = pwhash::gen_salt();
    let nonce = secretbox::gen_nonce();

    let sealed_sk = {
        let derived_key = super::derive_key(passphrase, &salt)?;

        secretbox::seal(&sk.0, &nonce, &derived_key)
    };

    let config = Repo {
        version: 1,
        encryption: Encryption::Curve25519(Curve25519 {
            sealed_sec_key: sealed_sk,
            pub_key: *pk,
            nonce: nonce,
            salt: salt,
        }),
        chunking: Some(chunking),
    };

    let config_str = serde_yaml::to_string(&config)
        .expect("yaml serialization failed");

    let config_path = config_yml_file_path(repo_path);
    let config_path_tmp = config_path.with_extension("tmp");
    let mut config_file = fs::File::create(&config_path_tmp)?;


    (&mut config_file as &mut Write).write_all(config_str.as_bytes())?;
    config_file.flush()?;
    config_file.sync_data()?;

    fs::rename(config_path_tmp, &config_path)?;

    write_version_file(repo_path, REPO_VERSION_CURRENT)?;

    Ok(())
}

trait MyTryFromBytes: Sized {
    type Err: 'static + Sized + ::std::error::Error;
    fn try_from(&[u8]) -> Result<Self, Self::Err>;
}

impl MyTryFromBytes for box_::PublicKey {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        box_::PublicKey::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive PublicKey from invalid binary data")
        })
    }
}

impl MyTryFromBytes for secretbox::Nonce {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        secretbox::Nonce::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive Nonce from invalid binary data")
        })
    }
}

impl MyTryFromBytes for pwhash::Salt {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        pwhash::Salt::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive Nonce from invalid binary data")
        })
    }
}

impl MyTryFromBytes for Vec<u8> {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        Ok(Vec::from(slice))
    }
}

fn from_base64<T, D>(deserializer: D) -> Result<T, D::Error>
    where D: serde::Deserializer,
          T: MyTryFromBytes
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
            base64::decode(&string)
                .map_err(|err| Error::custom(err.to_string()))
        })
        .and_then(|ref bytes| {
            T::try_from(bytes).map_err(|err| {
                Error::custom(format!("{}", &err as &::std::error::Error))
            })
        })
}

fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: AsRef<[u8]>,
          S: serde::Serializer
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}


/// Configuration of repository encryption
#[derive(Serialize, Deserialize)]
pub struct Curve25519 {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub sealed_sec_key: Vec<u8>,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub pub_key: box_::PublicKey,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub salt: pwhash::Salt,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub nonce: secretbox::Nonce,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
/// `ChunkingAlgorithm` are the algorithms supported by rdedup
pub enum ChunkingAlgorithm {
    /// `Bup` is the default algorithm, the chunk_bits value provided with bup
    /// is the bit shift to be used by rollsum. The valid range is between 10
    /// and 30 (1KB to 1GB)
    #[serde(rename = "bup")]
    Bup { chunk_bits: u32 },
}
/// Default implementation for the ```ChunkingAlgorithm```
impl Default for ChunkingAlgorithm {
    fn default() -> ChunkingAlgorithm {
        ChunkingAlgorithm::Bup { chunk_bits: 17 }
    }
}

impl ChunkingAlgorithm {
    pub fn valid(self) -> bool {
        match self {
            ChunkingAlgorithm::Bup { chunk_bits: bits } => {
                30 >= bits && bits >= 10
            }
        }
    }
}

/// Types of supported encryption
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Encryption {
    /// No encryption
    #[serde(rename = "none")]
    None,
    /// `Curve25519Blake2BSalsa20Poly1305`
    #[serde(rename = "curve25519_blake2b_salsa20_poly1305")]
    Curve25519(Curve25519),
}

/// Rdedup repository configuration
///
/// This datastructure is used for serialization and deserialization
/// of repo configuration that is stored as a repostiory metadata.
#[derive(Serialize, Deserialize)]
pub struct Repo {
    pub version: u32,
    pub chunking: Option<ChunkingAlgorithm>,
    pub encryption: Encryption,
}
