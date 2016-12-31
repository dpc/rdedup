//! Repository config and metadata

use std::{io, fs};
use std::io::Write;
use std::path::{Path, PathBuf};

use sodiumoxide::crypto::{pwhash, secretbox, box_};
use serialize::hex::{ToHex};

use base64;
use serde::{self, Deserialize};

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
    writer.write_all(&encrypted_seckey.to_hex().as_bytes())?;
    writer.write_all(&nonce.0.to_hex().as_bytes())?;
    writer.write_all(&salt.0.to_hex().as_bytes())?;
    writer.flush()?;
    Ok(())
}

trait MyTryFromBytes : Sized {
    type Err : 'static + Sized + ::std::error::Error;
    fn try_from(&[u8]) -> Result<Self, Self::Err>;
}

impl MyTryFromBytes for box_::PublicKey {
    type Err = io::Error;
    fn try_from(slice : &[u8]) -> Result<Self, Self::Err> {
        box_::PublicKey::from_slice(slice).ok_or(
            io::Error::new(io::ErrorKind::InvalidData, "can't derive PublicKey from invalid binary data")
            )
    }
}

impl MyTryFromBytes for secretbox::Nonce {
    type Err = io::Error;
    fn try_from(slice : &[u8]) -> Result<Self, Self::Err> {
        secretbox::Nonce::from_slice(slice).ok_or(
            io::Error::new(io::ErrorKind::InvalidData, "can't derive Nonce from invalid binary data")
            )
    }
}

impl MyTryFromBytes for pwhash::Salt {
    type Err = io::Error;
    fn try_from(slice : &[u8]) -> Result<Self, Self::Err> {
        pwhash::Salt::from_slice(slice).ok_or(
            io::Error::new(io::ErrorKind::InvalidData, "can't derive Nonce from invalid binary data")
            )
    }
}

fn from_base64<'a, T, D>(deserializer: &mut D) -> Result<T, D::Error>
where D: serde::Deserializer,
      T: MyTryFromBytes,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|ref bytes| T::try_from(bytes).map_err(|err| Error::custom(format!("{}", &err as &::std::error::Error))))
}

fn as_base64<T, S>(key: &T, serializer: &mut S) -> Result<(), S::Error>
    where T: AsRef<[u8]>,
          S: serde::Serializer
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}


#[derive(Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub sealed_sec_key: Vec<u8>,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub pub_key: box_::PublicKey,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub salt: pwhash::Salt,
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub nonce: secretbox::Nonce,
}

#[derive(Serialize, Deserialize)]
pub struct RepoConfig {
    pub version : u32,
    pub encryption: Option<EncryptionConfig>,
}
