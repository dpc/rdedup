//! Config: options de/serialized to files
//! from `settings`

use {serde_yaml, PassphraseFn};

use encryption;
use encryption::{ArcDecrypter, ArcEncrypter};
use hex::ToHex;
use settings;

use sodiumoxide::crypto::{pwhash, secretbox};
use std::{io, fs};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

pub const DEFAULT_BUP_CHUNK_BITS: u32 = 17;

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

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
/// `Chunking` are the algorithms supported by rdedup
pub enum Chunking {
    /// `Bup` is the default algorithm, the chunk_bits value provided with bup
    /// is the bit shift to be used by rollsum. The valid range is between 10
    /// and 30 (1KB to 1GB)
    #[serde(rename = "bup")]
    Bup { chunk_bits: u32 },
}

/// Default implementation for the `Chunking`
impl Default for Chunking {
    fn default() -> Chunking {
        Chunking::Bup { chunk_bits: DEFAULT_BUP_CHUNK_BITS }
    }
}

impl Chunking {
    pub fn valid(self) -> bool {
        match self {
            Chunking::Bup { chunk_bits: bits } => 30 >= bits && bits >= 10,
        }
    }
}

/// Types of supported encryption
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Encryption {
    /// No encryption
    #[serde(rename = "none")]
    None,
    /// `Curve25519Blake2BSalsa20Poly1305`
    #[serde(rename = "curve25519_blake2b_salsa20_poly1305")]
    Curve25519(encryption::Curve25519),
}

impl encryption::EncryptionEngine for Encryption {
    fn change_passphrase(&mut self,
                         old_p: PassphraseFn,
                         new_p: PassphraseFn)
                         -> io::Result<()> {
        match *self {
            Encryption::None => Ok(()),
            Encryption::Curve25519(ref mut c) => {
                c.change_passphrase(old_p, new_p)
            }
        }

    }

    fn encrypter(&self, pass: PassphraseFn) -> io::Result<ArcEncrypter> {

        match *self {
            Encryption::None => Ok(Arc::new(encryption::NopEncrypter)),
            Encryption::Curve25519(ref c) => c.encrypter(pass),
        }

    }
    fn decrypter(&self, pass: PassphraseFn) -> io::Result<ArcDecrypter> {

        match *self {
            Encryption::None => Ok(Arc::new(encryption::NopDecrypter)),
            Encryption::Curve25519(ref c) => c.decrypter(pass),
        }
    }
}

/// Rdedup repository configuration
///
/// This datastructure is used for serialization and deserialization
/// of repo configuration that is stored as a repostiory metadata.
#[derive(Serialize, Deserialize, Clone)]
pub struct Repo {
    pub version: u32,
    #[serde(default)]
    pub chunking: Chunking,
    pub encryption: Encryption,
}


impl Repo {
    pub fn new_from_settings(pass: PassphraseFn,
                             settings: settings::Repo)
                             -> io::Result<Self> {

        let encryption = match settings.encryption {
            settings::Encryption::Curve25519 => {
                Encryption::Curve25519(encryption::Curve25519::new(pass)?)
            }
            settings::Encryption::None => Encryption::None,
        };

        Ok(Repo {
               version: REPO_VERSION_CURRENT,
               chunking: settings.chunking.0,
               encryption: encryption,
           })

    }


    pub fn write(&self, repo_path: &Path) -> super::Result<()> {

        let config_str =
            serde_yaml::to_string(self).expect("yaml serialization failed");

        let config_path = config_yml_file_path(repo_path);
        let config_path_tmp = config_path.with_extension("tmp");
        let mut config_file = fs::File::create(&config_path_tmp)?;


        (&mut config_file as &mut Write)
            .write_all(config_str.as_bytes())?;
        config_file.flush()?;
        config_file.sync_data()?;

        fs::rename(config_path_tmp, &config_path)?;

        write_version_file(repo_path, REPO_VERSION_CURRENT)?;

        Ok(())
    }
}
