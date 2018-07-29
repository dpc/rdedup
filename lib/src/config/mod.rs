//! Config: options de/serialized to files
//! from `settings`.

// {{{ use and mod
use {serde_yaml, PassphraseFn, SGData};

use aio;
use pwhash;

use hashing;

use hex;
use settings;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod chunking;
mod compression;
mod encryption;

pub(crate) use self::chunking::*;
pub(crate) use self::compression::*;
pub(crate) use self::encryption::*;
// }}}

pub const REPO_VERSION_LOWEST: u32 = 3;
pub const REPO_VERSION_CURRENT: u32 = 3;

pub const DATA_SUBDIR: &'static str = "chunk";
pub const LOCK_FILE: &'static str = ".lock";
pub const CONFIG_YML_FILE: &'static str = "config.yml";

// {{{ PWHash
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
/// `PWHash` is algorithm used to derive the secret key from
/// passphrase to unlock the sealed encryption key(s)
pub(crate) enum PWHash {
    #[serde(rename = "scryptsalsa208sha256")]
    SodiumOxide(pwhash::SodiumOxide),
}

impl Default for PWHash {
    fn default() -> PWHash {
        PWHash::SodiumOxide(Default::default())
    }
}

impl PWHash {
    fn from_settings(pwhash: settings::PWHash) -> Self {
        match pwhash {
            settings::PWHash::Weak => {
                PWHash::SodiumOxide(pwhash::SodiumOxide::new_weak())
            }
            settings::PWHash::Interactive => {
                PWHash::SodiumOxide(pwhash::SodiumOxide::new_interactive())
            }
            settings::PWHash::Strong => {
                PWHash::SodiumOxide(pwhash::SodiumOxide::new_sensitive())
            }
        }
    }
}

impl pwhash::PWHash for PWHash {
    fn derive_key(&self, passphrase: &str) -> io::Result<Vec<u8>> {
        match *self {
            PWHash::SodiumOxide(ref so) => so.derive_key(passphrase),
        }
    }
}
// }}}

// {{{ Hashing
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Hashing {
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "blake2b")]
    Blake2b,
}

impl Default for Hashing {
    fn default() -> Hashing {
        Hashing::Sha256
    }
}

impl Hashing {
    pub(crate) fn to_hasher(&self) -> hashing::ArcHasher {
        match *self {
            Hashing::Sha256 => Arc::new(hashing::Sha256),
            Hashing::Blake2b => Arc::new(hashing::Blake2b),
        }
    }
}
// }}}

// {{{ Nesting
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct Nesting(pub u8);
impl Default for Nesting {
    fn default() -> Self {
        Nesting(2)
    }
}

impl Nesting {
    pub fn get_path(
        &self,
        base: &Path,
        digest: &[u8],
        gen_str: &str,
    ) -> PathBuf {
        let hex_digest = hex::encode(&digest);
        let mut dir = PathBuf::from(gen_str);
        dir.push(base);
        let levels = self.clone().0;
        if levels > 0 {
            for i in 0..levels {
                let start = i as usize * 2;
                let end = start + 2;
                dir = dir.join(&hex_digest[start..end]);
            }
        }
        dir.join(&hex_digest)
    }
}
// }}}

// {{{ Repo
/// Rdedup repository configuration
///
/// This datastructure is used for serialization and deserialization
/// of repo configuration that is stored as a repostiory metadata.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Repo {
    pub version: u32,
    #[serde(default)]
    pub pwhash: PWHash,
    #[serde(default)]
    pub chunking: Chunking,
    #[serde(default)]
    pub hashing: Hashing,
    #[serde(default)]
    pub compression: Compression,
    pub encryption: Encryption,
    #[serde(default)]
    pub nesting: Nesting,
}

impl Repo {
    pub fn new_from_settings(
        pass: PassphraseFn,
        settings: settings::Repo,
    ) -> io::Result<Self> {
        let pwhash = PWHash::from_settings(settings.pwhash);
        let encryption = match settings.encryption {
            settings::Encryption::Curve25519 => Encryption::Curve25519(
                ::encryption::Curve25519::new(pass, &pwhash)?,
            ),
            settings::Encryption::None => Encryption::None,
        };

        Ok(Repo {
            version: REPO_VERSION_CURRENT,
            pwhash: pwhash,
            chunking: settings.chunking.0,
            encryption: encryption,
            compression: settings
                .compression
                .to_config(settings.compression_level),
            nesting: settings.nesting.to_config(),
            hashing: settings.hashing.to_config(),
        })
    }

    pub fn write(&self, aio: &aio::AsyncIO) -> super::Result<()> {
        let config_str =
            serde_yaml::to_string(self).expect("yaml serialization failed");

        aio.write(
            CONFIG_YML_FILE.into(),
            SGData::from_single(config_str.into_bytes()),
        ).wait()?;

        Ok(())
    }

    pub fn read(aio: &aio::AsyncIO) -> io::Result<Self> {
        let config_data = aio.read(CONFIG_YML_FILE.into()).wait()?;
        let config_data = config_data.to_linear_vec();

        let config: Repo = serde_yaml::from_reader(config_data.as_slice())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("couldn't parse yaml: {}", e.to_string()),
                )
            })?;

        check_version(config.version)?;

        Ok(config)
    }
}

fn check_version(version_int: u32) -> io::Result<()> {
    if version_int > REPO_VERSION_CURRENT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "repo version {} higher than \
                 supported {}; update?",
                version_int, REPO_VERSION_CURRENT
            ),
        ));
    }
    // This if statement triggers the absurd_extreme_comparisons because the
    // minimum repo version is also the smallest value of a u32
    if version_int < REPO_VERSION_LOWEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "repo version {} lower than \
                 lowest supported {}; \
                 restore using older version?",
                version_int, REPO_VERSION_LOWEST
            ),
        ));
    }

    Ok(())
}
// }}}
// vim: foldmethod=marker foldmarker={{{,}}}
