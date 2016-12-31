//! Repository config and metadata

use std::{io, fs};
use std::io::Write;
use std::path::{Path, PathBuf};

use sodiumoxide::crypto::{pwhash, secretbox};
use serialize::hex::{ToHex};

pub const REPO_VERSION_LOWEST: u32 = 0;
pub const REPO_VERSION_CURRENT: u32 = 0;

pub const DATA_SUBDIR: &'static str = "chunk";
pub const LOCK_FILE: &'static str = ".lock";
pub const PUBKEY_FILE: &'static str = "pub_key";
pub const SECKEY_FILE: &'static str = "sec_key";
pub const VERSION_FILE: &'static str = "version";
pub const NAME_SUBDIR: &'static str = "name";
pub const INDEX_SUBDIR: &'static str = "index";

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


