use sodiumoxide::crypto::pwhash;
use std::io;
use util::{as_base64, from_base64};

pub(crate) trait PWHash {
    fn derive_key(&self, passphrase: &str) -> io::Result<Vec<u8>>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct SodiumOxide {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    salt: pwhash::Salt,
    #[serde(rename = "mem_limit")]
    mem_limit: u64,
    #[serde(rename = "ops_limit")]
    ops_limit: u64,
}

impl SodiumOxide {
    pub(crate) fn new_weak() -> Self {
        Self {
            ops_limit: 0,
            mem_limit: 0,
            salt: pwhash::gen_salt(),
        }
    }

    pub(crate) fn new_interactive() -> Self {
        Self {
            ops_limit: pwhash::OPSLIMIT_INTERACTIVE.0 as u64,
            mem_limit: pwhash::MEMLIMIT_INTERACTIVE.0 as u64,
            salt: pwhash::gen_salt(),
        }
    }

    pub(crate) fn new_sensitive() -> Self {
        Self {
            ops_limit: pwhash::OPSLIMIT_SENSITIVE.0 as u64,
            mem_limit: pwhash::MEMLIMIT_SENSITIVE.0 as u64,
            salt: pwhash::gen_salt(),
        }
    }
}

impl Default for SodiumOxide {
    fn default() -> Self {
        SodiumOxide {
            ops_limit: pwhash::OPSLIMIT_SENSITIVE.0 as u64,
            mem_limit: pwhash::MEMLIMIT_SENSITIVE.0 as u64,
            salt: pwhash::gen_salt(),
        }
    }
}

impl PWHash for SodiumOxide {
    /// Derive secret key from passphrase and salt
    fn derive_key(&self, passphrase: &str) -> io::Result<Vec<u8>> {
        let mut key = vec![0; 32];

        pwhash::derive_key(
            &mut key,
            passphrase.as_bytes(),
            &self.salt,
            pwhash::OpsLimit(self.ops_limit as usize),
            pwhash::MemLimit(self.mem_limit as usize),
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "can't derive encryption key from passphrase",
            )
        })?;

        Ok(key)
    }
}
