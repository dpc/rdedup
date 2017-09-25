use sodiumoxide::crypto::{pwhash, secretbox};
use std::io;

/// Derive secret key from passphrase and salt
pub fn derive_key(
    passphrase: &str,
    salt: &pwhash::Salt,
) -> io::Result<secretbox::Key> {
    let mut derived_key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = derived_key;
        pwhash::derive_key(
            kb,
            passphrase.as_bytes(),
            salt,
            pwhash::OPSLIMIT_SENSITIVE,
            pwhash::MEMLIMIT_SENSITIVE,
        ).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "can't derive encryption key from passphrase",
            )
        })?;
    }

    Ok(derived_key)
}
