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


/// Writer that counts how many bytes were written to it
pub struct CounterWriter {
    pub count: u64,
}

impl CounterWriter {
    pub fn new() -> Self {
        CounterWriter { count: 0 }
    }
}

impl io::Write for CounterWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
