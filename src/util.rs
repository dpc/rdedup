use rpassword;
use std::{env, io};
use std::str::FromStr;

/// Parse human-readable size string
///
/// Takes a string representing a size in bytes like "192k" or "192K" and turns
/// it into a `u64`.
pub fn parse_size(input: &str) -> Option<u64> {
    let input = input.to_uppercase();

    if input.contains('.') {
        return None;
    }

    let units = ["K", "M", "G", "T", "P", "E"];
    let unit = input.matches(char::is_alphabetic).next();
    let str_size: String = input.matches(char::is_numeric).collect();

    let mut size = if !str_size.is_empty() {
        match u64::from_str(str_size.as_str()) {
            Ok(s) => s,
            Err(_) => return None,
        }
    } else {
        return None;
    };

    if let Some(unit) = unit {
        if let Some(idx) = units.iter().position(|&u| u == unit) {
            let modifier: u64 = 1024u64.pow(idx as u32 + 1);
            size *= modifier;
        } else {
            return None;
        }
    }
    Some(size)
}

#[test]
fn test_parse_size() {
    // tuples that are str, expected Option<u64>
    let tests = [
        ("192K", Some(192 * 1024)),
        ("1M", Some(1024u64.pow(2))),
        ("Hello", None),
        ("12345.6789", None),
        ("1024B", None),
        ("1024A", None),
        ("1t", Some(1024u64.pow(4))),
        ("1E", Some(1024u64.pow(6))),
    ];

    for test in &tests {
        let result = parse_size(test.0);
        if result != test.1 {
            panic!("expected {:?}, got {:?}", test.1, result);
        }
    }
}

pub fn read_passphrase() -> io::Result<String> {
    // The environment variable should only be used for testing
    if let Ok(pass) = env::var("RDEDUP_PASSPHRASE") {
        eprint!("Using passphrase set in RDEDUP_PASSPHRASE\n");
        return Ok(pass);
    }
    eprint!("Enter passphrase to unlock: ");
    rpassword::read_password()
}

pub fn read_new_passphrase() -> io::Result<String> {
    // The environment variable should only be used for testing
    if let Ok(pass) = env::var("RDEDUP_PASSPHRASE") {
        eprint!("Using passphrase set in RDEDUP_PASSPHRASE\n");
        return Ok(pass);
    }
    loop {
        eprint!("Enter new passphrase: ");
        let p1 = rpassword::read_password()?;
        eprint!("Enter new passphrase again: ");
        let p2 = rpassword::read_password()?;
        if p1 == p2 {
            return Ok(p1);
        }
        eprintln!("\nPassphrases don't match, try again.");
    }
}
