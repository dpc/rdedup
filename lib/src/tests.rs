mod lib {
    pub use super::super::*;
}

use std::path;
use std::io;
use rand::{self, Rng};
use serialize::hex::ToHex;
use crypto::sha2;
use crypto::digest::Digest;

fn rand_tmp_dir() -> path::PathBuf {
    // TODO: Use $TMP or something?
    path::PathBuf::from("/tmp")
        .join(rand::thread_rng()
              .gen_ascii_chars()
              .take(20)
              .collect::<String>())
}

fn rand_data(len : usize) -> Vec<u8> {
    rand::thread_rng()
        .gen_iter()
        .take(len)
        .collect::<Vec<u8>>()
}

#[test]
fn zero_size() {
    let (repo, sk) = lib::Repo::init(&rand_tmp_dir()).unwrap();

    let zero = Vec::new();
    repo.write("zero", &mut io::Cursor::new(zero)).unwrap();

    let mut read_zero = Vec::new();
    repo.read("zero", &mut read_zero, &sk).unwrap();

    assert_eq!(read_zero.len(), 0);
}


#[test]
fn byte_size() {
    let (repo, sk) = lib::Repo::init(&rand_tmp_dir()).unwrap();
    // TODO: Make inclusive
    for b in 0u8 .. 255 {
        let data = vec!(b);
        let name = data.to_hex();
        repo.write(&name, &mut io::Cursor::new(&data)).unwrap();
    }
    for b in 0u8..255 {
        let mut data = Vec::new();
        let name = vec!(b).to_hex();
        repo.read(&name, &mut data, &sk).unwrap();
        assert_eq!(data, vec!(b));
    }
}

#[test]
fn random_sanity() {
    let mut stored = vec!();

    let (repo, sk) = lib::Repo::init(&rand_tmp_dir()).unwrap();
    for _ in 0..50 {
        let data = rand_data(rand::thread_rng().gen_range(0, 1024 * 1024));

        let mut sha = sha2::Sha256::new();
        sha.input(&data);
        let name = sha.result_str();
        let mut digest = vec![0u8; 32];
        sha.result(&mut digest);
        println!("Writing {}", name);
        repo.write(&name, &mut io::Cursor::new(data)).unwrap();
        stored.push((name, digest));
    }

    for &(ref name, ref digest) in &stored {
        let mut data = vec!();
        println!("Reading {}", name);
        repo.read(&name, &mut data, &sk).unwrap();

        let mut sha = sha2::Sha256::new();
        sha.input(&data);
        let mut read_digest = vec![0u8; 32];
        sha.result(&mut read_digest);
        assert_eq!(digest, &read_digest);
    }
}
