mod lib {
    pub use super::super::*;
}

use std::path;
use std::fs;
use std::fs::OpenOptions;
use std::{io, cmp};
use std::io::Write;
use rand::{self, Rng};
use serialize::hex::ToHex;
use crypto::sha2;
use crypto::digest::Digest;

const PASS: &'static str = "FOO";

fn rand_tmp_dir() -> path::PathBuf {
    // TODO: Use $TMP or something?
    path::PathBuf::from("/tmp/rdedup-tests").join(rand::thread_rng()
        .gen_ascii_chars()
        .take(20)
        .collect::<String>())
}

/// Generate data that repease some chunks
struct ExampleDataGen {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    count: usize,
    sha: sha2::Sha256,
}

impl ExampleDataGen {
    fn new(kb: usize) -> Self {

        ExampleDataGen {
            a: rand_data(1024 * 2),
            b: rand_data(1024 * 2),
            c: rand_data(1024 * 2),
            count: kb,
            sha: sha2::Sha256::new(),
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut digest = vec![0u8; 32];
        self.sha.result(&mut digest);
        digest
    }
}

fn copy_as_much_as_possible(dst: &mut [u8], src: &[u8]) -> usize {
    let len = cmp::min(dst.len(), src.len());
    dst[..len].clone_from_slice(&src[..len]);
    len
}

impl io::Read for ExampleDataGen {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        self.count -= 1;

        let len = match rand::weak_rng().gen_range(0, 3) {
            0 => copy_as_much_as_possible(buf, &self.a),
            1 => copy_as_much_as_possible(buf, &self.b),
            2 => copy_as_much_as_possible(buf, &self.c),
            _ => panic!(),
        };

        self.sha.input(&buf[..len]);

        Ok(len)
    }
}

fn rand_data(len: usize) -> Vec<u8> {
    rand::weak_rng()
        .gen_iter()
        .take(len)
        .collect::<Vec<u8>>()
}

fn wipe(repo: &lib::Repo) {
    let names = repo.list_names().unwrap();

    for name in &names {
        repo.rm(&name).unwrap();
    }

    repo.gc().unwrap();

    assert_eq!(repo.list_stored_chunks().unwrap().len(), 0);
    assert_eq!(repo.list_reachable_chunks().unwrap().len(), 0);
}

#[test]
fn zero_size() {
    let repo = lib::Repo::init(&rand_tmp_dir(), PASS).unwrap();

    let seckey = repo.get_seckey(PASS).unwrap();

    let zero = Vec::new();
    repo.write("zero", &mut io::Cursor::new(zero)).unwrap();

    let mut read_zero = Vec::new();
    repo.read("zero", &mut read_zero, &seckey).unwrap();

    assert_eq!(read_zero.len(), 0);

    wipe(&repo);
}

#[test]
fn byte_size() {
    let repo = lib::Repo::init(&rand_tmp_dir(), PASS).unwrap();
    let seckey = repo.get_seckey(PASS).unwrap();
    let tests = [0u8, 1, 13, 255];
    for &b in &tests {
        let data = vec![b];
        let name = data.to_hex();
        repo.write(&name, &mut io::Cursor::new(&data)).unwrap();
    }
    for &b in &tests {
        let mut data = Vec::new();
        let name = vec![b].to_hex();
        repo.read(&name, &mut data, &seckey).unwrap();
        assert_eq!(data, vec![b]);
    }

    wipe(&repo);
}

#[test]
fn random_sanity() {
    let mut names = vec![];

    let repo = lib::Repo::init(&rand_tmp_dir(), PASS).unwrap();
    let seckey = repo.get_seckey(PASS).unwrap();
    for i in 0..10 {
        let mut data = ExampleDataGen::new(rand::weak_rng().gen_range(0, 10 * 1024));
        let name = format!("{:x}", i);
        repo.write(&name, &mut data).unwrap();
        names.push((name, data.finish()));
    }

    repo.gc().unwrap();

    for &(ref name, ref digest) in &names {
        let mut data = vec![];
        repo.read(&name, &mut data, &seckey).unwrap();

        let mut sha = sha2::Sha256::new();
        sha.input(&data);
        let mut read_digest = vec![0u8; 32];
        sha.result(&mut read_digest);
        assert_eq!(digest, &read_digest);
    }

    for (name, digest) in names.drain(..) {
        {
            let mut data = vec![];
            repo.read(&name, &mut data, &seckey).unwrap();

            let mut sha = sha2::Sha256::new();
            sha.input(&data);
            let mut read_digest = vec![0u8; 32];
            sha.result(&mut read_digest);
            assert_eq!(&digest, &read_digest);
        }

        let reachable = repo.list_reachable_chunks().unwrap();
        let stored = repo.list_stored_chunks().unwrap();

        for digest in reachable.iter() {
            assert!(stored.contains(digest));
        }
        for digest in stored.iter() {
            assert!(reachable.contains(digest));
        }

        repo.rm(&name).unwrap();
        let reachable_after_rm = repo.list_reachable_chunks().unwrap();
        let stored_after_rm = repo.list_stored_chunks().unwrap();

        assert_eq!(stored_after_rm.len(), stored.len());
        assert!(reachable_after_rm.len() < reachable.len());
        assert!(repo.gc().unwrap().chunks > 0);
    }

    wipe(&repo);
}

#[test]
fn change_passphrase() {
    let mut prev_passphrase = "foo";
    let dir_path = &rand_tmp_dir();
    let data_before = rand_data(1024);

    {
        let repo = lib::Repo::init(dir_path, prev_passphrase).unwrap();
        repo.write("data", &mut io::Cursor::new(&data_before)).unwrap();
    }

    for p in &["a", "", "foo", "bar"] {
        let repo = lib::Repo::open(dir_path).unwrap();
        let seckey = repo.get_seckey(&prev_passphrase).unwrap();
        repo.change_passphrase(&seckey, p).unwrap();
        prev_passphrase = p;
    }


    {
        let repo = lib::Repo::open(dir_path).unwrap();
        let seckey = repo.get_seckey(&prev_passphrase).unwrap();
        let mut data_after = vec![];
        repo.read("data", &mut data_after, &seckey).unwrap();

        assert_eq!(data_before, data_after);
    }

    let repo = lib::Repo::open(dir_path).unwrap();
    wipe(&repo);
}
#[test]
fn verify_name() {
    let dir_path = rand_tmp_dir();
    let repo = lib::Repo::init(&dir_path, PASS).unwrap();
    let seckey = repo.get_seckey(PASS).unwrap();
    let data = rand_data(1024);
    {
        repo.write("data", &mut io::Cursor::new(&data)).unwrap();
    }

    let mut result = repo.verify("data", &seckey).unwrap();
    assert_eq!(result.errors.len(), 0);

    // Corrupt first chunk we find
    let chunk_path = dir_path.join("chunk");
    for l1 in fs::read_dir(&chunk_path).unwrap() {
        let l1 = l1.unwrap();
        if l1.path().is_dir() {
            for l2 in fs::read_dir(l1.path()).unwrap() {
                let l2 = l2.unwrap();
                if l2.path().is_dir() {
                    for l3 in fs::read_dir(l2.path()).unwrap() {
                        let l3 = l3.unwrap();
                        let mut chunk = OpenOptions::new()
                            .write(true)
                            .append(true)
                            .open(l3.path())
                            .unwrap();
                        chunk.write(&vec![1]).unwrap();
                    }
                }
            }
        }
    }

    result = repo.verify("data", &seckey).unwrap();
    assert_eq!(result.errors.len(), 1);

    wipe(&repo);
}
