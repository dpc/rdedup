mod lib {
    pub use super::super::*;
}

use hex::ToHex;
use iterators::StoredChunks;
use rand::{self, Rng};
use settings;
use sha2::{Digest, Sha256};

use std::{cmp, io};

use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Result, Write};
use std::path;
use std::path::PathBuf;

const PASS: &'static str = "FOO";
const DIGEST_SIZE: usize = 32;

fn rand_tmp_dir() -> path::PathBuf {
    // TODO: Use $TMP or something?
    path::PathBuf::from("/tmp/rdedup-tests").join(
        rand::thread_rng()
            .gen_ascii_chars()
            .take(20)
            .collect::<String>(),
    )
}

fn list_stored_chunks(repo: &lib::Repo) -> Result<HashSet<Vec<u8>>> {
    let mut digests = HashSet::new();
    let index_chunks = StoredChunks::new(
        &repo.aio,
        PathBuf::from(super::config::INDEX_SUBDIR),
        DIGEST_SIZE,
        repo.log.clone(),
    )?;
    let data_chunks = StoredChunks::new(
        &repo.aio,
        PathBuf::from(super::config::DATA_SUBDIR),
        DIGEST_SIZE,
        repo.log.clone(),
    )?;
    for digest in index_chunks.chain(data_chunks) {
        let digest = digest.unwrap();
        digests.insert(digest);
    }
    Ok(digests)
}

fn test_repo(pass: &str) -> lib::Repo {
    let settings = settings::Repo::new();
    lib::Repo::init(&rand_tmp_dir(), &|| Ok(pass.into()), settings, None)
        .unwrap()
}

/// Generate data that repease some chunks
struct ExampleDataGen {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    count: usize,
    sha: Sha256,
}

impl ExampleDataGen {
    fn new(kb: usize) -> Self {

        ExampleDataGen {
            a: rand_data(1024 * 2),
            b: rand_data(1024 * 2),
            c: rand_data(1024 * 2),
            count: kb,
            sha: Sha256::default(),
        }
    }

    fn finish(self) -> Vec<u8> {
        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&self.sha.result());
        vec_result
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
    rand::weak_rng().gen_iter().take(len).collect::<Vec<u8>>()
}

fn wipe(repo: &lib::Repo) {
    let names = repo.list_names().unwrap();

    for name in &names {
        repo.rm(&name).unwrap();
    }

    repo.gc().unwrap();

    assert_eq!(list_stored_chunks(repo).unwrap().len(), 0);
    assert_eq!(repo.list_reachable_chunks().unwrap().len(), 0);
}

#[test]
fn zero_size() {
    let repo = test_repo(PASS);
    {
        let zero = Vec::new();
        let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();
        repo.write("zero", &mut io::Cursor::new(zero), &enc_handle)
            .unwrap();

    }

    let mut read_zero = Vec::new();
    {
        let dec_handle = repo.unlock_decrypt(&|| Ok(PASS.into())).unwrap();
        repo.read("zero", &mut read_zero, &dec_handle).unwrap();
    }

    assert_eq!(read_zero.len(), 0);

    wipe(&repo);
}

#[test]
fn byte_size() {
    let repo = test_repo(PASS);

    let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();
    let dec_handle = repo.unlock_decrypt(&|| Ok(PASS.into())).unwrap();

    let tests = [0u8, 1, 13, 255];
    for &b in &tests {
        let data = vec![b];
        let name = data.to_hex();
        repo.write(&name, &mut io::Cursor::new(&data), &enc_handle)
            .unwrap();
    }
    for &b in &tests {
        let mut data = Vec::new();
        let name = vec![b].to_hex();
        repo.read(&name, &mut data, &dec_handle).unwrap();
        assert_eq!(data, vec![b]);
    }

    wipe(&repo);
}

#[test]
fn random_sanity() {
    let mut names = vec![];

    let repo = test_repo(PASS);
    let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();
    let dec_handle = repo.unlock_decrypt(&|| Ok(PASS.into())).unwrap();

    for i in 0..10 {
        let mut data =
            ExampleDataGen::new(rand::weak_rng().gen_range(0, 10 * 1024));
        let name = format!("{:x}", i);
        repo.write(&name, &mut data, &enc_handle).unwrap();
        names.push((name, data.finish()));
    }

    repo.gc().unwrap();

    for &(ref name, ref digest) in &names {
        let mut data = vec![];
        repo.read(&name, &mut data, &dec_handle).unwrap();

        let mut sha = Sha256::default();
        sha.input(&data);
        let mut read_digest = vec![0u8; DIGEST_SIZE];
        read_digest.copy_from_slice(&sha.result());
        assert_eq!(digest, &read_digest);
    }

    for (name, digest) in names.drain(..) {
        {
            let mut data = vec![];
            repo.read(&name, &mut data, &dec_handle).unwrap();

            let mut sha = Sha256::default();
            sha.input(&data);
            let mut read_digest = vec![0u8; DIGEST_SIZE];
            read_digest.copy_from_slice(&sha.result());
            assert_eq!(&digest, &read_digest);
        }

        let reachable = repo.list_reachable_chunks().unwrap();
        let stored = list_stored_chunks(&repo).unwrap();

        for digest in reachable.iter() {
            assert!(stored.contains(digest));
        }
        for digest in stored.iter() {
            assert!(reachable.contains(digest));
        }

        repo.rm(&name).unwrap();
        let reachable_after_rm = repo.list_reachable_chunks().unwrap();
        let stored_after_rm = list_stored_chunks(&repo).unwrap();

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
        let settings = settings::Repo::new();
        let repo = lib::Repo::init(
            &dir_path,
            &|| Ok(prev_passphrase.into()),
            settings,
            None,
        ).unwrap();

        let enc_handle =
            repo.unlock_encrypt(&|| Ok(prev_passphrase.into())).unwrap();

        repo.write("data", &mut io::Cursor::new(&data_before), &enc_handle)
            .unwrap();
    }

    for &p in &["a", "", "foo", "bar"] {
        let mut repo = lib::Repo::open(dir_path, None).unwrap();
        repo.change_passphrase(
            &|| Ok(prev_passphrase.into()),
            &|| Ok(p.into()),
        ).unwrap();
        prev_passphrase = p;
    }


    {
        let repo = lib::Repo::open(dir_path, None).unwrap();
        let dec_handle =
            repo.unlock_decrypt(&|| Ok(prev_passphrase.into())).unwrap();
        let mut data_after = vec![];
        repo.read("data", &mut data_after, &dec_handle).unwrap();

        assert_eq!(data_before, data_after);
    }

    let repo = lib::Repo::open(dir_path, None).unwrap();
    wipe(&repo);
}

#[test]
fn verify_name() {
    let repo = test_repo(PASS);

    let dec_handle = repo.unlock_decrypt(&|| Ok(PASS.into())).unwrap();
    let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();
    let data = rand_data(1024);
    {
        repo.write("data", &mut io::Cursor::new(&data), &enc_handle)
            .unwrap();
    }

    let mut result = repo.verify("data", &dec_handle).unwrap();
    assert_eq!(result.errors.len(), 0);

    // Corrupt first chunk we find
    let chunk_path = repo.path().join("chunk");
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

    result = repo.verify("data", &dec_handle).unwrap();
    assert_eq!(result.errors.len(), 1);

    wipe(&repo);
}

#[test]
fn test_stored_chunks_iter() {
    let repo = test_repo(PASS);
    let data = rand_data(1024 * 1024);

    let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();

    repo.write("data", &mut io::Cursor::new(&data), &enc_handle)
        .unwrap();
    let chunks_from_indexes = repo.list_reachable_chunks().unwrap();

    let mut chunks_from_iter = list_stored_chunks(&repo).unwrap();
    assert_eq!(chunks_from_indexes.difference(&chunks_from_iter).count(), 0);

    // Insert garbage file into chunks folder
    let garbage_file_path = repo.path().join("chunk/garbage.data");
    {
        let mut f = fs::File::create(&garbage_file_path).unwrap();
        f.write_all(&data).unwrap();
    }
    chunks_from_iter = list_stored_chunks(&repo).unwrap();
    assert_eq!(chunks_from_indexes.difference(&chunks_from_iter).count(), 0);

    fs::remove_file(&garbage_file_path).unwrap();

    // Add a second name to the repo and compare chunks
    let data2 = rand_data(1024 * 1024);
    repo.write("data2", &mut io::Cursor::new(&data2), &enc_handle)
        .unwrap();
    let chunks_from_indexes2 = repo.list_reachable_chunks().unwrap();
    chunks_from_iter = list_stored_chunks(&repo).unwrap();
    assert_eq!(chunks_from_indexes.difference(&chunks_from_iter).count(), 0);

    // Remove the second name and make sure the difference
    repo.rm("data2").unwrap();
    let chunks_from_indexes3 = repo.list_reachable_chunks().unwrap();
    assert_eq!(
        chunks_from_indexes3
            .difference(&chunks_from_indexes)
            .count(),
        0
    );
    // Chunks from iterator should equal the list from both names before the
    // removal
    chunks_from_iter = list_stored_chunks(&repo).unwrap();
    assert_eq!(
        chunks_from_indexes2.difference(&chunks_from_iter).count(),
        0
    );

    repo.gc().unwrap();
    // Chunks from iterator should equal the first reachable list
    chunks_from_iter = list_stored_chunks(&repo).unwrap();
    assert_eq!(chunks_from_indexes.difference(&chunks_from_iter).count(), 0);
}

#[test]
fn test_custom_chunking_size() {
    for &bits in &[9, 10, 17, 20, 30, 31] {
        let dir_path = rand_tmp_dir();
        {

            let mut settings = settings::Repo::new();
            let result = settings.use_bup_chunking(Some(bits));


            if bits < 10 || bits > 30 {
                if result.is_err() {
                    continue;
                } else {
                    panic!("expected an error for value {:}, but got Ok", bits);
                }
            } else if result.is_err() {
                panic!("expected Ok, but got {:}", result.err().unwrap());
            }
            lib::Repo::init(
                &dir_path,
                &|| Ok(PASS.into()),
                settings.clone(),
                None,
            ).unwrap();

            let repo = lib::Repo::open(&dir_path, None).unwrap();
            assert_eq!(settings.chunking.0, repo.config.chunking);
            wipe(&repo);
        }
    }
}

#[test]
fn test_custom_nesting() {
    for &level in &[0, 1, 4, 31, 64] {
        let dir_path = rand_tmp_dir();
        {

            let mut settings = settings::Repo::new();
            let result = settings.set_nesting(level);


            if level > 31 {
                if result.is_err() {
                    continue;
                } else {
                    panic!(
                        "expected an error for value {:}, but got Ok",
                        level
                    );
                }
            } else if result.is_err() {
                panic!("expected Ok, but got {:}", result.err().unwrap());
            }
            lib::Repo::init(
                &dir_path,
                &|| Ok(PASS.into()),
                settings.clone(),
                None,
            ).unwrap();

            let repo = lib::Repo::open(&dir_path, None).unwrap();
            assert_eq!(lib::config::Nesting(level), repo.config.nesting);

            // Test Store, Load, RM, and GC
            let data = rand_data(1024 * 1024);
            let enc_handle = repo.unlock_encrypt(&|| Ok(PASS.into())).unwrap();
            let dec_handle = repo.unlock_decrypt(&|| Ok(PASS.into())).unwrap();

            let wstats =
                repo.write("data", &mut io::Cursor::new(&data), &enc_handle)
                    .unwrap();

            let mut load_data = vec![];
            repo.read("data", &mut load_data, &dec_handle).unwrap();

            assert_eq!(load_data, data);

            repo.rm("data").unwrap();

            let gstats = repo.gc().unwrap();

            assert_eq!(wstats.new_chunks, gstats.chunks);
            wipe(&repo);
        }
    }
}
