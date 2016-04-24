mod lib {
    pub use super::super::*;
}

use std::path;
use std::io;
use rand::{self, Rng};

fn rand_tmp_dir() -> path::PathBuf {
    // TODO: Use $TMP or something?
    path::PathBuf::from("/tmp")
        .join(rand::thread_rng()
              .gen_ascii_chars()
              .take(20)
              .collect::<String>())
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
