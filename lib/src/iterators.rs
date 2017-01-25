use serialize::hex::FromHex;

use std::fs;
use std::fs::ReadDir;
use std::io::Result;
use std::path::Path;

/// ```StoredChunks``` is an iterator for the list of chunks stored in a path, it will crawl the
/// directory structure looking for chunks that have valid digest sized elements as their name.
/// Invalid files with incorrect names will be ignored.
pub struct StoredChunks {
    dirs: Vec<ReadDir>,
    digest_size: usize,
}

impl StoredChunks {
    pub fn new(root: &Path, digest_size: usize) -> Result<StoredChunks> {
        Ok(StoredChunks {
            dirs: vec![fs::read_dir(root)?],
            digest_size: digest_size,
        })
    }
}

impl Iterator for StoredChunks {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Result<Vec<u8>>> {
        while !self.dirs.is_empty() {
            let entry = match self.dirs.last_mut().unwrap().next() {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => return Some(Err(error)),
                None => {
                    self.dirs.pop();
                    continue;
                }
            };
            let entry_path = entry.path();
            let entry_path_str = entry_path.to_string_lossy();
            trace!("Looking at {}", entry_path_str);
            if entry_path.is_dir() {
                match fs::read_dir(&entry_path) {
                    Ok(entries) => self.dirs.push(entries),
                    Err(e) => return Some(Err(e)),
                }
                continue;
            }
            // We have landed on a file, we need to verify the file is a valid chunk by parsing the
            // hex code in the file name.
            let name = entry.file_name().to_string_lossy().to_string();
            match name.from_hex() {
                Ok(digest) => {
                    if digest.len() == self.digest_size {
                        return Some(Ok(digest));
                    }
                    trace!("skipping {}", entry_path_str);
                    // Maybe we should remove this file? It is not a valid chunk file.
                }
                Err(e) => trace!("skipping {}, error {}", entry_path_str, e),
            }
        }
        None
    }
}
