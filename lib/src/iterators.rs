use serialize::hex::FromHex;

use std::fs;
use std::fs::ReadDir;
use std::io::Result;
use std::path::Path;

pub struct StoredChunks {
    dir: ReadDir,
    next_level: Option<Box<StoredChunks>>,
    digest_size: usize,
}

impl StoredChunks {
    pub fn new(root: &Path, digest_size: usize) -> Result<StoredChunks> {
        Ok(StoredChunks {
            dir: try!(fs::read_dir(root)),
            next_level: None,
            digest_size: digest_size,
        })
    }
}

impl Iterator for StoredChunks {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Result<Vec<u8>>> {
        // Check if we have an iterator for the next level, if so we process from that iterator.
        if self.next_level.is_some() {
            match self.next_level.as_mut().unwrap().next() {
                Some(v) => return Some(v),
                None => self.next_level = None,
            };
        }
        // There was either no next_level or next_level is now exhausted, move our directory
        // iterator forward
        let entry = match self.dir.next() {
            Some(Ok(entry)) => entry,
            Some(Err(error)) => return Some(Err(error)),
            None => return None,
        };
        let entry_path = entry.path();
        let entry_path_str = entry_path.to_string_lossy();
        trace!("Looking at {}", entry_path_str);
        if entry_path.is_dir() {
            // We hit a directory lets get a new StoredChunks iterator for that level and exhaust it.
            self.next_level = match StoredChunks::new(&entry_path, self.digest_size) {
                Ok(sc) => Some(Box::new(sc)),
                Err(e) => return Some(Err(e)),
            };
            return self.next();
        }
        // We have landed on a file, we need to verify the file is a valid chunk by parsing the hex
        // code in the file name.
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
        return self.next();
    }
}
