

use asyncio;
use hex::FromHex;

use slog::Logger;

use std::io;
use std::io::Result;
use std::path::PathBuf;

/// `StoredChunks` is an iterator for the list of chunks stored in a path,
/// it will crawl the directory structure looking for chunks that have valid
/// digest sized elements as their name.  Invalid files with incorrect names
/// will be ignored.
pub struct StoredChunks {
    paths: Box<Iterator<Item = io::Result<PathBuf>>>,
    digest_size: usize,
    log: Logger,
}

impl StoredChunks {
    pub fn new(
        aio: &asyncio::AsyncIO,
        rel_path: PathBuf,
        digest_size: usize,
        log: Logger,
    ) -> Result<StoredChunks> {
        let paths = aio.list_recursively(rel_path);

        Ok(StoredChunks {
            paths: paths,
            digest_size: digest_size,
            log: log,
        })
    }
}

impl Drop for StoredChunks {
    fn drop(&mut self) {
        // drain the receiver so the sender can send everything
        // without failing
        while let Some(_) = self.paths.next() {}
    }
}
impl Iterator for StoredChunks {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Result<Vec<u8>>> {
        loop {
            let next = self.paths.next();

            if let Some(next) = next {

                let name = match next {
                    Ok(name) => name,
                    Err(e) => return Some(Err(e)),
                };

                let name = name.file_name()
                    .expect("Path terminated with ..?")
                    .to_string_lossy();
                let bytes = name.to_string().into_bytes();
                match Vec::from_hex(bytes) {
                    Ok(digest) => {
                        if digest.len() == self.digest_size {
                            return Some(Ok(digest));
                        }
                        trace!(self.log, "skipping"; "path" => %name);
                        // Maybe we should remove this file? It is not a valid
                        // chunk
                        // file.
                    }
                    Err(e) => trace!(self.log, "skipping";
                               "path" => %name, "error" => %e),
                }
            } else {
                return None;
            }
        }
    }
}
