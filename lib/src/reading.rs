use std;
use {DataAddress, DataType, Digest, Error, Repo, DIGEST_SIZE};
use VerifyResults;
use std::io;
use std::cell::RefCell;
use std::collections::HashSet;
use std::io::Write;
use {ArcCompression, ArcDecrypter};
use slog::{FnValue, Logger};
use hex::ToHex;

/// Translates index stream into data stream
///
/// This type implements `io::Write` and interprets what's written to it as a
/// stream of digests.
///
/// For every digest written to it, it will access the corresponding chunk and
/// write it into `writer` that it wraps.
struct IndexTranslator<'a> {
    accessor: &'a ChunkAccessor,
    writer: Option<&'a mut Write>,
    digest_buf: Digest,
    data_type: DataType,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,
    log: Logger,
}

impl<'a> IndexTranslator<'a> {
    pub(crate) fn new(
        accessor: &'a ChunkAccessor,
        writer: Option<&'a mut Write>,
        data_type: DataType,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
        log: Logger,
    ) -> Self {
        IndexTranslator {
            accessor: accessor,
            data_type: data_type,
            digest_buf: Digest(Vec::with_capacity(DIGEST_SIZE)),
            decrypter: decrypter,
            compression: compression,
            writer: writer,
            log: log,
        }
    }
}

impl<'a> Write for IndexTranslator<'a> {
    // TODO: This is copying too much. Could be not copying anything, unless
    // bytes < DIGEST_SIZE
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        assert!(!bytes.is_empty());

        let total_len = bytes.len();
        loop {
            let has_already = self.digest_buf.0.len();
            if (has_already + bytes.len()) < DIGEST_SIZE {
                self.digest_buf.0.extend_from_slice(bytes);

                trace!(self.log, "left with a buffer";
                       "digest" => FnValue(|_| self.digest_buf.0.to_hex()),
                       );
                return Ok(total_len);
            }

            let needs = DIGEST_SIZE - has_already;
            self.digest_buf.0.extend_from_slice(&bytes[..needs]);
            debug_assert_eq!(self.digest_buf.0.len(), DIGEST_SIZE);

            bytes = &bytes[needs..];
            let &mut IndexTranslator {
                accessor,
                ref mut digest_buf,
                data_type,
                ref decrypter,
                ref compression,
                ref mut writer,
                ..
            } = self;
            let res = if let Some(ref mut writer) = *writer {
                let mut traverser = ReadContext::new(
                    Some(writer),
                    decrypter.clone(),
                    compression.clone(),
                    self.log.clone(),
                );

                traverser.read_recursively(
                    data_type,
                    accessor,
                    &DataAddress {
                        digest: digest_buf,
                        index_level: 0,
                    },
                )
            } else {
                accessor.touch(&digest_buf)
            };
            digest_buf.0.clear();
            res?;
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for IndexTranslator<'a> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            debug_assert_eq!(self.digest_buf.0.len(), 0);
        }
    }
}

/// Read Context
///
/// Information necessary to complete given operation of reading given data in
/// the repository.
pub(crate) struct ReadContext<'a> {
    /// Writer to write the data to; `None` will discard the data
    writer: Option<&'a mut Write>,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,

    log: Logger,
}

impl<'a> ReadContext<'a> {
    pub(crate) fn new(
        writer: Option<&'a mut Write>,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
        log: Logger,
    ) -> Self {
        ReadContext {
            writer: writer,
            decrypter: decrypter,
            compression: compression,
            log: log,
        }
    }

    fn on_index(
        &mut self,
        accessor: &'a ChunkAccessor,
        data_address: &DataAddress,
        data_type: DataType,
    ) -> io::Result<()> {
        trace!(self.log, "Traversing index";
               "digest" => FnValue(|_| data_address.digest.0.to_hex()),
               );

        let mut translator = IndexTranslator::new(
            accessor,
            self.writer.take(),
            data_type,
            self.decrypter.clone(),
            self.compression.clone(),
            self.log.clone(),
        );

        let mut sub_traverser = ReadContext::new(
            Some(&mut translator),
            None,
            self.compression.clone(),
            self.log.clone(),
        );

        let da = DataAddress {
            digest: data_address.digest,
            index_level: data_address.index_level - 1,
        };
        sub_traverser.read_recursively(DataType::Index, accessor, &da)
    }

    fn on_data(
        &mut self,
        accessor: &'a ChunkAccessor,
        digest: &Digest,
        data_type: DataType,
    ) -> io::Result<()> {
        trace!(self.log, "Traversing data";
               "digest" => FnValue(|_| digest.0.to_hex()),
               );
        if let Some(writer) = self.writer.take() {
            accessor.read_chunk_into(digest, data_type, writer)
        } else {
            accessor.touch(digest)
        }
    }

    pub(crate) fn read_recursively(
        &mut self,
        data_type: DataType,
        accessor: &'a ChunkAccessor,
        da: &DataAddress,
    ) -> io::Result<()> {
        trace!(self.log, "Reading recursively";
               "digest" => FnValue(|_| da.digest.0.to_hex()),
               );

        let s = &*accessor as &ChunkAccessor;
        if da.index_level == 0 {
            self.on_data(s, &da.digest, data_type)
        } else {
            self.on_index(s, da, data_type)
        }
    }
}


/// Abstraction over accessing chunks stored in the repository
pub(crate) trait ChunkAccessor {
    fn repo(&self) -> &Repo;

    /// Read a chunk identified by `digest` into `writer`
    fn read_chunk_into(
        &self,
        digest: &Digest,
        data_type: DataType,
        writer: &mut Write,
    ) -> io::Result<()>;


    fn touch(&self, _digest: &Digest) -> io::Result<()> {
        Ok(())
    }
}

/// `ChunkAccessor` that just reads the chunks as requested, without doing
/// anything
pub(crate) struct DefaultChunkAccessor<'a> {
    repo: &'a Repo,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,
}

impl<'a> DefaultChunkAccessor<'a> {
    pub(crate) fn new(
        repo: &'a Repo,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
    ) -> Self {
        DefaultChunkAccessor {
            repo: repo,
            decrypter: decrypter,
            compression: compression,
        }
    }
}

impl<'a> ChunkAccessor for DefaultChunkAccessor<'a> {
    fn repo(&self) -> &Repo {
        self.repo
    }

    fn read_chunk_into(
        &self,
        digest: &Digest,
        data_type: DataType,
        writer: &mut Write,
    ) -> io::Result<()> {
        let path = self.repo.chunk_rel_path_by_digest(digest);
        let data = self.repo.aio.read(path).wait()?;

        let data = if data_type.should_encrypt() {
            self.decrypter
                .as_ref()
                .expect("Decrypter expected")
                .decrypt(data, &digest.0)?
        } else {
            data
        };

        let data = if data_type.should_compress() {
            self.compression.decompress(data)?
        } else {
            data
        };

        let vec_result = self.repo.hasher.calculate_digest(&data);

        if vec_result != digest.0 {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} corrupted, data read: {}",
                    digest.0.to_hex(),
                    vec_result.to_hex()
                ),
            ))
        } else {
            for part in data.as_parts() {
                writer.write_all(&*part)?;
            }
            Ok(())
        }
    }
}

/// `ChunkAccessor` that records which chunks
/// were accessed
///
/// This is useful for chunk garbage-collection
pub(crate) struct RecordingChunkAccessor<'a> {
    raw: DefaultChunkAccessor<'a>,
    accessed: RefCell<&'a mut HashSet<Vec<u8>>>,
}

impl<'a> RecordingChunkAccessor<'a> {
    pub(crate) fn new(
        repo: &'a Repo,
        accessed: &'a mut HashSet<Vec<u8>>,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
    ) -> Self {
        RecordingChunkAccessor {
            raw: DefaultChunkAccessor::new(repo, decrypter, compression),
            accessed: RefCell::new(accessed),
        }
    }
}

impl<'a> ChunkAccessor for RecordingChunkAccessor<'a> {
    fn repo(&self) -> &Repo {
        self.raw.repo()
    }

    fn touch(&self, digest: &Digest) -> io::Result<()> {
        self.accessed.borrow_mut().insert(digest.0.clone());
        Ok(())
    }

    fn read_chunk_into(
        &self,
        digest: &Digest,
        data_type: DataType,
        writer: &mut Write,
    ) -> io::Result<()> {
        self.touch(digest)?;
        self.raw.read_chunk_into(digest, data_type, writer)
    }
}

/// `ChunkAccessor` that verifies the chunks
/// that are accessed
///
/// This is used to verify a name / index
pub(crate) struct VerifyingChunkAccessor<'a> {
    raw: DefaultChunkAccessor<'a>,
    accessed: RefCell<HashSet<Vec<u8>>>,
    errors: RefCell<Vec<(Vec<u8>, Error)>>,
}

impl<'a> VerifyingChunkAccessor<'a> {
    pub(crate) fn new(
        repo: &'a Repo,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
    ) -> Self {
        VerifyingChunkAccessor {
            raw: DefaultChunkAccessor::new(repo, decrypter, compression),
            accessed: RefCell::new(HashSet::new()),
            errors: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn get_results(self) -> VerifyResults {
        VerifyResults {
            scanned: self.accessed.borrow().len(),
            errors: self.errors.into_inner(),
        }
    }
}

impl<'a> ChunkAccessor for VerifyingChunkAccessor<'a> {
    fn repo(&self) -> &Repo {
        self.raw.repo()
    }

    fn read_chunk_into(
        &self,
        digest: &Digest,
        data_type: DataType,
        writer: &mut Write,
    ) -> io::Result<()> {
        {
            let mut accessed = self.accessed.borrow_mut();
            if accessed.contains(&digest.0) {
                return Ok(());
            }
            accessed.insert(digest.0.clone());
        }
        let res = self.raw.read_chunk_into(digest, data_type, writer);

        if res.is_err() {
            self.errors
                .borrow_mut()
                .push((digest.0.clone(), res.err().unwrap()));
        }
        Ok(())
    }
}
