extern crate base64;
extern crate blake2;
extern crate bzip2;
extern crate crossbeam;
extern crate dangerous_option;
extern crate digest;
extern crate flate2;
extern crate fs2;
extern crate hex;
extern crate lzma;
extern crate num_cpus;
extern crate owning_ref;
extern crate rand;
extern crate rdedup_cdc as rollsum;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate sgdata;
extern crate sha2;
#[macro_use]
extern crate slog;
extern crate slog_perf;
extern crate sodiumoxide;
extern crate two_lock_queue;
extern crate walkdir;
extern crate zstd;

use hex::ToHex;
use sgdata::SGData;
use slog::{Level, Logger};
use slog_perf::TimeReporter;
use slog::FnValue;

use sodiumoxide::crypto::{box_, pwhash, secretbox};

use std::{fs, io};
use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error as StdErrorError;
use std::io::{Error, Read, Result, Write};
use std::iter::Iterator;
use std::path::{Path, PathBuf};

use std::sync::{mpsc, Arc};

mod iterators;
use iterators::StoredChunks;

mod config;

mod sg;
use sg::*;

mod asyncio;
use asyncio::*;

mod hashing;
mod chunking;

mod chunk_processor;
use chunk_processor::*;

mod sorting_recv;
use sorting_recv::SortingIterator;

mod encryption;
use encryption::EncryptionEngine;

mod compression;
use compression::ArcCompression;

pub mod settings;

mod util;
use util::*;

mod misc;
use misc::*;

type ArcDecrypter = Arc<encryption::Decrypter + Send + Sync + 'static>;
type ArcEncrypter = Arc<encryption::Encrypter + Send + Sync + 'static>;

const INGRESS_BUFFER_SIZE: usize = 128 * 1024;
// TODO: Parametrize over repo chunk size
const DIGEST_SIZE: usize = 32;

/// Type of user provided closure that will ask user for a passphrase is needed
type PassphraseFn<'a> = &'a Fn() -> io::Result<String>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataType {
    Index,
    Data,
}

impl DataType {
    fn should_compress(&self) -> bool {
        *self == DataType::Data
    }

    fn should_encrypt(&self) -> bool {
        *self == DataType::Data
    }
}

/// Translates index stream into data stream
///
/// This type implements `io::Write` and interprets what's written to it as a
/// stream of digests.
///
/// For every digest written to it, it will access the corresponding chunk and
/// write it into `writer` that it wraps.
struct IndexTranslator<'a, 'b> {
    accessor: &'a ChunkAccessor,
    parent_digest: &'b [u8],
    writer: Option<&'a mut Write>,
    digest_buf: Digest,
    data_type: DataType,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,
    log: Logger,
}

impl<'a, 'b> IndexTranslator<'a, 'b> {
    fn new(
        accessor: &'a ChunkAccessor,
        parent_digest: &'b [u8],
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
            parent_digest: parent_digest,
            decrypter: decrypter,
            compression: compression,
            writer: writer,
            log: log,
        }
    }
}

impl<'a, 'b> Write for IndexTranslator<'a, 'b> {
    // TODO: This is copying too much. Could be not copying anything, unless
    // bytes < DIGEST_SIZE
    fn write(&mut self, mut bytes: &[u8]) -> Result<usize> {
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
                ref parent_digest,
                data_type,
                ref decrypter,
                ref compression,
                ref mut writer,
                ..
            } = self;
            let res = if let Some(ref mut writer) = *writer {
                let mut traverser = ReadContext::new(
                    Some(writer),
                    &parent_digest,
                    data_type,
                    decrypter.clone(),
                    compression.clone(),
                    self.log.clone(),
                );

                traverser.read_recursively(
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

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a, 'b> Drop for IndexTranslator<'a, 'b> {
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
struct ReadContext<'a> {
    /// Writer to write the data to; `None` will discard the data
    writer: Option<&'a mut Write>,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,
    /// The type of the data to be read
    data_type: DataType,
    parent_digest: &'a [u8],

    log: Logger,
}

impl<'a> ReadContext<'a> {
    fn new(
        writer: Option<&'a mut Write>,
        parent_digest: &'a [u8],
        data_type: DataType,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
        log: Logger,
    ) -> Self {
        ReadContext {
            writer: writer,
            parent_digest: parent_digest,
            data_type: data_type,
            decrypter: decrypter,
            compression: compression,
            log: log,
        }
    }

    fn on_index(
        &mut self,
        accessor: &'a ChunkAccessor,
        data_address: &DataAddress,
    ) -> Result<()> {
        trace!(self.log, "Traversing index";
               "parent" => FnValue(|_| self.parent_digest.to_hex()),
               "digest" => FnValue(|_| data_address.digest.0.to_hex()),
               );

        let mut translator = IndexTranslator::new(
            accessor,
            &data_address.digest.0,
            self.writer.take(),
            self.data_type,
            self.decrypter.clone(),
            self.compression.clone(),
            self.log.clone(),
        );

        let mut sub_traverser = ReadContext::new(
            Some(&mut translator),
            &data_address.digest.0,
            DataType::Index,
            None,
            self.compression.clone(),
            self.log.clone(),
        );

        let da = DataAddress {
            digest: data_address.digest,
            index_level: data_address.index_level - 1,
        };
        sub_traverser.read_recursively(accessor, &da)
    }

    fn on_data(
        &mut self,
        accessor: &'a ChunkAccessor,
        digest: &Digest,
    ) -> Result<()> {
        trace!(self.log, "Traversing data";
               "parent" => FnValue(|_| self.parent_digest.to_hex()),
               "digest" => FnValue(|_| digest.0.to_hex()),
               );
        if let Some(writer) = self.writer.take() {
            accessor.read_chunk_into(
                digest,
                DataType::Data,
                self.data_type,
                writer,
            )
        } else {
            accessor.touch(digest)
        }
    }

    fn read_recursively(
        &mut self,
        accessor: &'a ChunkAccessor,
        da: &DataAddress,
    ) -> Result<()> {
        trace!(self.log, "Reading recursively";
               "parent" => FnValue(|_| self.parent_digest.to_hex()),
               "digest" => FnValue(|_| da.digest.0.to_hex()),
               );

        let s = &*accessor as &ChunkAccessor;
        if da.index_level == 0 {
            self.on_data(s, &da.digest)
        } else {
            self.on_index(s, da)
        }
    }
}


/// Abstraction over accessing chunks stored in the repository
trait ChunkAccessor {
    fn repo(&self) -> &Repo;

    /// Read a chunk identified by `digest` into `writer`
    fn read_chunk_into(
        &self,
        digest: &Digest,
        chunk_type: DataType,
        data_type: DataType,
        writer: &mut Write,
    ) -> Result<()>;


    fn touch(&self, _digest: &Digest) -> Result<()> {
        Ok(())
    }
}

/// `ChunkAccessor` that just reads the chunks as requested, without doing
/// anything
struct DefaultChunkAccessor<'a> {
    repo: &'a Repo,
    decrypter: Option<ArcDecrypter>,
    compression: ArcCompression,
}

impl<'a> DefaultChunkAccessor<'a> {
    fn new(
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
        chunk_type: DataType,
        data_type: DataType,
        writer: &mut Write,
    ) -> Result<()> {
        let path = self.repo.chunk_rel_path_by_digest(digest);
        let data = self.repo.aio.read(path).wait()?;

        let data = if data_type.should_encrypt() && chunk_type.should_encrypt()
        {
            self.decrypter
                .as_ref()
                .expect("Decrypter expected")
                .decrypt(data, &digest.0)?
        } else {
            data
        };

        let data =
            if data_type.should_compress() && chunk_type.should_compress() {
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
struct RecordingChunkAccessor<'a> {
    raw: DefaultChunkAccessor<'a>,
    accessed: RefCell<&'a mut HashSet<Vec<u8>>>,
}

impl<'a> RecordingChunkAccessor<'a> {
    fn new(
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

    fn touch(&self, digest: &Digest) -> Result<()> {
        self.accessed.borrow_mut().insert(digest.0.clone());
        Ok(())
    }

    fn read_chunk_into(
        &self,
        digest: &Digest,
        chunk_type: DataType,
        data_type: DataType,
        writer: &mut Write,
    ) -> Result<()> {
        self.touch(digest)?;
        self.raw
            .read_chunk_into(digest, chunk_type, data_type, writer)
    }
}

/// `ChunkAccessor` that verifies the chunks
/// that are accessed
///
/// This is used to verify a name / index
struct VerifyingChunkAccessor<'a> {
    raw: DefaultChunkAccessor<'a>,
    accessed: RefCell<HashSet<Vec<u8>>>,
    errors: RefCell<Vec<(Vec<u8>, Error)>>,
}

impl<'a> VerifyingChunkAccessor<'a> {
    fn new(
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

    fn get_results(self) -> VerifyResults {
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
        chunk_type: DataType,
        data_type: DataType,
        writer: &mut Write,
    ) -> Result<()> {
        {
            let mut accessed = self.accessed.borrow_mut();
            if accessed.contains(&digest.0) {
                return Ok(());
            }
            accessed.insert(digest.0.clone());
        }
        let res =
            self.raw
                .read_chunk_into(digest, chunk_type, data_type, writer);

        if res.is_err() {
            self.errors
                .borrow_mut()
                .push((digest.0.clone(), res.err().unwrap()));
        }
        Ok(())
    }
}

pub struct VerifyResults {
    pub scanned: usize,
    pub errors: Vec<(Vec<u8>, Error)>,
}

pub struct GcResults {
    pub chunks: usize,
    pub bytes: u64,
}

pub struct DuResults {
    pub chunks: usize,
    pub bytes: u64,
}



/// Rdedup repository
#[derive(Clone)]
pub struct Repo {
    /// Path of the repository
    path: PathBuf,

    config: config::Repo,

    compression: compression::ArcCompression,
    hasher: hashing::ArcHasher,

    /// Logger
    log: slog::Logger,

    aio: asyncio::AsyncIO,
}

/// A reading handle
pub struct DecryptHandle {
    decrypter: ArcDecrypter,
}

pub struct EncryptHandle {
    encrypter: ArcEncrypter,
}


#[derive(Clone)]
struct Digest(Vec<u8>);

#[derive(Clone)]
struct DataAddress<'a> {
    // number of times the data index
    // was written (and then index of an index and so forth)
    // until it was reduced to a final digest
    index_level: u32,
    // final digest
    digest: &'a Digest,
}

#[derive(Clone)]
struct OwnedDataAddress {
    // number of times the data index
    // was written (and then index of an index and so forth)
    // until it was reduced to a final digest
    index_level: u32,
    // final digest
    digest: Digest,
}

impl OwnedDataAddress {
    fn as_ref(&self) -> DataAddress {
        DataAddress {
            index_level: self.index_level,
            digest: &self.digest,
        }
    }
}

impl From<config::Name> for OwnedDataAddress {
    fn from(name: config::Name) -> Self {
        OwnedDataAddress {
            index_level: name.index_level,
            digest: Digest(name.digest),
        }
    }
}


/// Opaque wrapper over secret key
pub struct SecretKey(box_::SecretKey);

impl Repo {
    pub fn unlock_decrypt(
        &self,
        pass: PassphraseFn,
    ) -> io::Result<DecryptHandle> {
        info!(self.log, "Opening read handle");
        let decrypter = self.config.encryption.decrypter(pass)?;

        Ok(DecryptHandle {
            decrypter: decrypter,
        })
    }

    pub fn unlock_encrypt(
        &self,
        pass: PassphraseFn,
    ) -> io::Result<EncryptHandle> {
        info!(self.log, "Opening write handle");
        let encrypter = self.config.encryption.encrypter(pass)?;


        Ok(EncryptHandle {
            encrypter: encrypter,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_repo_empty_or_new(aio: &AsyncIO) -> Result<()> {
        let list = aio.list(PathBuf::from(".")).wait();

        if !list.is_err() && !list.unwrap().is_empty() {
            return Err(Error::new(
                io::ErrorKind::AlreadyExists,
                "repo dir must not exist or be empty to be used",
            ));
        }
        Ok(())
    }

    /// Create new rdedup repository
    pub fn init<L>(
        repo_path: &Path,
        passphrase: PassphraseFn,
        settings: settings::Repo,
        log: L,
    ) -> Result<Repo>
    where
        L: Into<Option<Logger>>,
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));

        let aio = asyncio::AsyncIO::new(repo_path.to_owned(), log.clone());

        Repo::ensure_repo_empty_or_new(&aio)?;
        let config = config::Repo::new_from_settings(passphrase, settings)?;
        config.write(&aio)?;

        let compression = config.compression.to_engine();
        let hasher = config.hashing.to_hasher();

        Ok(Repo {
            path: repo_path.into(),
            config: config,
            compression: compression,
            hasher: hasher,
            log: log,
            aio: aio,
        })
    }

    #[allow(unknown_lints)]
    #[allow(absurd_extreme_comparisons)]
    fn read_and_validate_version(aio: &AsyncIO) -> Result<u32> {
        let version = aio.read(PathBuf::from(config::VERSION_FILE))
            .wait()?
            .to_linear_vec();
        let version = String::from_utf8_lossy(&version);

        let version_int = version.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "can't parse version file; \
                     unsupported repo format version: {}",
                    version
                ),
            )
        })?;


        if version_int > config::REPO_VERSION_CURRENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "repo version {} higher than \
                     supported {}; update?",
                    version,
                    config::REPO_VERSION_CURRENT
                ),
            ));
        }
        // This if statement triggers the absurd_extreme_comparisons because the
        // minimum repo version is also the smallest value of a u32
        if version_int < config::REPO_VERSION_LOWEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "repo version {} lower than \
                     lowest supported {}; \
                     restore using older version?",
                    version,
                    config::REPO_VERSION_LOWEST
                ),
            ));
        }

        Ok(version_int)
    }

    /// List all names
    pub fn list_names(&self) -> Result<Vec<String>> {
        let _lock = self.aio.lock_shared();

        config::Name::list(&self.aio)
    }

    pub fn open<L>(repo_path: &Path, log: L) -> Result<Repo>
    where
        L: Into<Option<Logger>>,
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));


        let aio = asyncio::AsyncIO::new(repo_path.to_owned(), log.clone());

        if !repo_path.exists() {
            return Err(Error::new(
                io::ErrorKind::NotFound,
                format!("repo not found: {}", repo_path.to_string_lossy()),
            ));
        }

        let version = Repo::read_and_validate_version(&aio)?;

        if version == 0 {
            return Err(Error::new(
                io::ErrorKind::NotFound,
                "rdedup v0 config format not supported",
            ));
        }

        let config = config::Repo::read(&aio)?;

        let compression = config.compression.to_engine();
        let hasher = config.hashing.to_hasher();
        Ok(Repo {
            path: repo_path.to_owned(),
            config: config,
            compression: compression,
            hasher: hasher,
            log: log,
            aio: aio,
        })
    }

    /// Change the passphrase
    pub fn change_passphrase(
        &mut self,
        old_p: PassphraseFn,
        new_p: PassphraseFn,
    ) -> Result<()> {
        let _lock = self.aio.lock_exclusive();

        if self.config.version == 0 {
            Err(Error::new(
                io::ErrorKind::NotFound,
                "rdedup v0 config format not supported",
            ))
        } else {
            self.config.encryption.change_passphrase(old_p, new_p)?;
            self.config.write(&self.aio)?;
            Ok(())
        }
    }


    /// Write a chunk of data to the repo.
    fn chunk_and_write_data_thread<'a>(
        &'a self,
        input_data_iter: Box<Iterator<Item = Vec<u8>> + Send + 'a>,
        process_tx: two_lock_queue::Sender<chunk_processor::Message>,
        aio: asyncio::AsyncIO,
        data_type: DataType,
    ) -> io::Result<OwnedDataAddress> {
        // Note: This channel is intentionally unbounded
        // The processing loop runs in sort of a loop (actually more of a
        // recursive spiral). Unless this channel is unbounded it's possible
        // that one `index-processor` will wait for `chunker` while `chunker`
        // waits for `chunk-processor` while will `chunk-processor` waits
        // for `index-processor`.
        //
        // In practice there's always less `index` data than chunk data (that's
        // the whole point of keeping index) so this channel does not have
        // to be bounded.
        let (digests_tx, digests_rx) = mpsc::channel();

        crossbeam::scope(move |scope| {
            let mut timer = slog_perf::TimeReporter::new_with_level(
                "index-processor",
                self.log.clone(),
                Level::Debug,
            );
            timer.start("spawn-chunker");

            scope.spawn({
                let process_tx = process_tx.clone();
                move || {
                    let mut timer = slog_perf::TimeReporter::new_with_level(
                        "chunker",
                        self.log.clone(),
                        Level::Debug,
                    );

                    let chunker = Chunker::new(
                        input_data_iter.into_iter(),
                        self.config.chunking.to_engine(),
                    );

                    // TODO: Change to `enumerate_u64`
                    let mut data = chunker.enumerate();

                    while let Some(i_sg) =
                        timer.start_with("rx-and-chunking", || data.next())
                    {
                        timer.start("tx");
                        let (i, sg) = i_sg;
                        process_tx
                            .send(chunk_processor::Message {
                                data: (i as u64, sg),
                                response_tx: digests_tx.clone(),
                                data_type: data_type,
                            })
                            .expect("process_tx.send(...)")
                    }
                    drop(digests_tx);
                }
            });

            timer.start("sorting-recv-create");
            let mut digests_rx = SortingIterator::new(digests_rx.into_iter());

            timer.start("digest-rx");
            let first_digest =
                digests_rx.next().expect("At least one index digest");

            if let Some(second_digest) =
                timer.start_with("digest-rx", || digests_rx.next())
            {
                let mut two_first = vec![first_digest, second_digest];
                let mut address = self.chunk_and_write_data_thread(
                    Box::new(
                        two_first
                            .drain(..)
                            .chain(digests_rx)
                            .map(|digest| digest.0),
                    ),
                    process_tx,
                    aio.clone(),
                    DataType::Index,
                )?;

                address.index_level += 1;
                Ok(address)
            } else {
                Ok(OwnedDataAddress {
                    index_level: 0,
                    digest: first_digest,
                })
            }
        })
    }

    /// Number of threads to use to parallelize CPU-intense part of
    /// the workload.
    fn write_cpu_thread_num(&self) -> usize {
        num_cpus::get()
    }

    fn input_reader_thread<R>(
        &self,
        reader: R,
        chunker_tx: mpsc::SyncSender<Vec<u8>>,
    ) where
        R: Read + Send,
    {
        let mut time = TimeReporter::new_with_level(
            "input-reader",
            self.log.clone(),
            Level::Debug,
        );

        let r2vi = ReaderVecIter::new(reader, INGRESS_BUFFER_SIZE);
        let mut while_ok = WhileOk::new(r2vi);

        while let Some(buf) = time.start_with("input", || while_ok.next()) {
            time.start("tx");
            chunker_tx.send(buf).unwrap()
        }
    }

    fn get_chunk_accessor(
        &self,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
    ) -> DefaultChunkAccessor {
        DefaultChunkAccessor::new(self, decrypter, compression)
    }

    fn get_recording_chunk_accessor<'a>(
        &'a self,
        accessed: &'a mut HashSet<Vec<u8>>,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
    ) -> RecordingChunkAccessor<'a> {
        RecordingChunkAccessor::new(self, accessed, decrypter, compression)
    }

    fn reachable_recursively_insert(
        &self,
        da: &DataAddress,
        reachable_digests: &mut HashSet<Vec<u8>>,
    ) -> Result<()> {
        reachable_digests.insert(da.digest.0.clone());

        let mut traverser = ReadContext::new(
            None,
            &da.digest.0,
            DataType::Data,
            None,
            self.compression.clone(),
            self.log.clone(),
        );
        traverser.read_recursively(
            &self.get_recording_chunk_accessor(
                reachable_digests,
                None,
                self.compression.clone(),
            ),
            da,
        )
    }



    /// Return all reachable chunks
    fn list_reachable_chunks(&self) -> Result<HashSet<Vec<u8>>> {
        let mut reachable_digests = HashSet::new();
        let all_names = config::Name::list(&self.aio)?;
        for name_str in &all_names {
            match config::Name::load_from(name_str, &self.aio) {
                Ok(name) => {
                    let data_address: OwnedDataAddress = name.into();
                    info!(self.log, "processing"; "name" => name_str);
                    self.reachable_recursively_insert(
                        &data_address.as_ref(),
                        &mut reachable_digests,
                    )?;
                }
                Err(e) => {
                    info!(self.log, "skipped"; "name" => name_str, "error" =>
                          e.description());
                }
            };
        }
        Ok(reachable_digests)
    }

    // fn chunk_type(&self, digest: &[u8]) -> Result<DataType> {
    // for i in &[DataType::Index, DataType::Data] {
    // let file_path = self.chunk_path_by_digest(digest, *i);
    // if file_path.exists() {
    // return Ok(*i);
    // }
    // }
    // Err(Error::new(
    // io::ErrorKind::NotFound,
    // format!("chunk file missing: {}", digest.to_hex()),
    // ))
    // }

    fn chunk_rel_path_by_digest(&self, digest: &Digest) -> PathBuf {
        self.config
            .nesting
            .get_path(Path::new(config::DATA_SUBDIR), &digest.0)
    }

    fn chunk_path_by_digest(&self, digest: &Digest) -> PathBuf {
        self.path.join(self.chunk_rel_path_by_digest(digest))
    }

    fn rm_chunk_by_digest(&self, digest: &Digest) -> Result<u64> {
        let path = self.chunk_path_by_digest(digest);
        let md = fs::metadata(&path)?;
        fs::remove_file(path)?;
        Ok(md.len())
    }


    /// Remove a stored name from repo
    pub fn rm(&self, name: &str) -> Result<()> {
        let _lock = self.aio.lock_exclusive();
        config::Name::remove(name, self)
    }

    pub fn gc(&self) -> Result<GcResults> {
        let _lock = self.aio.lock_exclusive();

        let reachable = self.list_reachable_chunks().unwrap();

        let data_chunks = StoredChunks::new(
            &self.aio,
            PathBuf::from(config::DATA_SUBDIR),
            DIGEST_SIZE,
            self.log.clone(),
        )?;

        let mut result = GcResults {
            chunks: 0,
            bytes: 0,
        };

        for digest in data_chunks {
            let digest = digest?;
            if !reachable.contains(&digest) {
                trace!(self.log, "removing chunk"; "digest" => digest.to_hex());
                let bytes = self.rm_chunk_by_digest(&Digest(digest))?;
                result.chunks += 1;
                result.bytes += bytes;
            }
        }

        Ok(result)
    }

    pub fn read<W: Write>(
        &self,
        name_str: &str,
        writer: &mut W,
        dec: &DecryptHandle,
    ) -> Result<()> {
        let _lock = self.aio.lock_shared();

        let name = config::Name::load_from(name_str, &self.aio)?;
        let data_address: OwnedDataAddress = name.into();

        let accessor = self.get_chunk_accessor(
            Some(dec.decrypter.clone()),
            self.compression.clone(),
        );
        let mut traverser = ReadContext::new(
            Some(writer),
            &[],
            DataType::Data,
            Some(dec.decrypter.clone()),
            self.compression.clone(),
            self.log.clone(),
        );
        traverser.read_recursively(&accessor, &data_address.as_ref())
    }

    pub fn du(&self, name_str: &str, dec: &DecryptHandle) -> Result<DuResults> {
        let _lock = self.aio.lock_shared();

        let name = config::Name::load_from(name_str, &self.aio)?;
        let data_address: OwnedDataAddress = name.into();

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(
            self,
            Some(dec.decrypter.clone()),
            self.compression.clone(),
        );
        {
            let mut traverser = ReadContext::new(
                Some(&mut counter),
                &[],
                DataType::Data,
                Some(dec.decrypter.clone()),
                self.compression.clone(),
                self.log.clone(),
            );
            traverser.read_recursively(&accessor, &data_address.as_ref())?;
        }
        Ok(DuResults {
            chunks: accessor.get_results().scanned,
            bytes: counter.count,
        })
    }

    pub fn verify(
        &self,
        name_str: &str,
        dec: &DecryptHandle,
    ) -> Result<VerifyResults> {
        let _lock = self.aio.lock_shared();
        let name = config::Name::load_from(name_str, &self.aio)?;
        let data_address: OwnedDataAddress = name.into();

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(
            self,
            Some(dec.decrypter.clone()),
            self.compression.clone(),
        );
        {
            let mut traverser = ReadContext::new(
                Some(&mut counter),
                &[],
                DataType::Data,
                Some(dec.decrypter.clone()),
                self.compression.clone(),
                self.log.clone(),
            );
            traverser.read_recursively(&accessor, &data_address.as_ref())?;
        }
        Ok(accessor.get_results())
    }

    pub fn write<R>(
        &self,
        name_str: &str,
        reader: R,
        enc: &EncryptHandle,
    ) -> Result<WriteStats>
    where
        R: Read + Send,
    {
        info!(self.log, "Writing data"; "name" => name_str);
        let _lock = self.aio.lock_shared();

        let mut timer = slog_perf::TimeReporter::new_with_level(
            "write",
            self.log.clone(),
            Level::Info,
        );
        timer.start("write");
        let num_threads = num_cpus::get();
        let (chunker_tx, chunker_rx) =
            mpsc::sync_channel(self.write_cpu_thread_num());

        let aio = asyncio::AsyncIO::new(self.path.clone(), self.log.clone());

        let stats = aio.stats();

        // mpmc queue used  as spmc fan-out
        let (process_tx, process_rx) = two_lock_queue::channel(num_threads);

        let data_address = crossbeam::scope(|scope| {
            scope.spawn(move || self.input_reader_thread(reader, chunker_tx));

            for _ in 0..num_threads {
                let process_rx = process_rx.clone();
                let aio = aio.clone();
                let encrypter = enc.encrypter.clone();
                let compression = self.compression.clone();
                let hasher = self.hasher.clone();
                scope.spawn(move || {
                    let processor = ChunkProcessor::new(
                        self.clone(),
                        process_rx,
                        aio,
                        encrypter,
                        compression,
                        hasher,
                    );
                    processor.run();
                });
            }
            drop(process_rx);

            let chunk_and_write = scope.spawn(move || {
                self.chunk_and_write_data_thread(
                    Box::new(chunker_rx.into_iter()),
                    process_tx,
                    aio,
                    DataType::Data,
                )
            });

            chunk_and_write.join()
        });


        let name: config::Name = data_address?.into();
        name.write_as(name_str, &self.aio)?;
        Ok(stats.get_stats())
    }
}

#[cfg(test)]
mod tests;
