extern crate rollsum;
extern crate sha2;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate sodiumoxide;
extern crate flate2;
#[cfg(test)]
extern crate rand;
extern crate fs2;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate base64;
extern crate owning_ref;
extern crate two_lock_queue;
extern crate num_cpus;
extern crate crossbeam;
#[macro_use]
extern crate slog;
extern crate slog_perf;

use sha2::{Sha256, Digest};
use fs2::FileExt;

use serialize::hex::{ToHex, FromHex};
use slog::Logger;
use slog_perf::TimeReporter;

use sodiumoxide::crypto::{box_, pwhash, secretbox};

use std::{fs, io};
use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error as StdErrorError;
use std::io::{BufRead, Read, Write, Result, Error};
use std::iter::Iterator;
use std::path::{Path, PathBuf};

use std::sync::mpsc;

mod iterators;
use iterators::StoredChunks;

pub mod config;
use config::ChunkingAlgorithm;

mod sg;
use sg::*;

mod chunk_writer;
use chunk_writer::*;

mod chunk_processor;
use chunk_processor::*;

mod sorting_recv;
use sorting_recv::SortingIterator;

const INGRESS_BUFFER_SIZE: usize = 128 * 1024;
// TODO: Parametrize over repo chunk size
const ACCESSOR_BUFFER_SIZE: usize = 128 * 1024;
const DIGEST_SIZE: usize = 32;


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

/// Convenient function to calculate sha256 for one continuous data block
fn quick_sha256(data: &[u8]) -> Vec<u8> {

    let mut sha256 = Sha256::default();
    sha256.input(data);
    let mut vec_result = vec![0u8; DIGEST_SIZE];
    vec_result.copy_from_slice(&sha256.result());

    vec_result
}

/// Derive secret key from passphrase and salt
fn derive_key(passphrase: &str, salt: &pwhash::Salt) -> Result<secretbox::Key> {
    let mut derived_key = secretbox::Key([0; secretbox::KEYBYTES]);
    {
        let secretbox::Key(ref mut kb) = derived_key;
        pwhash::derive_key(kb,
                           passphrase.as_bytes(),
                           salt,
                           pwhash::OPSLIMIT_SENSITIVE,
                           pwhash::MEMLIMIT_SENSITIVE).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "can't derive encryption key from passphrase")
            })?;
    }

    Ok(derived_key)
}

/// Returns the path where the chunk should be located
fn chunk_path_by_digest(repo_dir: &Path,
                        digest: &[u8],
                        chunk_type: DataType)
                        -> PathBuf {
    let i_or_c = match chunk_type {
        DataType::Data => Path::new(config::DATA_SUBDIR),
        DataType::Index => Path::new(config::INDEX_SUBDIR),
    };

    repo_dir
        .join(i_or_c)
        .join(&digest[0..1].to_hex())
        .join(digest[1..2].to_hex())
        .join(&digest.to_hex())
}

/// Writer that counts how many bytes were written to it
struct CounterWriter {
    count: u64,
}

impl CounterWriter {
    fn new() -> Self {
        CounterWriter { count: 0 }
    }
}

impl Write for CounterWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        self.count += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Translates index stream into data stream
///
/// This type implements `io::Write` and interprets what's written to it as a
/// stream of digests.
///
/// For every digest written to it, it will access the corresponding chunk and
/// write it into `writer` that it wraps.
struct IndexTranslator<'a> {
    accessor: &'a ChunkAccessor,
    digest: Vec<u8>,
    writer: Option<&'a mut Write>,
    data_type: DataType,
    sec_key: Option<&'a box_::SecretKey>,
    log: Logger,
}

impl<'a> IndexTranslator<'a> {
    fn new(accessor: &'a ChunkAccessor,
           writer: Option<&'a mut Write>,
           data_type: DataType,
           sec_key: Option<&'a box_::SecretKey>,
           log: Logger)
           -> Self {
        IndexTranslator {
            accessor: accessor,
            digest: vec![],
            data_type: data_type,
            sec_key: sec_key,
            writer: writer,
            log: log,
        }
    }
}

impl<'a> Write for IndexTranslator<'a> {
    fn write(&mut self, mut bytes: &[u8]) -> Result<usize> {
        let total_len = bytes.len();
        loop {
            let has_already = self.digest.len();
            if (has_already + bytes.len()) < DIGEST_SIZE {
                self.digest.extend_from_slice(bytes);
                return Ok(total_len);
            }

            let needs = DIGEST_SIZE - has_already;
            self.digest.extend_from_slice(&bytes[..needs]);
            bytes = &bytes[needs..];
            let &mut IndexTranslator {
                         accessor,
                         ref mut digest,
                         data_type,
                         sec_key,
                         ref mut writer,
                         ..
                     } = self;
            if let Some(ref mut writer) = *writer {
                let mut traverser = ReadContext::new(Some(writer),
                                                     data_type,
                                                     sec_key,
                                                     self.log.clone());
                traverser.read_recursively(accessor, digest)?;
            } else {
                accessor.touch(digest)?
            }
            digest.clear();
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Read Context
///
/// Information necessary to complete given operation of reading given data in
/// the repository.
struct ReadContext<'a> {
    /// Writer to write the data to; `None` will discard the data
    writer: Option<&'a mut Write>,
    /// Secret key to access the data - `None` is used for operations
    /// that don't decrypt anything
    sec_key: Option<&'a box_::SecretKey>,
    /// The type of the data to be read
    data_type: DataType,

    log: Logger,
}

impl<'a> ReadContext<'a> {
    fn new(writer: Option<&'a mut Write>,
           data_type: DataType,
           sec_key: Option<&'a box_::SecretKey>,
           log: Logger)
           -> Self {
        ReadContext {
            writer: writer,
            data_type: data_type,
            sec_key: sec_key,
            log: log,
        }
    }

    fn on_index(&mut self,
                accessor: &'a ChunkAccessor,
                digest: &[u8])
                -> Result<()> {
        trace!(self.log, "Traversing index"; "digest" => digest.to_hex());
        let mut index_data = vec![];
        accessor
            .read_chunk_into(digest,
                             DataType::Index,
                             DataType::Index,
                             &mut index_data,
                             self.sec_key)?;

        assert_eq!(index_data.len(), DIGEST_SIZE);

        let mut translator = IndexTranslator::new(accessor,
                                                  self.writer.take(),
                                                  self.data_type,
                                                  self.sec_key,
                                                  self.log.clone());

        let mut sub_traverser = ReadContext::new(Some(&mut translator),
                                                 DataType::Index,
                                                 None,
                                                 self.log.clone());
        sub_traverser.read_recursively(accessor, &index_data)
    }

    fn on_data(&mut self,
               accessor: &'a ChunkAccessor,
               digest: &[u8])
               -> Result<()> {
        trace!(self.log, "Traversing data"; "digest" => digest.to_hex());
        if let Some(writer) = self.writer.take() {
            accessor.read_chunk_into(digest,
                                     DataType::Data,
                                     self.data_type,
                                     writer,
                                     self.sec_key)
        } else {
            accessor.touch(digest)
        }
    }

    fn read_recursively(&mut self,
                        accessor: &'a ChunkAccessor,
                        digest: &[u8])
                        -> Result<()> {

        let chunk_type = accessor.repo().chunk_type(digest)?;

        let s = &*accessor as &ChunkAccessor;
        match chunk_type {
            DataType::Index => self.on_index(s, digest),
            DataType::Data => self.on_data(s, digest),
        }
    }
}


/// Abstraction over accessing chunks stored in the repository
trait ChunkAccessor {
    fn repo(&self) -> &Repo;

    /// Read a chunk identified by `digest` into `writer`
    fn read_chunk_into(&self,
                       digest: &[u8],
                       chunk_type: DataType,
                       data_type: DataType,
                       writer: &mut Write,
                       sec_key: Option<&box_::SecretKey>)
                       -> Result<()>;


    fn touch(&self, _digest: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// `ChunkAccessor` that just reads the chunks as requested, without doing
/// anything
struct DefaultChunkAccessor<'a> {
    repo: &'a Repo,
}

impl<'a> DefaultChunkAccessor<'a> {
    fn new(repo: &'a Repo) -> Self {
        DefaultChunkAccessor { repo: repo }
    }
}

impl<'a> ChunkAccessor for DefaultChunkAccessor<'a> {
    fn repo(&self) -> &Repo {
        self.repo
    }

    fn read_chunk_into(&self,
                       digest: &[u8],
                       chunk_type: DataType,
                       data_type: DataType,
                       writer: &mut Write,
                       sec_key: Option<&box_::SecretKey>)
                       -> Result<()> {
        let path = self.repo.chunk_path_by_digest(digest, chunk_type);
        let mut file = fs::File::open(path)?;
        let mut data = Vec::with_capacity(ACCESSOR_BUFFER_SIZE);

        let data = if data_type.should_encrypt() {
            let mut ephemeral_pub = [0; box_::PUBLICKEYBYTES];
            file.read_exact(&mut ephemeral_pub)?;
            file.read_to_end(&mut data)?;
            let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES])
                .unwrap();
            box_::open(&data,
                       &nonce,
                       &box_::PublicKey(ephemeral_pub),
                       sec_key.unwrap()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData,
                                   format!("can't decrypt chunk file: {}",
                                           digest.to_hex()))
                })?
        } else {
            file.read_to_end(&mut data)?;
            data
        };

        let data = if data_type.should_compress() {
            let mut decompressor =
                flate2::write::DeflateDecoder::new(
                    Vec::with_capacity(data.len()));

            decompressor.write_all(&data)?;
            decompressor.finish()?
        } else {
            data
        };

        let mut sha256 = Sha256::default();
        sha256.input(&data);
        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.result());

        if vec_result != digest {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               format!("{} corrupted, data read: {}",
                                       digest.to_hex(),
                                       vec_result.to_hex())))
        } else {
            io::copy(&mut io::Cursor::new(data), writer)?;
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
    fn new(repo: &'a Repo, accessed: &'a mut HashSet<Vec<u8>>) -> Self {
        RecordingChunkAccessor {
            raw: DefaultChunkAccessor::new(repo),
            accessed: RefCell::new(accessed),
        }
    }
}

impl<'a> ChunkAccessor for RecordingChunkAccessor<'a> {
    fn repo(&self) -> &Repo {
        self.raw.repo()
    }

    fn touch(&self, digest: &[u8]) -> Result<()> {
        self.accessed.borrow_mut().insert(digest.to_owned());
        Ok(())
    }

    fn read_chunk_into(&self,
                       digest: &[u8],
                       chunk_type: DataType,
                       data_type: DataType,
                       writer: &mut Write,
                       sec_key: Option<&box_::SecretKey>)
                       -> Result<()> {
        self.touch(digest)?;
        self.raw
            .read_chunk_into(digest, chunk_type, data_type, writer, sec_key)
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
    fn new(repo: &'a Repo) -> Self {
        VerifyingChunkAccessor {
            raw: DefaultChunkAccessor::new(repo),
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

    fn read_chunk_into(&self,
                       digest: &[u8],
                       chunk_type: DataType,
                       data_type: DataType,
                       writer: &mut Write,
                       sec_key: Option<&box_::SecretKey>)
                       -> Result<()> {
        {
            let mut accessed = self.accessed.borrow_mut();
            if accessed.contains(digest) {
                return Ok(());
            }
            accessed.insert(digest.to_owned());
        }
        let res =
            self.raw
                .read_chunk_into(digest,
                                 chunk_type,
                                 data_type,
                                 writer,
                                 sec_key);

        if res.is_err() {
            self.errors
                .borrow_mut()
                .push((digest.to_owned(), res.err().unwrap()));
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
#[derive(Clone, Debug)]
pub struct Repo {
    /// Path of the repository
    path: PathBuf,
    /// Public key associated with the repository
    pub_key: box_::PublicKey,

    /// Repo configuration version
    version: u32,

    /// Repo Chunking Algorithm and settings
    chunking: config::ChunkingAlgorithm,

    /// Logger
    log: slog::Logger,
}

/// Opaque wrapper over secret key
pub struct SecretKey(box_::SecretKey);

impl Repo {
    fn ensure_repo_not_exists(repo_path: &Path) -> Result<()> {
        if repo_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists,
                                  format!("repo already exists: {}",
                                          repo_path.to_string_lossy())));
        }
        Ok(())
    }

    fn init_common_dirs(repo_path: &Path) -> Result<()> {
        // Workaround https://github.com/rust-lang/rust/issues/33707
        let _ = fs::create_dir_all(&repo_path.join(repo_path));

        fs::create_dir_all(&repo_path.join(config::DATA_SUBDIR))?;
        fs::create_dir_all(&repo_path.join(config::INDEX_SUBDIR))?;
        fs::create_dir_all(&repo_path.join(config::NAME_SUBDIR))?;
        Ok(())
    }

    /// Old repository config creation, should not be used anymore
    /// other than backward compatibility testing purposes
    pub fn init_v0<L>(repo_path: &Path,
                      passphrase: &str,
                      log: L)
                      -> Result<Repo>
        where L: Into<Option<Logger>>
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));
        Repo::ensure_repo_not_exists(repo_path)?;
        Repo::init_common_dirs(repo_path)?;

        let (pk, sk) = box_::gen_keypair();
        config::write_config_v0(repo_path, pk, &sk, passphrase)?;

        let repo = Repo {
            path: repo_path.to_owned(),
            pub_key: pk,
            version: 0,
            chunking: ChunkingAlgorithm::default(),
            log: log,
        };
        Ok(repo)
    }

    /// Create new rdedup repository
    pub fn init<L>(repo_path: &Path,
                   passphrase: &str,
                   chunking: ChunkingAlgorithm,
                   log: L)
                   -> Result<Repo>
        where L: Into<Option<Logger>>
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));
        // Validate ChunkingAlgorithm
        if !chunking.valid() {
            return Err(Error::new(io::ErrorKind::InvalidInput,
                                  "invalid chunking algorithm defined"));
        }

        let (pk, sk) = box_::gen_keypair();

        Repo::ensure_repo_not_exists(repo_path)?;
        Repo::init_common_dirs(repo_path)?;
        config::write_config_v1(repo_path, &pk, &sk, passphrase, chunking)?;

        let repo = Repo {
            path: repo_path.to_owned(),
            pub_key: pk,
            version: config::REPO_VERSION_CURRENT,
            chunking: chunking,
            log: log,
        };

        Ok(repo)
    }

    #[allow(unknown_lints)]
    #[allow(absurd_extreme_comparisons)]
    fn read_and_validate_version(repo_path: &Path) -> Result<u32> {
        let version_path = config::version_file_path(repo_path);
        let mut file = fs::File::open(&version_path)?;

        let mut reader = io::BufReader::new(&mut file);
        let mut version = String::new();
        reader.read_line(&mut version)?;
        let version_int = version
            .parse::<u32>()
            .map_err(|_| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        format!("can't parse version file; \
                                        unsupported repo format version: {}",
                                                version))
                     })?;


        if version_int > config::REPO_VERSION_CURRENT {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      format!("repo version {} higher than \
                                               supported {}; update?",
                                              version,
                                              config::REPO_VERSION_CURRENT)));
        }
        // This if statement triggers the absurd_extreme_comparisons because the
        // minimum repo version is also the smallest value of a u32
        if version_int < config::REPO_VERSION_LOWEST {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      format!("repo version {} lower than \
                                               lowest supported {}; \
                                               restore using older version?",
                                              version,
                                              config::REPO_VERSION_LOWEST)));
        }

        Ok(version_int)
    }

    pub fn get_seckey(&self, passphrase: &str) -> Result<SecretKey> {
        let _lock = self.lock_read()?;
        let sec_key = if self.version == 0 {
            self.load_sec_key_v0(passphrase)?
        } else {
            self.load_sec_key(passphrase)?
        };

        Ok(SecretKey(sec_key))
    }

    pub fn open_v0<L>(repo_path: &Path, log: L) -> Result<Repo>
        where L: Into<Option<Logger>>
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));
        if !repo_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("repo not found: {}",
                                          repo_path.to_string_lossy())));
        }

        let pubkey_path = config::pub_key_file_path(repo_path);
        if !pubkey_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("pubkey file not found: {}",
                                          pubkey_path.to_string_lossy())));
        }

        let version_int = Repo::read_and_validate_version(repo_path)?;

        let mut file = fs::File::open(&pubkey_path)?;

        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        let pubkey_str = std::str::from_utf8(&buf)
            .map_err(|_| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        "pubkey data invalid: not utf8")
                     })?;
        let pubkey_bytes = pubkey_str
            .from_hex()
            .map_err(|_| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        "pubkey data invalid: not hex")
                     })?;
        let pub_key = box_::PublicKey::from_slice(&pubkey_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "pubkey data invalid: can't convert to pubkey")
            })?;

        Ok(Repo {
               path: repo_path.to_owned(),
               pub_key: pub_key,
               version: version_int,
               chunking: ChunkingAlgorithm::default(),
               log: log,
           })
    }

    pub fn open<L>(repo_path: &Path, log: L) -> Result<Repo>
        where L: Into<Option<Logger>>
    {
        let log = log.into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));
        if !repo_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("repo not found: {}",
                                          repo_path.to_string_lossy())));
        }

        let version = Repo::read_and_validate_version(repo_path)?;

        if version == 0 {
            return Repo::open_v0(repo_path, log);
        }

        let file = fs::File::open(&config::config_yml_file_path(repo_path))?;
        let config: config::Repo = serde_yaml::from_reader(file)
            .map_err(|e| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        format!("couldn't parse yaml: {}",
                                                e.to_string()))
                     })?;

        if let config::Encryption::Curve25519(encryption_config) =
            config.encryption {
            Ok(Repo {
                   path: repo_path.to_owned(),
                   pub_key: encryption_config.pub_key,
                   version: version,
                   chunking: config.chunking.unwrap_or_default(),
                   log: log,
               })
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               "Repo without encryptin not supported yet"))
        }
    }

    /// Remove a stored name from repo
    pub fn rm(&self, name: &str) -> Result<()> {
        let _lock = self.lock_write()?;
        fs::remove_file(self.name_path(name))
    }

    fn change_passphrase_v0(&self,
                            seckey: &SecretKey,
                            new_passphrase: &str)
                            -> Result<()> {
        let _lock = self.lock_write()?;


        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();

        let derived_key = derive_key(new_passphrase, &salt)?;


        let encrypted_seckey =
            secretbox::seal(&(seckey.0).0, &nonce, &derived_key);

        let seckey_path = config::sec_key_file_path(&self.path);
        let seckey_path_tmp = seckey_path.with_extension("tmp");

        config::write_seckey_file(&seckey_path_tmp,
                                  &encrypted_seckey,
                                  &nonce,
                                  &salt)?;

        fs::rename(seckey_path_tmp, &seckey_path)?;

        Ok(())
    }

    /// Change the passphrase
    pub fn change_passphrase(&self,
                             seckey: &SecretKey,
                             new_passphrase: &str)
                             -> Result<()> {
        if self.version == 0 {
            self.change_passphrase_v0(seckey, new_passphrase)
        } else {
            config::write_config_v1(&self.path,
                                    &self.pub_key,
                                    &seckey.0,
                                    new_passphrase,
                                    self.chunking)
        }
    }

    fn lock_write(&self) -> Result<fs::File> {
        let lock_path = config::lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_exclusive()?;

        Ok(file)
    }

    fn lock_read(&self) -> Result<fs::File> {
        let lock_path = config::lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_shared()?;

        Ok(file)
    }


    /// Write a chunk of data to the repo.
    fn chunk_and_write_data_thread<'a>
        (&'a self,
         input_data_iter: Box<Iterator<Item = Vec<u8>> + Send + 'a>,
         process_tx: two_lock_queue::Sender<ChunkProcessorMessage>,
         writer_tx: two_lock_queue::Sender<ChunkWriterMessage>,
         data_type: DataType)
         -> io::Result<Vec<u8>>
    {
        let (digests_tx, digests_rx) = mpsc::sync_channel(num_cpus::get());

        // TODO: Instead of using collecting whole index and then writing it,
        // use a priority queue on the sender side (with some `condvar`
        // for back-pressure, to write index at the same time as data.
        crossbeam::scope(|scope| {
            scope.spawn({
                            let process_tx = process_tx.clone();
                            move || {

                    let mut timer =
                        slog_perf::TimeReporter::new("chunker",
                                                     self.log.clone());

                    let chunk_bits = match self.chunking {
                        ChunkingAlgorithm::Bup { chunk_bits: bits } => bits,
                    };

                    let chunker = Chunker::new(input_data_iter.into_iter(),
                                               BupEdgeFinder::new(chunk_bits));

                    let mut data = chunker.enumerate();


                    while let Some(i_sg) =
                        timer.start_with("rx-and-chunking", || data.next()) {
                        timer.start("tx");
                        process_tx
                            .send((i_sg, digests_tx.clone(), data_type))
                            .expect("process_tx.send(...)")
                    }
                    drop(digests_tx);
                }
                        });

            let mut digests_rx = SortingIterator::new(digests_rx.into_iter());

            let first_digest =
                digests_rx.next().expect("At least one index digest");

            if let Some(second_digest) = digests_rx.next() {
                let mut two_first = vec![first_digest, second_digest];
                let digest =
                    self.chunk_and_write_data_thread(
                        Box::new(two_first.drain(..).chain(digests_rx)
                                 .map(|i_sg| i_sg)),
                                 process_tx,
                                 writer_tx.clone(),
                                 DataType::Index,
                                 )?;

                let index_digest = quick_sha256(&digest);

                writer_tx
                    .send(ChunkWriterMessage {
                              sg: SGBuf::from_single(digest),
                              digest: index_digest.clone(),
                              chunk_type: DataType::Index,
                          })
                    .expect("writer_tx.send(...)");
                Ok(index_digest)

            } else {
                Ok(first_digest)
            }
        })
    }

    /// Number of threads to use to parallelize CPU-intense part of
    /// the workload.
    fn write_cpu_thread_num(&self) -> usize {
        num_cpus::get()
    }

    fn input_reader_thread<R>(&self,
                              reader: R,
                              chunker_tx: mpsc::SyncSender<Vec<u8>>)
        where R: Read + Send
    {
        let mut time = TimeReporter::new("input-reader", self.log.clone());

        let r2vi = ReaderVecIter::new(reader, INGRESS_BUFFER_SIZE);
        let mut while_ok = WhileOk::new(r2vi);

        while let Some(buf) = time.start_with("input", || while_ok.next()) {
            time.start("tx");
            chunker_tx.send(buf).unwrap()
        }
    }

    pub fn write<R>(&self, name: &str, reader: R) -> Result<WriteStats>
        where R: Read + Send
    {
        info!(self.log, "Writing data"; "name" => name);
        let _lock = self.lock_write()?;

        let num_threads = num_cpus::get();
        let (writer_tx, writer_rx) =
            two_lock_queue::channel(4 * self.write_cpu_thread_num());

        let (chunker_tx, chunker_rx) =
            mpsc::sync_channel(self.write_cpu_thread_num());

        // mpmc queue used  as spmc fan-out
        let (process_tx, process_rx) = two_lock_queue::channel(num_threads);



        let (final_digest, writer_stats) = crossbeam::scope(|scope| {

            scope.spawn(move || self.input_reader_thread(reader, chunker_tx));


            for _ in 0..num_threads {
                let process_rx = process_rx.clone();
                let writer_tx = writer_tx.clone();
                scope.spawn(move || {
                                let processor =
                                    ChunkProcessor::new(self.clone(),
                                                        process_rx,
                                                        writer_tx);
                                processor.run();
                            });
            }
            drop(process_rx);

            let chunk_and_write =
                scope.spawn(move || {
                                self.chunk_and_write_data_thread(
                                    Box::new(chunker_rx.into_iter()),
                                    process_tx,
                                    writer_tx,
                                    DataType::Data)
                            });

            let writer =
                scope.spawn(move || self.chunk_writer_thread(writer_rx));

            let final_digest = chunk_and_write.join();

            let writer_stats = writer.join();
            (final_digest, writer_stats)
        });


        self.store_digest_as_name(&final_digest?, name)?;
        Ok(writer_stats)
    }

    pub fn read<W: Write>(&self,
                          name: &str,
                          writer: &mut W,
                          seckey: &SecretKey)
                          -> Result<()> {
        let digest = self.name_to_digest(name)?;

        let _lock = self.lock_read()?;

        let accessor = self.chunk_accessor();
        let mut traverser = ReadContext::new(Some(writer),
                                             DataType::Data,
                                             Some(&seckey.0),
                                             self.log.clone());
        traverser.read_recursively(&accessor, &digest)
    }

    pub fn du(&self, name: &str, seckey: &SecretKey) -> Result<DuResults> {
        let _lock = self.lock_read()?;

        let digest = self.name_to_digest(name)?;

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(self);
        {
            let mut traverser = ReadContext::new(Some(&mut counter),
                                                 DataType::Data,
                                                 Some(&seckey.0),
                                                 self.log.clone());
            traverser.read_recursively(&accessor, &digest)?;
        }
        Ok(DuResults {
               chunks: accessor.get_results().scanned,
               bytes: counter.count,
           })
    }

    pub fn verify(&self,
                  name: &str,
                  seckey: &SecretKey)
                  -> Result<VerifyResults> {
        let _lock = self.lock_read()?;

        let digest = self.name_to_digest(name)?;

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(self);
        {
            let mut traverser = ReadContext::new(Some(&mut counter),
                                                 DataType::Data,
                                                 Some(&seckey.0),
                                                 self.log.clone());
            traverser.read_recursively(&accessor, &digest)?;
        }
        Ok(accessor.get_results())
    }

    fn read_hex_file(&self, path: &Path) -> Result<Vec<u8>> {
        let mut file = fs::File::open(&path)?;

        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        let str_ = std::str::from_utf8(&buf)
            .map_err(|_| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        "seckey data invalid: not utf8")
                     })?;
        let bytes = str_.from_hex()
            .map_err(|_| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        "seckey data invalid: not hex")
                     })?;
        Ok(bytes)
    }

    fn load_sec_key_v0(&self, passphrase: &str) -> Result<box_::SecretKey> {
        let seckey_path = config::sec_key_file_path(&self.path);
        if !seckey_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("seckey file not found: {}",
                                          seckey_path.to_string_lossy())));
        }


        let secfile_bytes = self.read_hex_file(&seckey_path)?;

        const TOTAL_SECKEY_FILE_LEN: usize =
            pwhash::SALTBYTES + secretbox::NONCEBYTES + secretbox::MACBYTES +
            box_::SECRETKEYBYTES;
        if secfile_bytes.len() != TOTAL_SECKEY_FILE_LEN {
            return Err(Error::new(io::ErrorKind::InvalidData,
                                  "seckey file is not of correct length"));
        }

        let (sealed_key, rest) =
            secfile_bytes.split_at(box_::SECRETKEYBYTES + secretbox::MACBYTES);
        let (nonce, rest) = rest.split_at(secretbox::NONCEBYTES);
        let (salt, rest) = rest.split_at(pwhash::SALTBYTES);
        assert_eq!(rest.len(), 0);

        let salt = pwhash::Salt::from_slice(salt).unwrap();
        let nonce = secretbox::Nonce::from_slice(nonce).unwrap();

        let derived_key = derive_key(passphrase, &salt)?;

        let plain_seckey =
            secretbox::open(sealed_key, &nonce, &derived_key).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData,
                                   "can't decrypt key using given passphrase")
                })?;
        let sec_key = box_::SecretKey::from_slice(&plain_seckey).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "encrypted seckey data invalid: can't convert \
                                to seckey")
            })?;

        Ok(sec_key)
    }

    fn load_sec_key(&self, passphrase: &str) -> Result<box_::SecretKey> {

        let file = fs::File::open(&config::config_yml_file_path(&self.path))?;
        let config: config::Repo = serde_yaml::from_reader(file)
            .map_err(|e| {
                         io::Error::new(io::ErrorKind::InvalidData,
                                        format!("couldn't parse yaml: {}",
                                                e.to_string()))
                     })?;

        if let config::Encryption::Curve25519(enc) = config.encryption {
            let derived_key = derive_key(passphrase, &enc.salt)?;

            let plain_seckey = secretbox::open(&enc.sealed_sec_key,
                                               &enc.nonce,
                                               &derived_key).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData,
                                   "can't decrypt key using given passphrase")
                })?;
            let sec_key =
                box_::SecretKey::from_slice(&plain_seckey).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData,
                                       "encrypted seckey data invalid: can't \
                                        convert to seckey")
                    })?;



            Ok(sec_key)

        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               "Repo without encryptin not supported yet"))
        }
    }

    fn chunk_accessor(&self) -> DefaultChunkAccessor {
        DefaultChunkAccessor::new(self)
    }

    fn recording_chunk_accessor<'a>(&'a self,
                                    accessed: &'a mut HashSet<Vec<u8>>)
                                    -> RecordingChunkAccessor<'a> {
        RecordingChunkAccessor::new(self, accessed)
    }

    fn chunk_writer_thread(&self,
                           rx: two_lock_queue::Receiver<ChunkWriterMessage>)
                           -> WriteStats {

        let shared = ChunkWriterShared::new();

        crossbeam::scope(|scope| {
            // Unlike CPU-intense workload, it's hard to come up with one
            // formula for best number of `fdatasync` threads for everyone.
            // Each buffer is blocked on one chunk, so the longer the chunks,
            // the less threads are needed to saturate the disk and so on. Some
            // form of run-time scaling would be best. I picked some reasonable
            // that also works well for me with defaults. --dpc
            let thread_num = 4 * self.write_cpu_thread_num();

            for _ in 0..thread_num {
                // let self_clone = self.clone();
                let rx = rx.clone();
                let shared = shared.clone();
                scope.spawn(move || {
                                let thread =
                                    ChunkWriterThread::new(self.clone(),
                                                           shared,
                                                           rx);
                                thread.run();
                            });
            }
            drop(rx);
        });


        shared.get_stats()
    }

    fn name_to_digest(&self, name: &str) -> Result<Vec<u8>> {
        let name_path = self.name_path(name);
        if !name_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  "name file not found"));
        }

        let mut file = fs::File::open(&name_path)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        debug!(self.log, "Resolved"; "name" => name, "digest" => buf.to_hex());
        Ok(buf)
    }

    fn store_digest_as_name(&self, digest: &[u8], name: &str) -> Result<()> {
        let name_dir = self.name_dir_path();
        fs::create_dir_all(&name_dir)?;
        let name_path = self.name_path(name);

        if name_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists,
                                  "name already exists"));
        }

        let mut file = fs::File::create(&name_path)?;

        file.write_all(digest)?;
        Ok(())
    }


    fn reachable_recursively_insert(&self,
                                    digest: &[u8],
                                    reachable_digests: &mut HashSet<Vec<u8>>)
                                    -> Result<()> {
        reachable_digests.insert(digest.to_owned());

        let mut traverser =
            ReadContext::new(None, DataType::Data, None, self.log.clone());
        traverser
            .read_recursively(&self.recording_chunk_accessor(reachable_digests),
                              digest)
    }

    /// List all names
    fn list_names_nolock(&self) -> Result<Vec<String>> {
        let mut ret: Vec<String> = vec![];

        let name_dir = self.name_dir_path();
        for entry in fs::read_dir(name_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            ret.push(name)
        }

        Ok(ret)
    }

    /// List all names
    pub fn list_names(&self) -> Result<Vec<String>> {
        let _lock = self.lock_read()?;

        self.list_names_nolock()
    }

    /// Return all reachable chunks
    fn list_reachable_chunks(&self) -> Result<HashSet<Vec<u8>>> {

        let mut reachable_digests = HashSet::new();
        let all_names = self.list_names_nolock()?;
        for name in &all_names {
            match self.name_to_digest(name) {
                Ok(digest) => {
                    // Make sure digest is the standard size
                    if digest.len() == DIGEST_SIZE {
                        info!(self.log, "processing"; "name" => name);
                        self.reachable_recursively_insert(
                            &digest, &mut reachable_digests
                            )?;
                    } else {
                        info!(self.log, "skipped";  "name" => name);
                    }
                }
                Err(e) => {
                    info!(self.log, "skipped"; "name" => name, "error" =>
                          e.description());
                }
            };
        }
        Ok(reachable_digests)
    }

    fn chunk_type(&self, digest: &[u8]) -> Result<DataType> {
        for i in &[DataType::Index, DataType::Data] {
            let file_path = self.chunk_path_by_digest(digest, *i);
            if file_path.exists() {
                return Ok(*i);
            }
        }
        Err(Error::new(io::ErrorKind::NotFound,
                       format!("chunk file missing: {}", digest.to_hex())))
    }

    fn chunk_path_by_digest(&self,
                            digest: &[u8],
                            chunk_type: DataType)
                            -> PathBuf {
        chunk_path_by_digest(&self.path, digest, chunk_type)
    }

    fn rm_chunk_by_digest(&self, digest: &[u8]) -> Result<u64> {
        let chunk_type = self.chunk_type(digest)?;
        let path = self.chunk_path_by_digest(digest, chunk_type);
        let md = fs::metadata(&path)?;
        fs::remove_file(path)?;
        Ok(md.len())
    }
    pub fn gc(&self) -> Result<GcResults> {

        let _lock = self.lock_write()?;

        let reachable = self.list_reachable_chunks().unwrap();
        let index_chunks = StoredChunks::new(&self.index_dir_path(),
                                             DIGEST_SIZE,
                                             self.log.clone())?;
        let data_chunks = StoredChunks::new(&self.chunk_dir_path(),
                                            DIGEST_SIZE,
                                            self.log.clone())?;

        let mut result = GcResults {
            chunks: 0,
            bytes: 0,
        };

        for digest in index_chunks.chain(data_chunks) {
            let digest = digest?;
            if !reachable.contains(&digest) {
                trace!(self.log, "removing chunk"; "digest" => digest.to_hex());
                let bytes = self.rm_chunk_by_digest(&digest)?;
                result.chunks += 1;
                result.bytes += bytes;
            }
        }

        Ok(result)
    }

    fn name_dir_path(&self) -> PathBuf {
        self.path.join(config::NAME_SUBDIR)
    }

    fn index_dir_path(&self) -> PathBuf {
        self.path.join(config::INDEX_SUBDIR)
    }

    fn chunk_dir_path(&self) -> PathBuf {
        self.path.join(config::DATA_SUBDIR)
    }

    fn name_path(&self, name: &str) -> PathBuf {
        self.name_dir_path().join(name)
    }
}

#[cfg(test)]
mod tests;
