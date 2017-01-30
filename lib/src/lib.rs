#![feature(proc_macro)]

extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;
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

use std::io::{BufRead, Read, Write, Result, Error};

use std::{fs, mem, thread, io};
use std::fs::File;
use std::path::{Path, PathBuf};
use serialize::hex::{ToHex, FromHex};
use std::collections::{HashSet, VecDeque};
use std::cell::RefCell;

use fs2::FileExt;

use std::sync::mpsc;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

use sodiumoxide::crypto::{box_, pwhash, secretbox};

mod iterators;
use iterators::StoredChunks;

mod config;

const BUFFER_SIZE: usize = 16 * 1024;
const CHANNEL_SIZE: usize = 128;
const DIGEST_SIZE: usize = 32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DataType {
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

enum ChunkAssemblerMessage {
    // DataType in every Data is somewhat redundant...
    Data(Vec<u8>, Vec<Edge>, DataType, DataType),
    Exit,
}

enum ChunkMessage {
    // TODO: Make struct: data, sha, chunk_type, data_type
    Data(Vec<u8>, Vec<u8>, DataType, DataType),
    Exit,
}

/// Edge: offset in the input and sha256 sum of the chunk
type Edge = (usize, Vec<u8>);

/// Finds edges using rolling sum
struct Chunker {
    roll: rollsum::Bup,
    sha256: sha2::Sha256,
    bytes_total: usize,
    bytes_chunk: usize,
    chunks_total: usize,

    edges: Vec<Edge>,
}

const ROLLSUM_BUP_CHUNK_BITS: u32 = 17;

impl Chunker {
    pub fn new() -> Self {
        Chunker {
            roll: rollsum::Bup::new_with_chunk_bits(ROLLSUM_BUP_CHUNK_BITS),
            sha256: sha2::Sha256::new(),
            bytes_total: 0,
            bytes_chunk: 0,
            chunks_total: 0,
            edges: vec![],
        }
    }

    fn edge_found(&mut self, input_ofs: usize) {
        debug!("found edge at {}; sum: {:x}", self.bytes_total, self.roll.digest());

        debug!("sha256 hash: {}", self.sha256.result_str());

        let mut sha256 = vec![0u8; DIGEST_SIZE];
        self.sha256.result(&mut sha256);

        self.edges.push((input_ofs, sha256));

        self.chunks_total += 1;
        self.bytes_chunk = 0;

        self.sha256.reset();
        self.roll = rollsum::Bup::new_with_chunk_bits(ROLLSUM_BUP_CHUNK_BITS);
    }

    pub fn input(&mut self, buf: &[u8]) -> Vec<Edge> {
        let mut ofs: usize = 0;
        let len = buf.len();
        while ofs < len {
            if let Some(count) = self.roll.find_chunk_edge(&buf[ofs..len]) {
                self.sha256.input(&buf[ofs..ofs + count]);

                ofs += count;

                self.bytes_chunk += count;
                self.bytes_total += count;
                self.edge_found(ofs);
            } else {
                let count = len - ofs;
                self.sha256.input(&buf[ofs..len]);
                self.bytes_chunk += count;
                self.bytes_total += count;
                break;
            }
        }
        mem::replace(&mut self.edges, vec![])
    }

    pub fn finish(&mut self) -> Vec<Edge> {
        // Process the final chunk
        if self.bytes_chunk != 0 || self.bytes_total == 0 {
            self.edge_found(0);
        }
        mem::replace(&mut self.edges, vec![])
    }
}

/// Convenient function to callculate sha256 for one continous data block
fn quick_sha256(data: &[u8]) -> Vec<u8> {

    let mut sha256 = sha2::Sha256::new();
    sha256.input(data);
    let mut sha256_digest = vec![0u8; DIGEST_SIZE];
    sha256.result(&mut sha256_digest);

    sha256_digest
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

/// Store data, using ```input_f``` to get chunks of data
///
/// Return final digest
fn chunk_and_send_to_assembler<R: Read>(tx: &mpsc::SyncSender<ChunkAssemblerMessage>,
                                        mut reader: &mut R,
                                        data_type: DataType)
                                        -> Result<Vec<u8>> {
    let mut chunker = Chunker::new();

    let mut index: Vec<u8> = vec![];
    loop {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let len = reader.read(&mut buf)?;

        if len == 0 {
            break;
        }
        buf.truncate(len);

        let edges = chunker.input(&buf[..len]);

        for &(_, ref sum) in &edges {
            index.append(&mut sum.clone());
        }
        tx.send(ChunkAssemblerMessage::Data(buf, edges, DataType::Data, data_type))
            .unwrap();
    }
    let edges = chunker.finish();

    for &(_, ref sum) in &edges {
        index.append(&mut sum.clone());
    }
    tx.send(ChunkAssemblerMessage::Data(vec![], edges, DataType::Data, data_type))
        .unwrap();

    if index.len() > DIGEST_SIZE {
        let digest =
            chunk_and_send_to_assembler(tx, &mut io::Cursor::new(index), DataType::Index)?;
        assert!(digest.len() == DIGEST_SIZE);
        let index_digest = quick_sha256(&digest);
        tx.send(ChunkAssemblerMessage::Data(digest.clone(),
                                              vec![(digest.len(), index_digest.clone())],
                                              DataType::Index,
                                              DataType::Index))
            .unwrap();
        Ok(index_digest)
    } else {
        Ok(index)
    }
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
/// This type implements `io::Write` and interprets what's writen to it as a stream of digests.
///
/// For every digest written to it, it will access the corresponding chunk and write it into
/// `writer` that it wraps.
struct IndexTranslator<'a> {
    accessor: &'a ChunkAccessor,
    digest: Vec<u8>,
    writer: Option<&'a mut Write>,
    data_type: DataType,
    sec_key: Option<&'a box_::SecretKey>,
}

impl<'a> IndexTranslator<'a> {
    fn new(accessor: &'a ChunkAccessor,
           writer: Option<&'a mut Write>,
           data_type: DataType,
           sec_key: Option<&'a box_::SecretKey>)
           -> Self {
        IndexTranslator {
            accessor: accessor,
            digest: vec![],
            data_type: data_type,
            sec_key: sec_key,
            writer: writer,
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
            let &mut IndexTranslator { accessor,
                                       ref mut digest,
                                       data_type,
                                       sec_key,
                                       ref mut writer } = self;
            if let Some(ref mut writer) = *writer {
                let mut traverser = ReadContext::new(Some(writer), data_type, sec_key);
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
/// Information neccessary to complete given operation of reading given data in the repository.
struct ReadContext<'a> {
    /// Writer to write the data to; `None` will discard the data
    writer: Option<&'a mut Write>,
    /// Secret key to access the data - `None` is used for operations
    /// that don't decrypt anything
    sec_key: Option<&'a box_::SecretKey>,
    /// The type of the data to be read
    data_type: DataType,
}

impl<'a> ReadContext<'a> {
    fn new(writer: Option<&'a mut Write>,
           data_type: DataType,
           sec_key: Option<&'a box_::SecretKey>)
           -> Self {
        ReadContext {
            writer: writer,
            data_type: data_type,
            sec_key: sec_key,
        }
    }

    fn on_index(&mut self, accessor: &'a ChunkAccessor, digest: &[u8]) -> Result<()> {
        trace!("Traversing index: {}", digest.to_hex());
        let mut index_data = vec![];
        accessor.read_chunk_into(digest,
                             DataType::Index,
                             DataType::Index,
                             &mut index_data,
                             self.sec_key)?;

        assert!(index_data.len() == DIGEST_SIZE);

        let mut translator =
            IndexTranslator::new(accessor, self.writer.take(), self.data_type, self.sec_key);

        let mut sub_traverser = ReadContext::new(Some(&mut translator), DataType::Index, None);
        sub_traverser.read_recursively(accessor, &index_data)
    }

    fn on_data(&mut self, accessor: &'a ChunkAccessor, digest: &[u8]) -> Result<()> {
        trace!("Traversing data: {}", digest.to_hex());
        if let Some(writer) = self.writer.take() {
            accessor.read_chunk_into(digest, DataType::Data, self.data_type, writer, self.sec_key)
        } else {
            accessor.touch(digest)
        }
    }

    fn read_recursively(&mut self, accessor: &'a ChunkAccessor, digest: &[u8]) -> Result<()> {

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

/// `ChunkAccessor` that just reads the chunks as requested, without doing anything
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
        let mut data = Vec::with_capacity(BUFFER_SIZE);

        let data = if data_type.should_encrypt() {
            let mut ephemeral_pub = [0; box_::PUBLICKEYBYTES];
            file.read_exact(&mut ephemeral_pub)?;
            file.read_to_end(&mut data)?;
            let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES]).unwrap();
            box_::open(&data, &nonce, &box_::PublicKey(ephemeral_pub), sec_key.unwrap())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData,
                                   format!("can't decrypt chunk file: {}", digest.to_hex()))
                })?
        } else {
            file.read_to_end(&mut data)?;
            data
        };

        let data = if data_type.should_compress() {
            let mut decompressor =
                flate2::write::DeflateDecoder::new(Vec::with_capacity(data.len()));

            decompressor.write_all(&data)?;
            decompressor.finish()?
        } else {
            data
        };

        let mut sha256 = sha2::Sha256::new();
        sha256.input(&data);
        let mut sha256_digest = vec![0u8; DIGEST_SIZE];
        sha256.result(&mut sha256_digest);
        if sha256_digest != digest {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               format!("{} corrupted, data read: {}",
                                       digest.to_hex(),
                                       sha256_digest.to_hex())))
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
        self.raw.read_chunk_into(digest, chunk_type, data_type, writer, sec_key)
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
        let res = self.raw
            .read_chunk_into(digest, chunk_type, data_type, writer, sec_key);

        if res.is_err() {
            self.errors.borrow_mut().push((digest.to_owned(), res.err().unwrap()));
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
#[derive(Clone, Debug)]
pub struct WriteStats {
    pub new_chunks: usize,
    pub new_bytes: u64,
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
    pub fn init_v0(repo_path: &Path, passphrase: &str) -> Result<Repo> {
        info!("Init repo (v0 - legacy) {}", repo_path.to_string_lossy());

        Repo::ensure_repo_not_exists(repo_path)?;
        Repo::init_common_dirs(repo_path)?;

        let (pk, sk) = box_::gen_keypair();
        config::write_config_v0(repo_path, pk, sk, passphrase)?;

        let repo = Repo {
            path: repo_path.to_owned(),
            pub_key: pk,
            version: 0,
        };
        Ok(repo)
    }

    /// Create new rdedup repository
    pub fn init(repo_path: &Path, passphrase: &str) -> Result<Repo> {
        info!("Init repo {}", repo_path.to_string_lossy());
        let (pk, sk) = box_::gen_keypair();

        Repo::ensure_repo_not_exists(repo_path)?;
        Repo::init_common_dirs(repo_path)?;
        config::write_config_v1(repo_path, &pk, &sk, passphrase)?;

        let repo = Repo {
            path: repo_path.to_owned(),
            pub_key: pk,
            version: config::REPO_VERSION_CURRENT,
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
        let version_int = version.parse::<u32>()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData,
                               format!("can't parse version file; unsupported \
                                        repo format version: {}",
                                       version))
            })?;


        if version_int > config::REPO_VERSION_CURRENT {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      format!("repo version {} higher than \
                                               supported {}; update?",
                                              version,
                                              config::REPO_VERSION_CURRENT)));
        }
        // This if statement triggers the absurd_extreme_comparisons because the minimum repo
        // version is also the smallest value of a u32
        if version_int < config::REPO_VERSION_LOWEST {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                      format!("repo version {} lower than \
                                               lowest supported {}; restore \
                                               using older version?",
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

    pub fn open_v0(repo_path: &Path) -> Result<Repo> {
        info!("Open repo {}", repo_path.to_string_lossy());
        if !repo_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("repo not found: {}", repo_path.to_string_lossy())));
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

        let pubkey_str = std::str::from_utf8(&buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "pubkey data invalid: not utf8")
            })?;
        let pubkey_bytes =
            pubkey_str.from_hex()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "pubkey data invalid: not hex")
                })?;
        let pub_key = box_::PublicKey::from_slice(&pubkey_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "pubkey data invalid: can't convert to pubkey")
            })?;

        Ok(Repo {
            path: repo_path.to_owned(),
            pub_key: pub_key,
            version: version_int,
        })
    }

    pub fn open(repo_path: &Path) -> Result<Repo> {
        info!("Open repo {}", repo_path.to_string_lossy());
        if !repo_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound,
                                  format!("repo not found: {}", repo_path.to_string_lossy())));
        }

        let version = Repo::read_and_validate_version(repo_path)?;

        if version == 0 {
            return Repo::open_v0(repo_path);
        }

        let file = fs::File::open(&config::config_yml_file_path(repo_path))?;
        let config: config::Repo = serde_yaml::from_reader(file).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData,
                               format!("couldn't parse yaml: {}", e.to_string()))
            })?;

        if let config::Encryption::Curve25519(encryption_config) = config.encryption {
            Ok(Repo {
                path: repo_path.to_owned(),
                pub_key: encryption_config.pub_key,
                version: version,
            })
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData,
                               "Repo without encryptin not supported yet"))
        }
    }

    /// Remove a stored name from repo
    pub fn rm(&self, name: &str) -> Result<()> {
        info!("Remove name {}", name);
        let _lock = self.lock_write()?;
        fs::remove_file(self.name_path(name))
    }

    fn change_passphrase_v0(&self, seckey: &SecretKey, new_passphrase: &str) -> Result<()> {
        info!("Changing password");
        let _lock = self.lock_write()?;


        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();

        let derived_key = derive_key(new_passphrase, &salt)?;


        let encrypted_seckey = secretbox::seal(&(seckey.0).0, &nonce, &derived_key);

        let seckey_path = config::sec_key_file_path(&self.path);
        let seckey_path_tmp = seckey_path.with_extension("tmp");

        config::write_seckey_file(&seckey_path_tmp, &encrypted_seckey, &nonce, &salt)?;

        fs::rename(seckey_path_tmp, &seckey_path)?;

        Ok(())
    }

    /// Change the passphrase
    pub fn change_passphrase(&self, seckey: &SecretKey, new_passphrase: &str) -> Result<()> {
        if self.version == 0 {
            self.change_passphrase_v0(seckey, new_passphrase)
        } else {
            config::write_config_v1(&self.path, &self.pub_key, &seckey.0, new_passphrase)
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

    pub fn write<R: Read>(&self, name: &str, reader: &mut R) -> Result<WriteStats> {
        info!("Write name {}", name);
        let _lock = self.lock_write()?;

        let (tx_to_assembler, assembler_rx) = mpsc::sync_channel(CHANNEL_SIZE);
        let (tx_to_compressor, compressor_rx) = mpsc::sync_channel(CHANNEL_SIZE);
        let (tx_to_encrypter, encrypter_rx) = mpsc::sync_channel(CHANNEL_SIZE);
        let (tx_to_writer, writer_rx) = mpsc::sync_channel(CHANNEL_SIZE);


        let mut joins = vec![];
        joins.push(thread::spawn({
            let self_clone = self.clone();
            move || self_clone.chunk_assembler(assembler_rx, tx_to_compressor)
        }));

        joins.push(thread::spawn({
            let self_clone = self.clone();
            move || self_clone.chunk_compressor(compressor_rx, tx_to_encrypter)
        }));

        joins.push(thread::spawn({
            let self_clone = self.clone();
            move || self_clone.chunk_encrypter(encrypter_rx, tx_to_writer)
        }));

        let self_clone = self.clone();
        let chunk_writer = thread::spawn(move || self_clone.chunk_writer(writer_rx));

        let final_digest = chunk_and_send_to_assembler(&tx_to_assembler, reader, DataType::Data)?;

        tx_to_assembler.send(ChunkAssemblerMessage::Exit).unwrap();
        for join in joins.drain(..) {
            join.join().unwrap();
        }
        let write_stats = chunk_writer.join().unwrap();

        self.store_digest_as_name(&final_digest, name)?;
        Ok(write_stats)
    }

    pub fn read<W: Write>(&self, name: &str, writer: &mut W, seckey: &SecretKey) -> Result<()> {
        info!("Read name {}", name);
        let digest = self.name_to_digest(name)?;

        let _lock = self.lock_read()?;

        let accessor = self.chunk_accessor();
        let mut traverser = ReadContext::new(Some(writer), DataType::Data, Some(&seckey.0));
        traverser.read_recursively(&accessor, &digest)
    }

    pub fn du(&self, name: &str, seckey: &SecretKey) -> Result<DuResults> {
        info!("DU name {}", name);
        let _lock = self.lock_read()?;

        let digest = self.name_to_digest(name)?;

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(self);
        {
            let mut traverser =
                ReadContext::new(Some(&mut counter), DataType::Data, Some(&seckey.0));
            traverser.read_recursively(&accessor, &digest)?;
        }
        Ok(DuResults {
            chunks: accessor.get_results().scanned,
            bytes: counter.count,
        })
    }

    pub fn verify(&self, name: &str, seckey: &SecretKey) -> Result<VerifyResults> {
        info!("verify name {}", name);

        let _lock = self.lock_read()?;

        let digest = self.name_to_digest(name)?;

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(self);
        {
            let mut traverser =
                ReadContext::new(Some(&mut counter), DataType::Data, Some(&seckey.0));
            traverser.read_recursively(&accessor, &digest)?;
        }
        Ok(accessor.get_results())
    }

    // pub fn du_by_digest(&self, digest: &[u8], seckey: &SecretKey) -> Result<u64> {
    //
    // let _lock = try!(self.lock_read());
    //
    // let mut counter = CounterWriter::new();
    // {
    // let accessor = self.chunk_accessor();
    // let mut traverser = ReadContext::new(Some(&mut counter), DataType::Data, Some(&seckey.0));
    // try!(traverser.read_recursively(&accessor, &digest));
    // }
    //
    // Ok(counter.count)
    // }
    //

    fn read_hex_file(&self, path: &Path) -> Result<Vec<u8>> {
        let mut file = fs::File::open(&path)?;

        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        let str_ = std::str::from_utf8(&buf).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "seckey data invalid: not utf8")
            })?;
        let bytes =
            str_.from_hex()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "seckey data invalid: not hex")
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
            pwhash::SALTBYTES + secretbox::NONCEBYTES + secretbox::MACBYTES + box_::SECRETKEYBYTES;
        if secfile_bytes.len() != TOTAL_SECKEY_FILE_LEN {
            return Err(Error::new(io::ErrorKind::InvalidData,
                                  "seckey file is not of correct length"));
        }

        let (sealed_key, rest) =
            secfile_bytes.split_at(box_::SECRETKEYBYTES + secretbox::MACBYTES);
        let (nonce, rest) = rest.split_at(secretbox::NONCEBYTES);
        let (salt, rest) = rest.split_at(pwhash::SALTBYTES);
        assert!(rest.len() == 0);

        let salt = pwhash::Salt::from_slice(salt).unwrap();
        let nonce = secretbox::Nonce::from_slice(nonce).unwrap();

        let derived_key = derive_key(passphrase, &salt)?;

        let plain_seckey = secretbox::open(sealed_key, &nonce, &derived_key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "can't decrypt key using given passphrase")
            })?;
        let sec_key = box_::SecretKey::from_slice(&plain_seckey).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData,
                               "encrypted seckey data invalid: can't convert to seckey")
            })?;

        Ok(sec_key)
    }

    fn load_sec_key(&self, passphrase: &str) -> Result<box_::SecretKey> {

        let file = fs::File::open(&config::config_yml_file_path(&self.path))?;
        let config: config::Repo = serde_yaml::from_reader(file).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData,
                               format!("couldn't parse yaml: {}", e.to_string()))
            })?;

        if let config::Encryption::Curve25519(enc) = config.encryption {
            let derived_key = derive_key(passphrase, &enc.salt)?;

            let plain_seckey =
                secretbox::open(&enc.sealed_sec_key, &enc.nonce, &derived_key).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData,
                                       "can't decrypt key using given passphrase")
                    })?;
            let sec_key = box_::SecretKey::from_slice(&plain_seckey).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData,
                                   "encrypted seckey data invalid: can't convert to seckey")
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

    fn chunk_assembler_handle_data_with_edges(&self,
                                              tx: &mut mpsc::SyncSender<ChunkMessage>,
                                              part: Vec<u8>,
                                              mut edges: Vec<Edge>,
                                              chunk_type: DataType,
                                              data_type: DataType,
                                              previous_parts: &mut Vec<Vec<u8>>) {
        let mut prev_ofs = 0;
        for (ofs, sha256) in edges.drain(..) {
            let path = self.chunk_path_by_digest(&sha256, chunk_type);
            if !path.exists() {
                let mut chunk_data = Vec::with_capacity(BUFFER_SIZE);

                for previous_part in previous_parts.drain(..) {
                    chunk_data.write_all(&previous_part).unwrap();
                }
                if ofs != prev_ofs {
                    chunk_data.write_all(&part[prev_ofs..ofs]).unwrap();
                }
                tx.send(ChunkMessage::Data(chunk_data, sha256, chunk_type, data_type))
                    .unwrap();

            } else {
                previous_parts.clear();
            }
            debug_assert!(previous_parts.is_empty());

            prev_ofs = ofs;
        }
        if prev_ofs != part.len() {
            let mut part = part;
            previous_parts.push(part.split_off(prev_ofs))
        }
    }

    fn chunk_assembler(&self,
                       rx: mpsc::Receiver<ChunkAssemblerMessage>,
                       mut tx: mpsc::SyncSender<ChunkMessage>) {
        let mut previous_parts = vec![];

        loop {
            match rx.recv().unwrap() {
                ChunkAssemblerMessage::Exit => {
                    tx.send(ChunkMessage::Exit).unwrap();
                    assert!(previous_parts.is_empty());
                    return;
                }
                ChunkAssemblerMessage::Data(part, edges, chunk_type, data_type) => {
                    if edges.is_empty() {
                        previous_parts.push(part)
                    } else {
                        self.chunk_assembler_handle_data_with_edges(&mut tx,
                                                                    part,
                                                                    edges,
                                                                    chunk_type,
                                                                    data_type,
                                                                    &mut previous_parts)
                    }
                }
            }
        }
    }

    fn chunk_compressor(&self,
                        rx: mpsc::Receiver<ChunkMessage>,
                        tx: mpsc::SyncSender<ChunkMessage>) {
        loop {
            match rx.recv().unwrap() {
                ChunkMessage::Exit => {
                    tx.send(ChunkMessage::Exit).unwrap();
                    return;
                }
                ChunkMessage::Data(data, sha256, chunk_type, data_type) => {
                    let tx_data = if data_type.should_compress() {
                        let mut compressor =
                            flate2::write::DeflateEncoder::new(Vec::with_capacity(data.len()),
                                                               flate2::Compression::Default);

                        compressor.write_all(&data).unwrap();
                        compressor.finish().unwrap()
                    } else {
                        data
                    };
                    tx.send(ChunkMessage::Data(tx_data, sha256, chunk_type, data_type))
                        .unwrap();
                }
            }
        }
    }


    fn chunk_encrypter(&self,
                       rx: mpsc::Receiver<ChunkMessage>,
                       tx: mpsc::SyncSender<ChunkMessage>) {
        loop {
            match rx.recv().unwrap() {
                ChunkMessage::Exit => {
                    tx.send(ChunkMessage::Exit).unwrap();
                    return;
                }
                ChunkMessage::Data(data, sha256, chunk_type, data_type) => {
                    let tx_data = if data_type.should_encrypt() {
                        let mut encrypted = Vec::with_capacity(BUFFER_SIZE);
                        let pub_key = &self.pub_key;
                        let nonce = box_::Nonce::from_slice(&sha256[0..box_::NONCEBYTES]).unwrap();

                        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
                        let cipher = box_::seal(&data, &nonce, pub_key, &ephemeral_sec);
                        encrypted.write_all(&ephemeral_pub.0).unwrap();
                        encrypted.write_all(&cipher).unwrap();
                        encrypted
                    } else {
                        data
                    };

                    tx.send(ChunkMessage::Data(tx_data, sha256, chunk_type, data_type))
                        .unwrap();
                }
            }
        }
    }

    fn chunk_writer(&self, rx: mpsc::Receiver<ChunkMessage>) -> WriteStats {
        let mut queue: VecDeque<(File)> = VecDeque::with_capacity(CHANNEL_SIZE);
        // Cache paths to make sure we don't queue up an existing block
        let mut queue_paths: HashSet<PathBuf> = HashSet::new();
        let mut write_stats = WriteStats {
            new_bytes: 0,
            new_chunks: 0,
        };

        fn flush(queue: &mut VecDeque<File>, queue_paths: &mut HashSet<PathBuf>) {
            while let Some(file) = queue.pop_front() {
                file.sync_all().unwrap();
            }
            // Run renames after data sync to mitigate data writes and metadata writes contention
            for path in queue_paths.drain() {
                let tmp_path = path.with_extension("tmp");
                fs::rename(&tmp_path, &path).unwrap();
            }
        }
        loop {
            match rx.recv().unwrap() {
                ChunkMessage::Exit => {
                    flush(&mut queue, &mut queue_paths);
                    return write_stats;
                }
                ChunkMessage::Data(data, sha256, chunk_type, _) => {
                    let path = self.chunk_path_by_digest(&sha256, chunk_type);
                    if !queue_paths.contains(&path) && !path.exists() {
                        if queue.len() == CHANNEL_SIZE {
                            flush(&mut queue, &mut queue_paths);
                        }


                        write_stats.new_chunks += 1;
                        write_stats.new_bytes += data.len() as u64;
                        let tmp_path = path.with_extension("tmp");
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        let mut chunk_file = fs::File::create(&tmp_path).unwrap();
                        chunk_file.write_all(&data).unwrap();

                        // Queue chunk up for data sync and rename
                        queue_paths.insert(path);
                        queue.push_back(chunk_file);
                    }
                }
            }
        }
    }

    fn name_to_digest(&self, name: &str) -> Result<Vec<u8>> {
        debug!("Resolving name {}", name);
        let name_path = self.name_path(name);
        if !name_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound, "name file not found"));
        }

        let mut file = fs::File::open(&name_path)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        debug!("Name {} is {}", name, buf.to_hex());
        Ok(buf)
    }

    fn store_digest_as_name(&self, digest: &[u8], name: &str) -> Result<()> {
        let name_dir = self.name_dir_path();
        fs::create_dir_all(&name_dir)?;
        let name_path = self.name_path(name);

        if name_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists, "name already exists"));
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

        let mut traverser = ReadContext::new(None, DataType::Data, None);
        traverser.read_recursively(&self.recording_chunk_accessor(reachable_digests), digest)
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
        info!("List repo");
        let _lock = self.lock_read()?;

        self.list_names_nolock()
    }

    /// Return all reachable chunks
    fn list_reachable_chunks(&self) -> Result<HashSet<Vec<u8>>> {

        info!("List reachable chunks");
        let mut reachable_digests = HashSet::new();
        let all_names = self.list_names_nolock()?;
        for name in &all_names {
            match self.name_to_digest(name) {
                Ok(digest) => {
                    // Make sure digest is the standard size
                    if digest.len() == DIGEST_SIZE {
                        info!("processing {}", name);
                        self.reachable_recursively_insert(&digest, &mut reachable_digests)?;
                    } else {
                        info!("skipped name {}", name);
                    }
                }
                Err(e) => {
                    info!("skipped name {} error {}", name, e);
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

    fn chunk_path_by_digest(&self, digest: &[u8], chunk_type: DataType) -> PathBuf {
        let i_or_c = match chunk_type {
            DataType::Data => Path::new(config::DATA_SUBDIR),
            DataType::Index => Path::new(config::INDEX_SUBDIR),
        };

        self.path
            .join(i_or_c)
            .join(&digest[0..1].to_hex())
            .join(digest[1..2].to_hex())
            .join(&digest.to_hex())
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
        let index_chunks = StoredChunks::new(&self.index_dir_path(), DIGEST_SIZE)?;
        let data_chunks = StoredChunks::new(&self.chunk_dir_path(), DIGEST_SIZE)?;

        let mut result = GcResults {
            chunks: 0,
            bytes: 0,
        };

        for digest in index_chunks.chain(data_chunks) {
            let digest = digest?;
            if !reachable.contains(&digest) {
                trace!("removing {}", digest.to_hex());
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
