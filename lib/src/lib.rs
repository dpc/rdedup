// {{{ extern crate ...
extern crate backblaze_b2;
extern crate base64;
extern crate blake2;
extern crate bytevec;
extern crate chrono;
extern crate crossbeam;
extern crate crossbeam_channel;
extern crate dangerous_option;
extern crate digest;
extern crate fs2;
extern crate hex;
extern crate hyper;
extern crate hyper_native_tls;
extern crate num_cpus;
extern crate owning_ref;
extern crate rand;
extern crate rdedup_cdc as rollsum;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;
extern crate sgdata;
extern crate sha2;
#[macro_use]
extern crate slog;
extern crate slog_perf;
extern crate sodiumoxide;
extern crate url;
extern crate walkdir;

#[cfg(feature = "with-bzip2")]
extern crate bzip2;
#[cfg(feature = "with-deflate")]
extern crate flate2;
#[cfg(feature = "with-xz2")]
extern crate lzma;
#[cfg(feature = "with-zstd")]
extern crate zstd;
// }}}

// {{{ use and mod
use sgdata::SGData;
use slog::{FnValue, Level, Logger};
use slog_perf::TimeReporter;
use sodiumoxide::crypto::{self, box_, secretbox};
use std::collections::HashSet;
use std::io;
use std::io::{Error, Read, Result, Write};
use std::iter::Iterator;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use url::Url;

mod iterators;

mod config;

mod aio;
use aio::*;

mod chunking;
mod hashing;

mod chunk_processor;
use chunk_processor::*;

mod sorting_recv;
use sorting_recv::SortingIterator;

mod encryption;
use encryption::EncryptionEngine;

mod compression;
use compression::ArcCompression;

mod pwhash;

pub mod settings;

mod util;
use self::util::*;

mod reading;
use self::reading::*;

mod generation;
use self::generation::*;

mod name;
use self::name::*;

mod misc;
use self::misc::*;

use std::error::Error as ErrorError;
// }}}

type ArcDecrypter = Arc<encryption::Decrypter + Send + Sync + 'static>;
type ArcEncrypter = Arc<encryption::Encrypter + Send + Sync + 'static>;

const INGRESS_BUFFER_SIZE: usize = 128 * 1024;
const DIGEST_SIZE: usize = 32;

/// Type of user provided closure that will ask user for a passphrase is needed
type PassphraseFn<'a> = &'a Fn() -> io::Result<String>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Data type (index/data)
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

pub struct VerifyResults {
    pub scanned: usize,
    pub errors: Vec<(Vec<u8>, Error)>,
}

pub struct DuResults {
    pub chunks: usize,
    pub bytes: u64,
}

/// A decryption handle
///
/// Used as an argument to operations that decrypt data.
pub struct DecryptHandle {
    decrypter: ArcDecrypter,
}

/// A encryption handle
///
/// Used as an argument to operations that encrypt data.
pub struct EncryptHandle {
    encrypter: ArcEncrypter,
}

// {{{ Repo
/// Rdedup repository handle
#[derive(Clone)]
pub struct Repo {
    url: Url,
    config: config::Repo,

    compression: compression::ArcCompression,
    hasher: hashing::ArcHasher,

    /// Logger
    log: slog::Logger,

    aio: aio::AsyncIO,
}

impl Repo {
    pub fn unlock_decrypt(
        &self,
        pass: PassphraseFn,
    ) -> io::Result<DecryptHandle> {
        info!(self.log, "Opening read handle");
        let decrypter =
            self.config.encryption.decrypter(pass, &self.config.pwhash)?;

        Ok(DecryptHandle {
            decrypter: decrypter,
        })
    }

    pub fn unlock_encrypt(
        &self,
        pass: PassphraseFn,
    ) -> io::Result<EncryptHandle> {
        info!(self.log, "Opening write handle");
        let encrypter =
            self.config.encryption.encrypter(pass, &self.config.pwhash)?;

        Ok(EncryptHandle {
            encrypter: encrypter,
        })
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
        url: &Url,
        passphrase: PassphraseFn,
        settings: settings::Repo,
        log: L,
    ) -> Result<Repo>
    where
        L: Into<Option<Logger>>,
    {
        let log = log
            .into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));

        let backend = aio::backend_from_url(url)?;
        let aio = aio::AsyncIO::new(backend, log.clone())?;

        Repo::ensure_repo_empty_or_new(&aio)?;
        let config = config::Repo::new_from_settings(passphrase, settings)?;
        config.write(&aio)?;

        let compression = config.compression.to_engine();
        let hasher = config.hashing.to_hasher();

        Ok(Repo {
            url: url.clone(),
            config: config,
            compression: compression,
            hasher: hasher,
            log: log,
            aio: aio,
        })
    }

    pub fn open<L>(url: &Url, log: L) -> Result<Repo>
    where
        L: Into<Option<Logger>>,
    {
        let log = log
            .into()
            .unwrap_or_else(|| Logger::root(slog::Discard, o!()));

        let backend = aio::backend_from_url(url)?;
        let aio = aio::AsyncIO::new(backend, log.clone())?;

        let config = config::Repo::read(&aio)?;

        let compression = config.compression.to_engine();
        let hasher = config.hashing.to_hasher();
        Ok(Repo {
            url: url.clone(),
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
            self.config.encryption.change_passphrase(
                old_p,
                new_p,
                &self.config.pwhash,
            )?;
            self.config.write(&self.aio)?;
            Ok(())
        }
    }

    /// Write a chunk of data to the repo.
    fn chunk_and_write_data_thread<'a>(
        &'a self,
        input_data_iter: Box<Iterator<Item = Vec<u8>> + Send + 'a>,
        process_tx: crossbeam_channel::Sender<chunk_processor::Message>,
        aio: aio::AsyncIO,
        data_type: DataType,
    ) -> io::Result<DataAddress> {
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

                    let chunker = chunking::Chunker::new(
                        input_data_iter.into_iter(),
                        self.config.chunking.to_engine(),
                    );

                    let mut data = util::EnumerateU64::new(chunker);

                    while let Some(i_sg) =
                        timer.start_with("rx-and-chunking", || data.next())
                    {
                        timer.start("tx");
                        let (i, sg) = i_sg;
                        process_tx.send(chunk_processor::Message {
                            data: (i as u64, sg),
                            response_tx: digests_tx.clone(),
                            data_type: data_type,
                        })
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
                Ok(DataAddress {
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

        if let Some(e) = while_ok.finish() {
            panic!("Input thread error: {}", e)
        }
    }

    fn get_chunk_accessor(
        &self,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
        generations: Vec<Generation>,
    ) -> DefaultChunkAccessor {
        DefaultChunkAccessor::new(self, decrypter, compression, generations)
    }

    fn get_recording_chunk_accessor<'a>(
        &'a self,
        accessed: &'a mut HashSet<Vec<u8>>,
        decrypter: Option<ArcDecrypter>,
        compression: ArcCompression,
        generations: Vec<Generation>,
    ) -> RecordingChunkAccessor<'a> {
        RecordingChunkAccessor::new(
            self,
            accessed,
            decrypter,
            compression,
            generations,
        )
    }

    fn wipe_generation_maybe(
        &self,
        gen: Generation,
        min_age_secs: u64,
    ) -> io::Result<()> {
        let gen_config = match gen.load_config(&self.aio) {
            Ok(c) => c,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!(
                    self.log,
                    "Generation config file not found. Rerun GC later to finish";
                    );

                return Ok(());
            }
            Err(e) => return Err(e),
        };

        if gen_config.created + chrono::Duration::seconds(min_age_secs as i64)
            > chrono::Utc::now()
        {
            info!(
                self.log,
                "Generation is not old enough. Rerun GC later to finish";
                "gen" => FnValue(|_| gen.to_string()),
                "gen-created" => gen_config.created.to_rfc3339(),
                "now" => chrono::Utc::now().to_rfc3339(),
            );
            return Ok(());
        }
        info!(
            self.log,
            "Reclaiming old generation finished. Deleting...";
            "gen" => FnValue(|_| gen.to_string()),
            );

        // Make sure chunks are successfully removed before
        // attempting to delete the generation dir itself
        // so that we don't leave garbage with no Generation
        // config file.
        substitute_err_not_found(
            self.aio
                .remove_dir_all(
                    PathBuf::from(gen.to_string()).join(NAME_SUBDIR),
                )
                .wait(),
            || (),
        )?;

        substitute_err_not_found(
            self.aio
                .remove_dir_all(
                    PathBuf::from(gen.to_string()).join(config::DATA_SUBDIR),
                )
                .wait(),
            || (),
        )?;

        self.aio
            .remove_dir_all(PathBuf::from(gen.to_string()))
            .wait()?;

        Ok(())
    }

    fn update_name_to(
        &self,
        name_str: &str,
        cur_gen: Generation,
        generations: &[Generation],
    ) -> io::Result<()> {
        // traverse all the chunks (both index and data)
        // and move all the chunks to the newest gen
        info!(self.log, "Updating name to current generation";
              "name" => name_str,
              "gen" => FnValue(|_| cur_gen.to_string()));
        let name = Name::load_from_any(name_str, generations, &self.aio)?;
        let data_address: DataAddress = name.into();

        let accessor = GenerationUpdateChunkAccessor::new(
            self,
            Arc::clone(&self.compression),
            generations.to_vec(),
        );
        {
            let traverser = ReadContext::new(&accessor);
            traverser.read_recursively(ReadRequest::new(
                DataType::Data,
                data_address.as_ref(),
                None,
                self.log.clone(),
            ))?;
        }

        Name::update_generation_to(name_str, cur_gen, generations, &self.aio)?;

        Ok(())
    }

    fn reachable_recursively_insert(
        &self,
        da: DataAddressRef,
        reachable_digests: &mut HashSet<Vec<u8>>,
        generations: Vec<Generation>,
    ) -> Result<()> {
        reachable_digests.insert(da.digest.0.into());

        let accessor = self.get_recording_chunk_accessor(
            reachable_digests,
            None,
            Arc::clone(&self.compression),
            generations,
        );
        let traverser = ReadContext::new(&accessor);
        traverser.read_recursively(ReadRequest::new(
            DataType::Data,
            da,
            None,
            self.log.clone(),
        ))
    }

    /// Return all reachable chunks
    #[allow(dead_code)] // tests
    fn list_reachable_chunks(&self) -> Result<HashSet<Vec<u8>>> {
        let generations = self.read_generations()?;
        let mut reachable_digests = HashSet::new();
        let all_names = Name::list_all(&generations, &self.aio)?;
        for name_str in &all_names {
            match Name::load_from_any(name_str, &generations, &self.aio) {
                Ok(name) => {
                    let data_address: DataAddress = name.into();
                    info!(self.log, "processing"; "name" => name_str);
                    self.reachable_recursively_insert(
                        data_address.as_ref(),
                        &mut reachable_digests,
                        generations.clone(),
                    )?;
                }
                Err(e) => {
                    info!(self.log, "skipped"; "name" => name_str, "error" =>
                          e.description());
                }
            }
        }

        Ok(reachable_digests)
    }

    fn chunk_rel_path_by_digest(
        &self,
        digest: DigestRef,
        gen_str: &str,
    ) -> PathBuf {
        self.config.nesting.get_path(
            Path::new(config::DATA_SUBDIR),
            digest.0,
            gen_str,
        )
    }

    pub fn list_names(&self) -> io::Result<Vec<String>> {
        let _lock = self.aio.lock_shared();
        Name::list_all(&self.read_generations()?, &self.aio)
    }

    /// Remove a stored name from repo
    pub fn rm(&self, name: &str) -> Result<()> {
        let _lock = self.aio.lock_exclusive();
        Name::remove_any(name, &self.read_generations()?, &self.aio)
    }

    pub fn gc(&self, min_age_secs: u64) -> Result<()> {
        let _lock = self.aio.lock_exclusive();

        let generations = self.read_generations()?;

        if generations.is_empty() {
            info!(self.log, "Nothing in the repository yet, nothing to gc");
            return Ok(());
        }

        if generations.len() == 1 {
            let new_gen = generations.last().unwrap().gen_next();
            info!(self.log, "Creating new generation"; "gen" => FnValue(|_| new_gen.to_string()));
            new_gen.write(&self.aio)?;
        } else {
            info!(self.log, "Restarting previous GC operation";
                  "gen" => FnValue(|_| generations.last().unwrap().to_string()));
        }

        loop {
            let generations = self.read_generations()?;
            assert!(!generations.is_empty());
            if generations.len() == 1 {
                info!(self.log, "One generation left - GC cycle complete";
                      "gen" => FnValue(|_| generations[0].to_string()));
                return Ok(());
            }
            let gen_oldest = generations[0];
            let gen_cur = generations.last().unwrap();

            let names = Name::list(gen_oldest, &self.aio)?;

            info!(self.log, "Names left in the generation to be GCed";
                  "count" => names.len(),
                  "gen" => FnValue(|_| gen_oldest.to_string())
                  );
            if names.is_empty() {
                self.wipe_generation_maybe(gen_oldest, min_age_secs)?;
                return Ok(());
            }
            self.update_name_to(&names[0], *gen_cur, &generations)?;
        }
    }

    pub fn read<W: Write>(
        &self,
        name_str: &str,
        writer: &mut W,
        dec: &DecryptHandle,
    ) -> Result<()> {
        let _lock = self.aio.lock_shared();

        let generations = self.read_generations()?;

        let name = Name::load_from_any(name_str, &generations, &self.aio)?;
        let data_address: DataAddress = name.into();

        let accessor = self.get_chunk_accessor(
            Some(Arc::clone(&dec.decrypter)),
            Arc::clone(&self.compression),
            generations,
        );
        let traverser = ReadContext::new(&accessor);
        traverser.read_recursively(ReadRequest::new(
            DataType::Data,
            data_address.as_ref(),
            Some(writer),
            self.log.clone(),
        ))
    }

    pub fn du(&self, name_str: &str, dec: &DecryptHandle) -> Result<DuResults> {
        let _lock = self.aio.lock_shared();

        let generations = self.read_generations()?;
        let name = Name::load_from_any(name_str, &generations, &self.aio)?;
        let data_address: DataAddress = name.into();

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(
            self,
            Some(Arc::clone(&dec.decrypter)),
            Arc::clone(&self.compression),
            generations,
        );
        {
            let traverser = ReadContext::new(&accessor);
            traverser.read_recursively(ReadRequest::new(
                DataType::Data,
                data_address.as_ref(),
                Some(&mut counter),
                self.log.clone(),
            ))?;
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

        let generations = self.read_generations()?;

        let name = Name::load_from_any(name_str, &generations, &self.aio)?;
        let data_address: DataAddress = name.into();

        let mut counter = CounterWriter::new();
        let accessor = VerifyingChunkAccessor::new(
            self,
            Some(Arc::clone(&dec.decrypter)),
            Arc::clone(&self.compression),
            generations,
        );
        {
            let traverser = ReadContext::new(&accessor);
            traverser.read_recursively(ReadRequest::new(
                DataType::Data,
                data_address.as_ref(),
                Some(&mut counter),
                self.log.clone(),
            ))?;
        }
        Ok(accessor.get_results())
    }

    fn read_generations(&self) -> io::Result<Vec<Generation>> {
        let mut list: Vec<_> = self
            .aio
            .list(PathBuf::new())
            .wait()?
            .iter()
            .filter_map(|path| path.file_name().and_then(|file| file.to_str()))
            .filter(|&item| {
                item != config::CONFIG_YML_FILE
                    && item != config::LOCK_FILE
                    && !item.ends_with(".yml")
            })
            .filter_map(|item| match Generation::try_from(item) {
                Ok(gen) => {
                    if self.aio.read_metadata(gen.config_path()).wait().is_ok()
                    {
                        Some(gen)
                    } else {
                        warn!(
                            self.log,
                            "skipping dead generation: `{}` (config missing)",
                            item,
                        );
                        None
                    }
                }
                Err(e) => {
                    warn!(
                        self.log,
                        "skipping unknown generation: `{}` due to: `{}`",
                        item,
                        e
                    );
                    None
                }
            })
            .collect();

        list.sort();
        Ok(list)
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

        let mut generations = self.read_generations()?;

        if generations.is_empty() {
            let gen_first = Generation::gen_first();
            gen_first.write(&self.aio)?;
            generations.push(gen_first);
        }

        let mut timer = slog_perf::TimeReporter::new_with_level(
            "write",
            self.log.clone(),
            Level::Info,
        );
        timer.start("write");
        let num_threads = num_cpus::get();
        let (chunker_tx, chunker_rx) =
            mpsc::sync_channel(self.write_cpu_thread_num());

        let backend = backend_from_url(&self.url)?;
        let aio = aio::AsyncIO::new(backend, self.log.clone())?;

        let stats = aio.stats();

        // mpmc queue used  as spmc fan-out
        let (process_tx, process_rx) = crossbeam_channel::bounded(num_threads);

        let data_address = crossbeam::scope(|scope| {
            scope.spawn(move || self.input_reader_thread(reader, chunker_tx));

            for _ in 0..num_threads {
                let process_rx = process_rx.clone();
                let aio = aio.clone();
                let encrypter = Arc::clone(&enc.encrypter);
                let compression = Arc::clone(&self.compression);
                let hasher = Arc::clone(&self.hasher);
                let generations = generations.clone();
                scope.spawn(move || {
                    let processor = ChunkProcessor::new(
                        self.clone(),
                        process_rx,
                        aio,
                        encrypter,
                        compression,
                        hasher,
                        generations,
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

        let data_address = data_address.map_err(|e| {
            if let Some(io_e) = e.downcast_ref::<io::Error>() {
                io::Error::new(io_e.kind(), format!("{}", io_e))
            } else {
                io::Error::new(io::ErrorKind::Other, format!("{:?}", e))
            }
        })?;

        let name: Name = data_address?.into();
        name.write_as(name_str, *generations.last().unwrap(), &self.aio)?;
        Ok(stats.get_stats())
    }
}
// }}}

#[cfg(test)]
mod tests;

// vim: foldmethod=marker foldmarker={{{,}}}
