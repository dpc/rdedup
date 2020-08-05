use super::aio;
use super::{DataType, Repo};
use compression::ArcCompression;
use crossbeam_channel;
use encryption::ArcEncrypter;
use hashing::ArcHasher;
use sgdata::SGData;
use slog::{Level, Logger};
use slog_perf::TimeReporter;
use std::io;
use std::sync::mpsc;
use {Digest, Generation};

pub(crate) struct Message {
    pub data: (u64, SGData),
    pub data_type: DataType,
    pub response_tx: mpsc::Sender<(u64, Digest)>,
}

pub(crate) struct ChunkProcessor {
    repo: Repo,
    rx: crossbeam_channel::Receiver<Message>,
    aio: aio::AsyncIO,
    log: Logger,
    encrypter: ArcEncrypter,
    compressor: ArcCompression,
    hasher: ArcHasher,
    generations: Vec<Generation>,
}

impl ChunkProcessor {
    pub fn new(
        repo: Repo,
        rx: crossbeam_channel::Receiver<Message>,
        aio: aio::AsyncIO,
        encrypter: ArcEncrypter,
        compressor: ArcCompression,
        hasher: ArcHasher,
        generations: Vec<Generation>,
    ) -> Self {
        assert!(generations.len() >= 1);
        ChunkProcessor {
            log: repo.log.clone(),
            repo,
            rx,
            aio,
            encrypter,
            compressor,
            hasher,
            generations,
        }
    }

    pub fn run(&self) {
        let mut timer = TimeReporter::new_with_level(
            "chunk-processing",
            self.log.clone(),
            Level::Debug,
        );

        let gen_strings: Vec<_> =
            self.generations.iter().map(|gen| gen.to_string()).collect();

        let last_gen_str = gen_strings.last().unwrap().to_owned();
        loop {
            timer.start("rx");

            if let Ok(input) = self.rx.recv() {
                timer.start("processing");

                let Message {
                    data,
                    response_tx,
                    data_type,
                } = input;
                let (sg_id, sg) = data;

                let digest = Digest(self.hasher.calculate_digest(&sg));

                let mut found = false;
                // lookup all generations in order, starting from current one
                // and at the end try the current gen. again, in case some other
                // thread/ instance just moved it from older generation to the
                // current one
                for gen_str in gen_strings
                    .iter()
                    .rev()
                    .chain([&last_gen_str].iter().cloned())
                {
                    let chunk_path = self.repo.chunk_rel_path_by_digest(
                        digest.as_digest_ref(),
                        gen_str,
                    );
                    match self.aio.read_metadata(chunk_path.clone()).wait() {
                        Ok(_metadata) => {
                            found = true;
                            if gen_str == &last_gen_str {
                                trace!(self.log, "already exists"; "path" => %chunk_path.display());
                            } else {
                                trace!(
                                    self.log,
                                    "already exists in previous generation";
                                    "path" => %chunk_path.display()
                                );
                                let dst_path =
                                    self.repo.chunk_rel_path_by_digest(
                                        digest.as_digest_ref(),
                                        gen_strings.last().unwrap(),
                                    );
                                self.aio
                                    .rename(
                                        chunk_path.clone(),
                                        dst_path.clone(),
                                    )
                                    .wait()
                                    .unwrap_or_else(|_e| {
                                        // chunk might have been upated
                                        // concurrently; check
                                        // if it's already in the destination
                                        if self
                                            .aio
                                            .read_metadata(dst_path.clone())
                                            .wait()
                                            .is_err()
                                        {
                                            panic!(
                                                "rename failed {} -> {}",
                                                chunk_path.display(),
                                                dst_path.display()
                                            )
                                        }
                                    });
                            }
                            break;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => panic!(
                            "read_metadata failed for {}, err: {}",
                            chunk_path.display(),
                            e
                        ),
                    }
                }

                if !found {
                    let chunk_path = self.repo.chunk_rel_path_by_digest(
                        digest.as_digest_ref(),
                        gen_strings.last().unwrap(),
                    );
                    let sg = if data_type.should_compress() {
                        trace!(self.log, "compress"; "path" => %chunk_path.display());
                        timer.start("compress");
                        self.compressor.compress(sg).unwrap()
                    } else {
                        sg
                    };

                    let sg = if data_type.should_encrypt() {
                        trace!(self.log, "encrypt"; "path" => %chunk_path.display());
                        timer.start("encrypt");
                        self.encrypter.encrypt(sg, &digest.0).unwrap()
                    } else {
                        sg
                    };

                    timer.start("tx-writer");
                    self.aio.write_checked_idempotent(
                        self.repo.chunk_rel_path_by_digest(
                            digest.as_digest_ref(),
                            &last_gen_str,
                        ),
                        sg,
                    );
                }
                timer.start("tx-digest");
                response_tx
                    .send((sg_id, digest))
                    .expect("chunk_processor: digests_tx.send")
            } else {
                return;
            }
        }
    }
}
