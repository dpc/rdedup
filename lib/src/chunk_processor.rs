use super::{DataType, Repo};
use super::asyncio;
use compression::ArcCompression;
use encryption::ArcEncrypter;
use hashing::ArcHasher;
use sgdata::SGData;
use slog::{Level, Logger};
use slog_perf::TimeReporter;
use std::sync::mpsc;
use two_lock_queue;
use Digest;

pub(crate) struct Message {
    pub data: (u64, SGData),
    pub data_type: DataType,
    pub response_tx: mpsc::Sender<(u64, Digest)>,
}

pub(crate) struct ChunkProcessor {
    repo: Repo,
    rx: two_lock_queue::Receiver<Message>,
    aio: asyncio::AsyncIO,
    log: Logger,
    encrypter: ArcEncrypter,
    compressor: ArcCompression,
    hasher: ArcHasher,
}

impl ChunkProcessor {
    pub fn new(
        repo: Repo,
        rx: two_lock_queue::Receiver<Message>,
        aio: asyncio::AsyncIO,
        encrypter: ArcEncrypter,
        compressor: ArcCompression,
        hasher: ArcHasher,
    ) -> Self {
        ChunkProcessor {
            log: repo.log.clone(),
            repo: repo,
            rx: rx,
            aio: aio,
            encrypter: encrypter,
            compressor: compressor,
            hasher: hasher,
        }
    }

    pub fn run(&self) {
        let mut timer = TimeReporter::new_with_level(
            "chunk-processing",
            self.log.clone(),
            Level::Debug,
        );

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
                let chunk_path = self.repo.chunk_path_by_digest(&digest);
                if !chunk_path.exists() {
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
                        self.repo.chunk_rel_path_by_digest(&digest),
                        sg,
                    );
                } else {
                    trace!(self.log, "already exists"; "path" => %chunk_path.display());
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
