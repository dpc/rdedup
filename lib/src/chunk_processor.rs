use super::{DataType, Repo};
use super::asyncio;
use compression::ArcCompression;
use encryption::ArcEncrypter;
use hashing::ArcHasher;
use sgdata::SGData;
use slog::Logger;
use slog_perf::TimeReporter;
use std::sync::mpsc;
use two_lock_queue;

pub struct Message {
    pub data: (u64, SGData),
    pub data_type: DataType,
    pub response_tx: mpsc::Sender<(u64, Vec<u8>)>,
}

pub struct ChunkProcessor {
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
        let mut timer = TimeReporter::new("chunk-processing", self.log.clone());

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

                let digest = self.hasher.calculate_digest(&sg);
                let chunk_path =
                    self.repo.chunk_path_by_digest(&digest, DataType::Data);
                if !chunk_path.exists() {
                    let sg = if data_type.should_compress() {
                        timer.start("compress");
                        self.compressor.compress(sg).unwrap()
                    } else {
                        sg
                    };
                    let sg = if data_type.should_encrypt() {
                        timer.start("encrypt");
                        self.encrypter.encrypt(sg, &digest).unwrap()
                    } else {
                        sg
                    };

                    timer.start("tx-writer");
                    self.aio.write_checked_idempotent(
                        self.repo
                            .chunk_rel_path_by_digest(&digest, DataType::Data),
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
