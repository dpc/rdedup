use super::{DataType, Repo};
use super::file_writer::*;
use DIGEST_SIZE;
use compression::ArcCompression;
use encryption::ArcEncrypter;
use sgdata::SGData;
use sha2::Digest;
use sha2::Sha256;
use slog::Logger;
use slog_perf::TimeReporter;
use std::sync::mpsc;
use two_lock_queue;

// TODO: Make a struct
pub type ChunkProcessorMessage = (
    (u64, SGData),
    mpsc::Sender<(u64, Vec<u8>)>,
    DataType,
);


pub struct ChunkProcessor {
    repo: Repo,
    rx: two_lock_queue::Receiver<ChunkProcessorMessage>,
    tx: two_lock_queue::Sender<FileWriterMessage>,
    log: Logger,
    encrypter: ArcEncrypter,
    compressor: ArcCompression,
}
// Calculate digest
pub fn calculate_digest(sg: &SGData) -> Vec<u8> {
    let mut sha256 = Sha256::default();

    for sg_part in sg.as_parts() {
        sha256.input(sg_part);
    }

    let mut vec_result = vec![0u8; DIGEST_SIZE];
    vec_result.copy_from_slice(&sha256.result());

    vec_result
}

impl ChunkProcessor {
    pub fn new(
        repo: Repo,
        rx: two_lock_queue::Receiver<ChunkProcessorMessage>,
        tx: two_lock_queue::Sender<FileWriterMessage>,
        encrypter: ArcEncrypter,
        compressor: ArcCompression,
    ) -> Self {
        ChunkProcessor {
            log: repo.log.clone(),
            repo: repo,
            rx: rx,
            tx: tx,
            encrypter: encrypter,
            compressor: compressor,
        }
    }

    pub fn run(&self) {
        let mut timer = TimeReporter::new("chunk-processing", self.log.clone());

        loop {
            timer.start("rx");

            if let Ok(input) = self.rx.recv() {
                timer.start("processing");

                let ((i, sg), digests_tx, data_type) = input;

                let digest = calculate_digest(&sg);
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
                    self.tx
                        .send(FileWriterMessage {
                            sg: sg,
                            path: self.repo.chunk_rel_path_by_digest(
                                &digest,
                                DataType::Data,
                            ),
                        })
                        .expect("chunk_processor: tx.send");
                }
                timer.start("tx-digest");
                digests_tx.send((i, digest)).expect(
                    "chunk_processor: digests_tx.send",
                )
            } else {
                return;
            }
        }

    }
}
