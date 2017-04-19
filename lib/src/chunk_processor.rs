use super::{SGBuf, DataType, Repo};
use super::chunk_writer::*;
use slog::Logger;
use slog_perf::TimeReporter;
use sodiumoxide::crypto::box_;
use std::sync::mpsc;
use two_lock_queue;

// TODO: Make a struct
pub type ChunkProcessorMessage = ((usize, SGBuf),
                                  mpsc::SyncSender<(usize, Vec<u8>)>,
                                  DataType);


pub struct ChunkProcessor {
    repo: Repo,
    rx: two_lock_queue::Receiver<ChunkProcessorMessage>,
    tx: two_lock_queue::Sender<ChunkWriterMessage>,
    log: Logger,
}

impl ChunkProcessor {
    pub fn new(repo: Repo,
               rx: two_lock_queue::Receiver<ChunkProcessorMessage>,
               tx: two_lock_queue::Sender<ChunkWriterMessage>)
               -> Self {
        ChunkProcessor {
            log: repo.log.clone(),
            repo: repo,
            rx: rx,
            tx: tx,
        }
    }

    pub fn run(&self) {
        let mut timer = TimeReporter::new("chunk-processing", self.log.clone());

        loop {
            timer.start("rx");

            if let Ok(input) = self.rx.recv() {
                timer.start("processing");

                let ((i, sg), digests_tx, data_type) = input;

                let digest = sg.calculate_digest();
                let chunk_path =
                    self.repo.chunk_path_by_digest(&digest, DataType::Data);
                if !chunk_path.exists() {
                    let sg = if data_type.should_compress() {
                        timer.start("compress");
                        sg.compress()
                    } else {
                        sg
                    };
                    let sg = if data_type.should_encrypt() {
                        timer.start("encrypt");
                        sg.encrypt(&self.repo.pub_key,
                                   &digest[0..box_::NONCEBYTES])
                    } else {
                        sg
                    };

                    timer.start("tx-writer");
                    self.tx
                        .send(ChunkWriterMessage {
                                  sg: sg,
                                  digest: digest.clone(),
                                  chunk_type: DataType::Data,
                              })
                        .expect("chunk_processor: tx.send");
                }
                timer.start("tx-digest");
                digests_tx
                    .send((i, digest))
                    .expect("chunk_processor: digests_tx.send")
            } else {
                return;
            }
        }

    }
}
