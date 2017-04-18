use super::{SGBuf, DataType, PipelinePerf, Repo};
use super::chunk_writer::*;
use slog::Logger;
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
        let mut bench = PipelinePerf::new("chunk-processing", self.log.clone());

        loop {
            let input = bench.input(|| self.rx.recv());

            if let Ok(input) = input {
                let ((i, sg), digests_tx, data_type) = input;

                let digest = sg.calculate_digest();
                let chunk_path =
                    self.repo.chunk_path_by_digest(&digest, DataType::Data);
                if !chunk_path.exists() {
                    let sg = if data_type.should_compress() {
                        bench.inside(|| sg.compress())
                    } else {
                        sg
                    };
                    let sg = if data_type.should_encrypt() {
                        bench.inside(|| {
                                         sg.encrypt(&self.repo.pub_key,
                                                    &digest[0..
                                                     box_::NONCEBYTES])
                                     })
                    } else {
                        sg
                    };

                    bench.output(|| {
                        self.tx
                            .send(ChunkWriterMessage {
                                      sg: sg,
                                      digest: digest.clone(),
                                      chunk_type: DataType::Data,
                                  })
                            .expect("chunk_processor: tx.send")
                    });
                }
                bench.output(|| {
                                 digests_tx
                                     .send((i, digest))
                                     .expect("chunk_processor: digests_tx.send")
                             });
            } else {
                return;
            }
        }

    }
}
