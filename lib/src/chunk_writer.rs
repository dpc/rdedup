use super::{SGBuf, DataType, PipelinePerf, Repo};
use slog::Logger;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, Arc};
use two_lock_queue;

#[derive(Clone, Debug)]
pub struct WriteStats {
    pub new_chunks: usize,
    pub new_bytes: u64,
}
pub struct ChunkWriterMessage {
    pub sg: SGBuf,
    pub digest: Vec<u8>,
    pub chunk_type: DataType,
}

struct ChunkWriterSharedInner {
    write_stats: WriteStats,
    in_progress: HashSet<PathBuf>,
}

#[derive(Clone)]
pub struct ChunkWriterShared {
    inner: Arc<Mutex<ChunkWriterSharedInner>>,
}

impl ChunkWriterShared {
    pub fn new() -> Self {
        let inner = ChunkWriterSharedInner {
            write_stats: WriteStats {
                new_bytes: 0,
                new_chunks: 0,
            },
            in_progress: Default::default(),
        };

        ChunkWriterShared { inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn get_stats(&self) -> WriteStats {
        let sh = self.inner.lock().unwrap();
        sh.write_stats.clone()
    }
}

pub struct ChunkWriterThread {
    repo: Repo,
    shared: ChunkWriterShared,
    rx: two_lock_queue::Receiver<ChunkWriterMessage>,
    log: Logger,
}

impl ChunkWriterThread {
    pub fn new(repo: Repo,
               shared: ChunkWriterShared,
               rx: two_lock_queue::Receiver<ChunkWriterMessage>)
               -> Self {

        ChunkWriterThread {
            log: repo.log.clone(),
            repo: repo,
            shared: shared,
            rx: rx,
        }
    }

    pub fn run(&self) {
        let mut bench = PipelinePerf::new("chunk-writer", self.log.clone());

        loop {
            match bench.input(|| self.rx.recv()) {
                Ok(msg) => {
                    let ChunkWriterMessage {
                        sg,
                        digest,
                        chunk_type,
                    } = msg;
                    let path =
                        self.repo.chunk_path_by_digest(&digest, chunk_type);

                    // check `in_progress` and add atomically
                    // if not already there
                    {
                        let mut sh = self.shared.inner.lock().unwrap();

                        if sh.in_progress.contains(&path) {
                            continue;
                        } else {
                            sh.in_progress.insert(path.clone());
                        }
                    }

                    // check if exists on disk
                    // remove from `in_progress` if it does
                    if path.exists() {
                        let mut sh = self.shared.inner.lock().unwrap();
                        sh.in_progress.remove(&path);
                        continue;
                    }

                    // write file to disk
                    let tmp_path = path.with_extension("tmp");
                    // Workaround
                    // https://github.com/rust-lang/rust/issues/33707
                    let _ = fs::create_dir_all(path.parent().unwrap());

                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    let mut chunk_file = fs::File::create(&tmp_path).unwrap();

                    let mut bytes_written = 0;
                    bench.inside(|| for data_part in sg.iter() {
                                     chunk_file.write_all(&data_part).unwrap();
                                     bytes_written += data_part.len() as u64;
                                 });

                    let tmp_path = path.with_extension("tmp");

                    bench.output(|| chunk_file.sync_data().unwrap());
                    fs::rename(&tmp_path, &path).unwrap();

                    let mut sh = self.shared.inner.lock().unwrap();

                    sh.in_progress.remove(&path);
                    sh.write_stats.new_bytes += bytes_written;
                    sh.write_stats.new_chunks += 1;

                    drop(sh);
                }
                Err(_) => {
                    break;
                }
            }
        }
    }
}
