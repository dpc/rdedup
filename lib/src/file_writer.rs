use sgdata::SGData;
use slog::Logger;
use slog_perf::TimeReporter;
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
pub struct FileWriterMessage {
    pub sg: SGData,
    pub path: PathBuf,
}

struct FileWriterSharedInner {
    write_stats: WriteStats,
    in_progress: HashSet<PathBuf>,
}

#[derive(Clone)]
pub struct FileWriterShared {
    inner: Arc<Mutex<FileWriterSharedInner>>,
}

impl FileWriterShared {
    pub fn new() -> Self {
        let inner = FileWriterSharedInner {
            write_stats: WriteStats {
                new_bytes: 0,
                new_chunks: 0,
            },
            in_progress: Default::default(),
        };

        FileWriterShared { inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn get_stats(&self) -> WriteStats {
        let sh = self.inner.lock().unwrap();
        sh.write_stats.clone()
    }
}

pub struct FileWriterThread {
    root_path: PathBuf,
    shared: FileWriterShared,
    rx: two_lock_queue::Receiver<FileWriterMessage>,
    log: Logger,
}

impl FileWriterThread {
    pub fn new(
        root_path: PathBuf,
        shared: FileWriterShared,
        rx: two_lock_queue::Receiver<FileWriterMessage>,
        log: Logger,
    ) -> Self {

        FileWriterThread {
            root_path: root_path,
            log: log,
            shared: shared,
            rx: rx,
        }
    }

    pub fn run(&self) {
        let mut t = TimeReporter::new("chunk-writer", self.log.clone());


        while let Ok(msg) = t.start_with("rx", || self.rx.recv()) {

            t.start("processing");

            let FileWriterMessage { sg, path } = msg;
            let path = self.root_path.join(path);

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
            t.start("write");

            let tmp_path = path.with_extension("tmp");
            // Workaround
            // https://github.com/rust-lang/rust/issues/33707
            let _ = fs::create_dir_all(path.parent().unwrap());

            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut chunk_file = fs::File::create(&tmp_path).unwrap();

            let mut bytes_written = 0;
            for data_part in sg.as_parts() {
                chunk_file.write_all(data_part).unwrap();
                bytes_written += data_part.len() as u64;
            }


            let tmp_path = path.with_extension("tmp");

            t.start("fsync");

            chunk_file.sync_data().unwrap();
            fs::rename(&tmp_path, &path).unwrap();

            t.start("processing");
            let mut sh = self.shared.inner.lock().unwrap();

            sh.in_progress.remove(&path);
            sh.write_stats.new_bytes += bytes_written;
            sh.write_stats.new_chunks += 1;

            drop(sh);
        }
    }
}
