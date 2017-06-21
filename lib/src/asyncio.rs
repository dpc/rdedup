

use INGRESS_BUFFER_SIZE;
use rand;
use rand::Rng;
use sgdata::SGData;
use slog;
use slog::Logger;
use slog_perf::TimeReporter;
use std::{fs, io, thread};
use std::collections::HashSet;
use std::io::{Write, Read};
use std::path::PathBuf;
use std::sync::{Mutex, Arc};
use std::sync::mpsc;
use two_lock_queue;
use dangerous_option::DangerousOption as AutoOption;

/// Message sent to a worker pool
enum Message {
    // TODO: break into a struct
    // "bool trap"
    Write(PathBuf, SGData, bool, Option<mpsc::Sender<io::Result<()>>>),
    #[allow(unused)]
    Read(PathBuf, mpsc::Sender<io::Result<SGData>>),
}

/// A handle to a async-io worker pool
#[derive(Clone)]
pub struct AsyncIO {
    shared: Arc<AsyncIOShared>,
    tx: AutoOption<two_lock_queue::Sender<Message>>,
}

impl AsyncIO {
    pub fn new(
        root_path: PathBuf,
        log: Logger,
        thread_num: usize,
    ) -> Self {
        let (tx, rx) = two_lock_queue::channel(thread_num);

        let shared = AsyncIOThreadShared::new();

        let join = (0..thread_num)
            .map(|_| {

                let rx = rx.clone();
                let shared = shared.clone();
                let log = log.clone();
                let root_path = root_path.clone();
                thread::spawn(move || {
                    let mut thread =
                        AsyncIOThread::new(root_path, shared, rx, log);
                    thread.run();
                })
            })
            .collect();

        drop(rx);

        let shared = AsyncIOShared {
            join: join,
            log: log.clone(),
            stats: shared.clone(),
        };

            AsyncIO {
                shared: Arc::new(shared),
                tx: AutoOption::new(tx),
            }
    }

    pub fn stats(&self) -> AsyncIOThreadShared {
        self.shared.stats.clone()
    }

    pub fn write(&self, path: PathBuf, sg: SGData) -> AsyncIOResult<()> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::Write(path, sg, false, Some(tx)))
            .expect("channel send failed");
        AsyncIOResult { rx: rx }
    }

    pub fn write_idempotent(
        &self,
        path: PathBuf,
        sg: SGData,
    ) -> AsyncIOResult<()> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::Write(path, sg, true, Some(tx)))
            .expect("channel send failed");
        AsyncIOResult { rx: rx }
    }

    /// Will panic the worker thread if fails, but does not require
    /// managing the result
    pub fn write_checked(&self, path: PathBuf, sg: SGData) {
        self.tx.send(Message::Write(path, sg, false, None)).expect(
            "channel send failed",
        );
    }

    pub fn write_checked_idempotent(&self, path: PathBuf, sg: SGData) {
        self.tx.send(Message::Write(path, sg, true, None)).expect(
            "channel send failed",
        );
    }

    pub fn read(&self, path: PathBuf) -> AsyncIOResult<SGData> {
        let (tx, rx) = mpsc::channel();
        self.tx.send(Message::Read(path, tx)).expect(
            "channel send failed",
        );
        AsyncIOResult { rx: rx }
    }
}

impl Drop for AsyncIO {
    fn drop(&mut self) {
        // It is important that the tx is dropped before `shared` is.
        // Otherwise join on worker threads will hang, as they are never
        // going to receive termination.
        AutoOption::take_unchecked(&mut self.tx);
    }
}

/// Arc-ed shared `AsyncIO` data
pub struct AsyncIOShared {
    join: Vec<thread::JoinHandle<()>>,
    log: slog::Logger,
    stats: AsyncIOThreadShared,
}

impl Drop for AsyncIOShared {
    fn drop(&mut self) {

        trace!(self.log, "Waiting for all threads to finish");
        for join in self.join.drain(..) {
            join.join().expect("AsyncIO worker thread panicked")
        }
    }
}

/// A result of async io operation
#[must_use]
pub struct AsyncIOResult<T> {
    rx: mpsc::Receiver<io::Result<T>>,
}

impl<T> AsyncIOResult<T> {
    /// Block until result arrives
    pub fn wait(self) -> io::Result<T> {
        self.rx.recv().expect("No `AsyncIO` thread response")
    }
}


#[derive(Clone, Debug)]
pub struct WriteStats {
    pub new_chunks: usize,
    pub new_bytes: u64,
}


struct AsyncIOSharedInner {
    write_stats: WriteStats,
    in_progress: HashSet<PathBuf>,
}

#[derive(Clone)]
pub struct AsyncIOThreadShared {
    inner: Arc<Mutex<AsyncIOSharedInner>>,
}

impl AsyncIOThreadShared {
    pub fn new() -> Self {
        let inner = AsyncIOSharedInner {
            write_stats: WriteStats {
                new_bytes: 0,
                new_chunks: 0,
            },
            in_progress: Default::default(),
        };

        AsyncIOThreadShared { inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn get_stats(&self) -> WriteStats {
        let sh = self.inner.lock().unwrap();
        sh.write_stats.clone()
    }
}

struct AsyncIOThread {
    root_path: PathBuf,
    shared: AsyncIOThreadShared,
    rx: two_lock_queue::Receiver<Message>,
    log: Logger,
    time_reporter: TimeReporter,
}

impl AsyncIOThread {
    fn new(
        root_path: PathBuf,
        shared: AsyncIOThreadShared,
        rx: two_lock_queue::Receiver<Message>,
        log: Logger,
    ) -> Self {

        let t = TimeReporter::new("chunk-writer", log.clone());
        AsyncIOThread {
            root_path: root_path,
            log: log,
            shared: shared,
            rx: rx,
            time_reporter: t,
        }
    }

    pub fn run(&mut self) {

        loop {

            self.time_reporter.start("rx");

            if let Ok(msg) = self.rx.recv() {

                match msg {
                    Message::Write(path, sg, idempotent, tx) => {
                        self.write(path, sg, idempotent, tx)
                    }
                    Message::Read(path, tx) => self.read(path, tx),
                }
            } else {
                break;
            }
        }
    }

    fn write(
        &mut self,
        path: PathBuf,
        sg: SGData,
        idempotent: bool,
        tx: Option<mpsc::Sender<io::Result<()>>>,
    ) {

        let path = self.root_path.join(path);

        let res = self.write_inner(path, idempotent, sg);
        if let Some(tx) = tx {
            self.time_reporter.start("write send response");
            tx.send(res).expect("send failed")
        }
    }

    fn write_inner(
        &mut self,
        path: PathBuf,
        idempotent: bool,
        sg: SGData,
    ) -> io::Result<()> {

        self.time_reporter.start("processing write");

        // check `in_progress` and add atomically
        // if not already there
        {
            let mut sh = self.shared.inner.lock().unwrap();

            if idempotent && sh.in_progress.contains(&path) {
                return Ok(());
            } else {
                sh.in_progress.insert(path.clone());
            }
        }

        // check if exists on disk
        // remove from `in_progress` if it does
        if idempotent && path.exists() {
            let mut sh = self.shared.inner.lock().unwrap();
            sh.in_progress.remove(&path);
            return Ok(());
        }

        // write file to disk
        self.time_reporter.start("write");

        let ext = rand::thread_rng()
            .gen_ascii_chars()
            .take(20)
            .collect::<String>();

        let tmp_path = path.with_extension(format!("{}.tmp", ext));
        // Workaround
        // https://github.com/rust-lang/rust/issues/33707
        let _ = fs::create_dir_all(path.parent().unwrap())?;

        fs::create_dir_all(path.parent().unwrap())?;
        let mut chunk_file = fs::File::create(&tmp_path)?;

        let mut bytes_written = 0;
        for data_part in sg.as_parts() {
            chunk_file.write_all(data_part)?;
            bytes_written += data_part.len() as u64;
        }


        self.time_reporter.start("fsync");

        chunk_file.sync_data()?;
        fs::rename(&tmp_path, &path)?;

        self.time_reporter.start("stats");
        let mut sh = self.shared.inner.lock().expect("couldn't acquire a lock");

        sh.in_progress.remove(&path);
        sh.write_stats.new_bytes += bytes_written;
        sh.write_stats.new_chunks += 1;

        drop(sh);
        Ok(())
    }


    fn read(&mut self, path: PathBuf, tx: mpsc::Sender<io::Result<SGData>>) {

        let path = self.root_path.join(path);

        let res = self.read_inner(path);
        self.time_reporter.start("read send response");
        tx.send(res).expect("send failed")
    }

    fn read_inner(&mut self, path: PathBuf) -> io::Result<SGData> {

        self.time_reporter.start("read");

        let mut file = fs::File::open(path)?;

        let mut bufs = Vec::new();
        loop {

            let mut buf: Vec<u8> = vec![0u8; INGRESS_BUFFER_SIZE];
            let len = file.read(&mut buf[..])?;

            if len == 0 {
                return Ok(SGData::from_many(bufs));
            }
            buf.truncate(len);
            bufs.push(buf);
        }
    }
}
