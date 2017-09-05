

use INGRESS_BUFFER_SIZE;
use config;
use dangerous_option::DangerousOption as AutoOption;

use fs2::FileExt;
use num_cpus;
use rand;
use rand::Rng;
use sgdata::SGData;
use slog;
use slog::Logger;
use slog_perf::TimeReporter;
use std;
use std::{fs, io, mem, thread};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use two_lock_queue;
use walkdir::WalkDir;

struct WriteArgs {
    path: PathBuf,
    data: SGData,
    idempotent: bool,
    complete_tx: Option<mpsc::Sender<io::Result<()>>>,
}

/// Message sent to a worker pool
enum Message {
    Write(WriteArgs),
    Read(PathBuf, mpsc::Sender<io::Result<SGData>>),
    List(PathBuf, mpsc::Sender<io::Result<Vec<PathBuf>>>),
    ListRecursively(PathBuf, mpsc::Sender<io::Result<Vec<PathBuf>>>),
}

/// A handle to a async-io worker pool
///
/// This object abstracts away file system asynchronous operations. In the
/// future, it will be supplied/parametrized by an underlying logic,
/// implementing
/// different backends (filesystem, protocols to remote locations etc).
#[derive(Clone)]
pub struct AsyncIO {
    shared: Arc<AsyncIOShared>,
    tx: AutoOption<two_lock_queue::Sender<Message>>,
    path: PathBuf,
}

impl AsyncIO {
    pub fn new(root_path: PathBuf, log: Logger) -> Self {
        let thread_num = 4 * num_cpus::get();
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
            path: root_path,
        }
    }

    pub fn lock_exclusive(&self) -> io::Result<fs::File> {
        let lock_path = config::lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_exclusive()?;

        Ok(file)
    }

    pub fn lock_shared(&self) -> io::Result<fs::File> {
        let lock_path = config::lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_shared()?;

        Ok(file)
    }


    pub fn stats(&self) -> AsyncIOThreadShared {
        self.shared.stats.clone()
    }

    pub fn list(&self, path: PathBuf) -> AsyncIOResult<Vec<PathBuf>> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::List(path, tx))
            .expect("channel send failed");
        AsyncIOResult { rx: rx }
    }

    pub fn list_recursively(
        &self,
        path: PathBuf,
    ) -> Box<Iterator<Item = io::Result<PathBuf>>> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::ListRecursively(path, tx))
            .expect("channel send failed");

        let iter = rx.into_iter().flat_map(|batch| match batch {
            Ok(batch) => Box::new(batch.into_iter().map(Ok)) as
                Box<Iterator<Item = io::Result<PathBuf>>>,
            Err(e) => Box::new(Some(Err(e)).into_iter()) as
                Box<Iterator<Item = io::Result<PathBuf>>>,
        });
        Box::new(iter)
    }

    pub fn write(&self, path: PathBuf, sg: SGData) -> AsyncIOResult<()> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::Write(WriteArgs {
                path: path,
                data: sg,
                idempotent: false,
                complete_tx: Some(tx),
            }))
            .expect("channel send failed");
        AsyncIOResult { rx: rx }
    }

    #[allow(dead_code)]
    pub fn write_idempotent(
        &self,
        path: PathBuf,
        sg: SGData,
    ) -> AsyncIOResult<()> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::Write(WriteArgs {
                path: path,
                data: sg,
                idempotent: true,
                complete_tx: Some(tx),
            }))
            .expect("channel send failed");
        AsyncIOResult { rx: rx }
    }

    /// Will panic the worker thread if fails, but does not require
    /// managing the result
    #[allow(dead_code)]
    pub fn write_checked(&self, path: PathBuf, sg: SGData) {
        self.tx
            .send(Message::Write(WriteArgs {
                path: path,
                data: sg,
                idempotent: false,
                complete_tx: None,
            }))
            .expect("channel send failed");
    }

    pub fn write_checked_idempotent(&self, path: PathBuf, sg: SGData) {
        self.tx
            .send(Message::Write(WriteArgs {
                path: path,
                data: sg,
                idempotent: true,
                complete_tx: None,
            }))
            .expect("channel send failed");
    }

    pub fn read(&self, path: PathBuf) -> AsyncIOResult<SGData> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Message::Read(path, tx))
            .expect("channel send failed");
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
///
/// It behaves a bit like a future/promise. It is happening
/// in the background, and only calling `wait` will make sure
/// the operations completed and return result.
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
    in_progress: HashMap<PathBuf, SGData>,
}

impl Drop for AsyncIOSharedInner {
    fn drop(&mut self) {
        debug_assert!(self.in_progress.is_empty());
    }
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

        AsyncIOThreadShared {
            inner: Arc::new(Mutex::new(inner)),
        }
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
    rand_ext: String,
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
            log: log.new(o!("module" => "asyncio")),
            shared: shared,
            rx: rx,
            time_reporter: t,
            rand_ext: rand::thread_rng()
                .gen_ascii_chars()
                .take(20)
                .collect::<String>(),
        }
    }

    pub fn run(&mut self) {
        loop {
            self.time_reporter.start("rx");

            if let Ok(msg) = self.rx.recv() {
                match msg {
                    Message::Write(WriteArgs {
                        path,
                        data,
                        idempotent,
                        complete_tx,
                    }) => self.write(path, data, idempotent, complete_tx),
                    Message::Read(path, tx) => self.read(path, tx),
                    Message::List(path, tx) => self.list(path, tx),
                    Message::ListRecursively(path, tx) => {
                        self.list_recursively(path, tx)
                    }
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
        trace!(self.log, "write"; "path" => %path.display());

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
        loop {
            let mut sh = self.shared.inner.lock().unwrap();

            if sh.in_progress.contains_key(&path) {
                if idempotent {
                    return Ok(());
                } else {
                    // a bit lame, but will do, since this should not really
                    // happen in practice anyway
                    drop(sh);
                    thread::sleep(std::time::Duration::from_millis(1000));
                }
            } else {
                sh.in_progress.insert(path.clone(), sg.clone());
                break;
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

        let tmp_path = path.with_extension(format!("{}.tmp", self.rand_ext));
        let mut chunk_file = match fs::File::create(&tmp_path) {
            Ok(file) => Ok(file),
            Err(_) => {
                // Workaround
                // https://github.com/rust-lang/rust/issues/33707
                let _ = fs::create_dir_all(path.parent().unwrap());

                fs::create_dir_all(path.parent().unwrap())?;
                fs::File::create(&tmp_path)
            }
        }?;

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
        trace!(self.log, "read"; "path" => %path.display());

        let path = self.root_path.join(path);

        let res = self.read_inner(path);
        self.time_reporter.start("read send response");
        tx.send(res).expect("send failed")
    }

    fn read_inner(&mut self, path: PathBuf) -> io::Result<SGData> {
        self.time_reporter.start("read");

        // check `in_progress` and return the that if present
        {
            let sh = self.shared.inner.lock().unwrap();

            if let Some(sg) = sh.in_progress.get(&path) {
                return Ok(sg.clone());
            }
        }


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

    fn list(
        &mut self,
        path: PathBuf,
        tx: mpsc::Sender<io::Result<Vec<PathBuf>>>,
    ) {
        trace!(self.log, "list"; "path" => %path.display());

        let path = self.root_path.join(path);

        let res = self.list_inner(path);
        self.time_reporter.start("list send response");
        tx.send(res).expect("send failed")
    }

    fn list_inner(&mut self, path: PathBuf) -> io::Result<Vec<PathBuf>> {
        self.time_reporter.start("list");

        let mut v = vec![];

        let dir = fs::read_dir(path);

        match dir {
            Ok(dir) => {
                for entry in dir {
                    let entry = entry?;
                    v.push(entry.path());
                }
                Ok(v)
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    }



    fn list_recursively(
        &mut self,
        path: PathBuf,
        tx: mpsc::Sender<io::Result<Vec<PathBuf>>>,
    ) {
        trace!(self.log, "list"; "path" => %path.display());
        self.time_reporter.start("list");

        let path = self.root_path.join(path);

        if !path.exists() {
            return;
        }

        let mut v = vec![];

        for path in WalkDir::new(path) {
            match path {
                Ok(path) => {
                    if !path.file_type().is_file() {
                        continue;
                    }
                    v.push(path.path().into());
                    if v.len() > 100 {
                        tx.send(Ok(mem::replace(&mut v, vec![])))
                            .expect("send failed")
                    }
                }
                Err(e) => tx.send(Err(e.into())).expect("send failed"),
            }
        }
        if !v.is_empty() {
            tx.send(Ok(v)).expect("send failed")
        }
    }
}
