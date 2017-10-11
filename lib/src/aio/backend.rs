use sgdata::SGData;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;


/// A lock held on the backend
///
/// It doesn't do much, except unlock on `drop`.
pub(crate) trait Lock {}


/// Backend API
///
/// Backend is thread-safe, and the actual work
/// is implemented by per-thread instances of it.
pub(crate) trait Backend: Send + Sync {
    /// Lock the repository exclusively
    ///
    /// Use to protect operations that are potentially destructive,
    /// like GC.
    fn lock_exclusive(&self) -> io::Result<Box<Lock>>;
    /// Lock the repository in shared mode
    ///
    /// This will only prevent anyone from grabing exclusive lock.
    /// Use to protect operations that only add new data, like `write`.
    fn lock_shared(&self) -> io::Result<Box<Lock>>;

    /// Spawn a new thread object of the backend.
    fn new_thread(&self) -> io::Result<Box<BackendThread>>;
}

pub(crate) trait BackendThread: Send {
    fn remove_dir_all(&mut self, path: PathBuf) -> io::Result<()>;

    fn rename(
        &mut self,
        src_path: PathBuf,
        dst_path: PathBuf,
    ) -> io::Result<()>;


    fn write(
        &mut self,
        path: PathBuf,
        sg: SGData,
        idempotent: bool,
    ) -> io::Result<()>;


    fn read(&mut self, path: PathBuf) -> io::Result<SGData>;

    fn remove(&mut self, path: PathBuf) -> io::Result<()>;

    fn read_metadata(&mut self, path: PathBuf) -> io::Result<super::Metadata>;
    fn list(&mut self, path: PathBuf) -> io::Result<Vec<PathBuf>>;

    fn list_recursively(
        &mut self,
        path: PathBuf,
        tx: mpsc::Sender<io::Result<Vec<PathBuf>>>,
    );
}
