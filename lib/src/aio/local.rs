// {{{ use and mod
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::{fs, io, mem};

use fs2::FileExt;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sgdata::SGData;
use walkdir::WalkDir;

use super::{Backend, BackendThread};
use super::{Lock, Metadata};
use crate::config;
use crate::INGRESS_BUFFER_SIZE;
// }}}

impl Lock for fs::File {}

pub(crate) fn lock_file_path(path: &Path) -> PathBuf {
    path.join(config::LOCK_FILE)
}

#[derive(Debug)]
pub struct Local {
    path: PathBuf,
}

#[derive(Debug)]
pub struct LocalThread {
    path: PathBuf,
    rand_ext: String,
}

impl Backend for Local {
    fn lock_exclusive(&self) -> io::Result<Box<dyn Lock>> {
        let lock_path = lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_exclusive()?;

        Ok(Box::new(file))
    }

    fn lock_shared(&self) -> io::Result<Box<dyn Lock>> {
        let lock_path = lock_file_path(&self.path);

        let file = fs::File::create(&lock_path)?;
        file.lock_shared()?;

        Ok(Box::new(file))
    }

    fn new_thread(&self) -> io::Result<Box<dyn BackendThread>> {
        Ok(Box::new(LocalThread {
            path: self.path.clone(),
            rand_ext: rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .collect::<String>(),
        }))
    }
}

impl Local {
    pub fn new(path: PathBuf) -> Self {
        Local { path }
    }
}

impl BackendThread for LocalThread {
    fn remove_dir_all(&mut self, path: PathBuf) -> io::Result<()> {
        let path = self.path.join(path);
        fs::remove_dir_all(&path)
    }

    fn rename(
        &mut self,
        src_path: PathBuf,
        dst_path: PathBuf,
    ) -> io::Result<()> {
        let src_path = self.path.join(src_path);
        let dst_path = self.path.join(dst_path);

        match fs::rename(&src_path, &dst_path) {
            Ok(_) => Ok(()),
            Err(_e) => {
                fs::create_dir_all(dst_path.parent().unwrap())?;
                fs::rename(&src_path, &dst_path)
            }
        }
    }

    fn write(
        &mut self,
        path: PathBuf,
        sg: SGData,
        idempotent: bool,
    ) -> io::Result<()> {
        let path = self.path.join(path);
        // check if exists on disk
        // remove from `in_progress` if it does
        if idempotent && path.exists() {
            return Ok(());
        }

        let tmp_path = path.with_extension(format!("{}.tmp", self.rand_ext));
        let mut chunk_file = match fs::File::create(&tmp_path) {
            Ok(file) => Ok(file),
            Err(_) => {
                fs::create_dir_all(path.parent().unwrap())?;
                fs::File::create(&tmp_path)
            }
        }?;

        for data_part in sg.as_parts() {
            chunk_file.write_all(data_part)?;
        }

        chunk_file.sync_data()?;
        fs::rename(&tmp_path, &path)?;

        Ok(())
    }

    fn read(&mut self, path: PathBuf) -> io::Result<SGData> {
        let path = self.path.join(path);

        let mut file = fs::File::open(&path)?;

        let mut bufs = Vec::with_capacity(16 * 1024 / INGRESS_BUFFER_SIZE);
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

    fn remove(&mut self, path: PathBuf) -> io::Result<()> {
        let path = self.path.join(path);
        fs::remove_file(&path)
    }

    fn read_metadata(&mut self, path: PathBuf) -> io::Result<Metadata> {
        let path = self.path.join(path);
        let md = fs::metadata(&path)?;
        let created = if let Ok(created) = md.created().map(Into::into) {
            created
        } else if let Ok(modified) = md.modified().map(Into::into) {
            modified
        } else {
            return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("filesystem metadata does not contain `created` or `modified` for {}", path.display())));
        };
        Ok(Metadata {
            len: md.len(),
            is_file: md.is_file(),
            created,
        })
    }

    fn list(&mut self, path: PathBuf) -> io::Result<Vec<PathBuf>> {
        let path = self.path.join(path);
        let mut v = Vec::with_capacity(128);

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
        let path = self.path.join(path);

        if !path.exists() {
            return;
        }

        let mut v = Vec::with_capacity(128);

        for path in WalkDir::new(path) {
            match path {
                Ok(path) => {
                    if !path.file_type().is_file() {
                        continue;
                    }
                    v.push(path.path().into());
                    if v.len() > 100 {
                        tx.send(Ok(mem::take(&mut v))).expect("send failed")
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

// vim: foldmethod=marker foldmarker={{{,}}}
