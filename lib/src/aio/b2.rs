#![allow(unused)]

use serde_json;

use sgdata::SGData;
use std;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc;
use std::{fs, io};

use aio;

use super::Metadata;
use super::{Backend, BackendThread};

use backblaze_b2::raw::authorize::{B2Authorization, B2Credentials};
use backblaze_b2::raw::files::FileNameListing;
use backblaze_b2::raw::upload::UploadAuthorization;
use backblaze_b2::B2Error;
use hyper::net::HttpsConnector;
use hyper::Client;
use hyper_native_tls::NativeTlsClient;

use config;

// TODO: make a thread, that keeps updating
// a timestamp file on the backend
struct Lock {
    path: PathBuf,
}

impl Lock {
    fn new(path: PathBuf) -> Self {
        Lock { path: path }
    }
}

impl aio::Lock for Lock {}

#[derive(Debug)]
pub(crate) struct B2 {
    cred: B2Credentials,
    bucket: String,
}

struct Auth {
    auth: B2Authorization,
    upload_auth: UploadAuthorization,
}

struct B2Thread {
    cred: B2Credentials,
    auth: RefCell<Option<Auth>>,
    client: Client,
    bucket: String,
}

/// Retry operations that can fail due to network/service issues
fn retry<F, R>(instance: Option<&B2Thread>, f: F) -> io::Result<R>
where
    F: Fn() -> Result<R, B2Error>,
{
    let mut backoff = 1;
    let mut err_counter = 0;
    loop {
        let res = f();

        match res {
            Ok(ok) => return Ok(ok),
            Err(e) => {
                err_counter += 1;

                if err_counter > 5 {
                    return Err(e).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!(
                                "Gave up b2 operation after {} retries: {}",
                                err_counter, e
                            ),
                        )
                    });
                }

                if e.should_back_off() {
                    std::thread::sleep(std::time::Duration::from_secs(backoff));
                    backoff = backoff * 2;
                } else {
                    backoff = 1;
                }

                if e.should_obtain_new_authentication() {
                    if let Some(instance) = instance.as_ref() {
                        let _ = instance.reauth();
                    }
                }
            }
        }
    }
}

impl B2Thread {
    fn reauth(&self) -> io::Result<()> {
        let auth = retry(None, || {
            let auth = self.cred.authorize(&self.client)?;
            let upload_auth = auth.get_upload_url(&self.bucket, &self.client)?;
            Ok((auth, upload_auth))
        })?;
        *self.auth.borrow_mut() = Some(Auth {
            auth: auth.0,
            upload_auth: auth.1,
        });

        Ok(())
    }

    fn new_from_cred(cred: &B2Credentials, bucket: String) -> io::Result<Self> {
        let ssl = NativeTlsClient::new().map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("Couldn't create `NativeTlsClient`: {}", e),
            )
        })?;
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut i = B2Thread {
            cred: cred.clone(),
            client: client,
            auth: RefCell::new(None),
            bucket: bucket,
        };

        i.reauth()?;

        Ok(i)
    }
}

impl Backend for B2 {
    fn new_thread(&self) -> io::Result<Box<dyn BackendThread>> {
        Ok(Box::new(B2Thread::new_from_cred(
            &self.cred,
            self.bucket.clone(),
        )?))
    }

    fn lock_exclusive(&self) -> io::Result<Box<dyn aio::Lock>> {
        Ok(Box::new(Lock::new(PathBuf::from(config::LOCK_FILE))))
    }

    fn lock_shared(&self) -> io::Result<Box<dyn aio::Lock>> {
        Ok(Box::new(Lock::new(PathBuf::from(config::LOCK_FILE))))
    }
}

impl B2 {
    pub(crate) fn new(id: &str, bucket: &str, key: &str) -> Self {
        let cred = B2Credentials {
            id: id.into(),
            key: key.into(),
        };

        B2 {
            cred: cred,
            bucket: bucket.into(),
        }
    }
}

impl BackendThread for B2Thread {
    fn rename(
        &mut self,
        src_path: PathBuf,
        dst_path: PathBuf,
    ) -> io::Result<()> {
        match fs::rename(&src_path, &dst_path) {
            Ok(file) => Ok(file),
            Err(_e) => {
                fs::create_dir_all(dst_path.parent().unwrap())?;
                fs::rename(&src_path, &dst_path)
            }
        }
    }

    fn remove_dir_all(&mut self, path: PathBuf) -> io::Result<()> {
        fs::remove_dir_all(&path)
    }

    fn write(
        &mut self,
        path: PathBuf,
        sg: SGData,
        idempotent: bool,
    ) -> io::Result<()> {
        Ok(())
    }

    fn read(&mut self, path: PathBuf) -> io::Result<SGData> {
        Ok(SGData::empty())
    }

    fn remove(&mut self, path: PathBuf) -> io::Result<()> {
        Ok(())
    }

    fn read_metadata(&mut self, path: PathBuf) -> io::Result<Metadata> {
        unimplemented!();
    }

    fn list(&mut self, path: PathBuf) -> io::Result<Vec<PathBuf>> {
        let mut list: FileNameListing<serde_json::value::Value> =
            retry(Some(self), || {
                self.auth
                    .borrow_mut()
                    .as_ref()
                    .unwrap()
                    .auth
                    .list_all_file_names(
                        &self.bucket,
                        1000,
                        Some(&path.to_string_lossy()),
                        None,
                        &self.client,
                    )
            })?;

        let FileNameListing {
            mut folders,
            mut files,
            ..
        } = list;

        let v = folders
            .drain(..)
            .map(|i| i.file_name)
            .chain(files.drain(..).map(|i| i.file_name))
            .map(|s| PathBuf::from(s))
            .collect();
        Ok(v)
    }

    fn list_recursively(
        &mut self,
        path: PathBuf,
        tx: mpsc::Sender<io::Result<Vec<PathBuf>>>,
    ) {
        unimplemented!();
    }
}
