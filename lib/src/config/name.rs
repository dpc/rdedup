use std::io;
use asyncio;
use std::path::{Path, PathBuf};
use serde_yaml;
use SGData;
use util::*;
use DIGEST_SIZE;
use {DataAddress, OwnedDataAddress};

pub(crate) const NAME_SUBDIR: &'static str = "name";

#[derive(Serialize, Deserialize)]
pub(crate) struct Name {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub(crate) digest: Vec<u8>,
    pub(crate) index_level: u32,
}

impl Name {
    pub(crate) fn remove(name: &str, aio: &asyncio::AsyncIO) -> io::Result<()> {
        aio.remove(Path::new(NAME_SUBDIR).join(name).with_extension("yml"))
            .wait()
    }

    /// List all names
    pub(crate) fn list(aio: &asyncio::AsyncIO) -> io::Result<Vec<String>> {
        let list = aio.list(PathBuf::from(NAME_SUBDIR)).wait()?;
        Ok(
            list.iter()
                .map(|e| {
                    e.file_stem()
                        .expect("malformed name: e")
                        .to_string_lossy()
                        .to_string()
                })
                .collect(),
        )
    }

    pub fn write_as(
        &self,
        name: &str,
        aio: &asyncio::AsyncIO,
    ) -> io::Result<()> {
        let serialized_str =
            serde_yaml::to_string(self).expect("yaml serialization failed");

        let path: PathBuf = NAME_SUBDIR.into();
        let mut path = path.join(name);
        path.set_extension("yml");

        if aio.read(path.clone()).wait().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "name already exists",
            ));
        }

        aio.write(path, SGData::from_single(serialized_str.into_bytes()))
            .wait()?;
        Ok(())
    }

    pub fn load_from(name: &str, aio: &asyncio::AsyncIO) -> io::Result<Self> {
        let path: PathBuf = NAME_SUBDIR.into();
        let mut path = path.join(name);
        path.set_extension("yml");

        let config_data = aio.read(path).wait()?;
        let config_data = config_data.to_linear_vec();

        let name: Name = serde_yaml::from_reader(config_data.as_slice())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("couldn't parse yaml: {}", e.to_string()),
                )
            })?;

        if name.digest.len() != DIGEST_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parsed digest has wrong size: {}", name.digest.len()),
            ));
        }

        Ok(name)
    }
}

impl<'a> From<DataAddress<'a>> for Name {
    fn from(da: DataAddress) -> Self {
        Name {
            digest: da.digest.0.clone(),
            index_level: da.index_level,
        }
    }
}

impl From<OwnedDataAddress> for Name {
    fn from(da: OwnedDataAddress) -> Self {
        Name {
            digest: da.digest.0,
            index_level: da.index_level,
        }
    }
}
