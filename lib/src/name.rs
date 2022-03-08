use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::aio;
use crate::util::*;
use crate::SGData;
use crate::DIGEST_SIZE;
use crate::{DataAddress, DataAddressRef, Generation};

pub(crate) const NAME_SUBDIR: &str = "name";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Name {
    #[serde(serialize_with = "as_hex", deserialize_with = "from_hex")]
    pub(crate) digest: Vec<u8>,
    pub(crate) index_level: u32,
    #[serde(serialize_with = "as_rfc3339", deserialize_with = "from_rfc3339")]
    /// The UTC timestamp when this `Name` was created.
    pub(crate) created: chrono::DateTime<chrono::Utc>,
}

// TODO: I am very displeased with myself how this
// API looks like. Everything is mashed together here:
// serialization, domain entity, file system operations.
// `Generation` is similar.
// Smells badly, but oh well...
// -- dpc
impl Name {
    /// The UTC timestamp when this `Name` was created.
    #[allow(unused)]
    pub(crate) fn created(&self) -> chrono::DateTime<chrono::Utc> {
        self.created
    }

    pub(crate) fn remove(
        name: &str,
        gen: Generation,
        aio: &aio::AsyncIO,
    ) -> io::Result<()> {
        let path = Name::path(name, gen);
        aio.remove(path).wait()
    }

    pub(crate) fn remove_any(
        name: &str,
        gens: &[Generation],
        aio: &aio::AsyncIO,
    ) -> io::Result<()> {
        for gen in gens.iter().rev() {
            match Name::remove(name, *gen, aio) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                res => return res,
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ))
    }

    pub(crate) fn update_generation_to(
        name: &str,
        cur_generation: Generation,
        gens: &[Generation],
        aio: &aio::AsyncIO,
    ) -> io::Result<()> {
        let dst_path = Name::path(name, cur_generation);
        for gen in gens.iter().rev() {
            if *gen == cur_generation {
                continue;
            }

            let src_path = Name::path(name, *gen);

            match aio.rename(src_path, dst_path.clone()).wait() {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                res => {
                    return res;
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ))
    }

    pub(crate) fn path(name: &str, gen: Generation) -> PathBuf {
        let mut path: PathBuf = gen.to_string().into();
        path.push(NAME_SUBDIR);
        path.push(name.to_string() + ".yml");
        path
    }

    /// List all names
    pub(crate) fn list(
        gen: Generation,
        aio: &aio::AsyncIO,
    ) -> io::Result<Vec<String>> {
        let list = substitute_err_not_found(
            aio.list(PathBuf::from(gen.to_string()).join(NAME_SUBDIR))
                .wait(),
            Vec::new,
        )?;

        Ok(list
            .iter()
            .map(|e| {
                e.file_stem()
                    .unwrap_or_else(|| panic!("malformed name: {:?}", e))
                    .to_string_lossy()
                    .to_string()
            })
            .collect())
    }

    pub fn list_all(
        gens: &[Generation],
        aio: &aio::AsyncIO,
    ) -> io::Result<Vec<String>> {
        let mut res = vec![];

        for gen in gens.iter().rev() {
            res.append(&mut Name::list(*gen, aio)?);
        }

        Ok(res)
    }

    pub fn write_as(
        &self,
        name: &str,
        gen: Generation,
        aio: &aio::AsyncIO,
    ) -> io::Result<()> {
        let serialized_str =
            serde_yaml::to_string(self).expect("yaml serialization failed");

        let path = Name::path(name, gen);

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

    /// Attempts to deserialize `path` as a `Name`. For backwards compatibility,
    /// if the source `Name` does not have populated `created` information,
    /// populates from filesystem metadata.
    fn try_deserialize(
        name_str: &str,
        gen: Generation,
        aio: &aio::AsyncIO,
    ) -> Result<Name, io::Error> {
        let path = Name::path(name_str, gen);

        let config_data = aio.read(path.clone()).wait()?;
        let config_data = config_data.into_linear_vec();

        if let Ok(name) = serde_yaml::from_reader(config_data.as_slice()) {
            return Ok(name); // Ok-rewrap for change in Result Error type
        }

        #[derive(Debug, Deserialize)]
        /// Legacy version of `Name` missing `created` field
        struct NameLegacyV3 {
            #[serde(deserialize_with = "from_hex")]
            digest: Vec<u8>,
            index_level: u32,
        }

        let NameLegacyV3 {
            digest,
            index_level,
        } = serde_yaml::from_reader(config_data.as_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("couldn't parse yaml: {}", e),
            )
        })?;

        let created = aio.read_metadata(path.clone()).wait()?.created;

        let name = Name {
            digest,
            index_level,
            created,
        };

        let is_serde_err = serde_yaml::to_string(&name)
            .map(|serialized_str| {
                aio.write(
                    path,
                    SGData::from_single(serialized_str.into_bytes()),
                )
                .wait()
            })
            .is_err();
        // re-write the `Name` configuration to include the `created` field.
        if is_serde_err {
            // FIXME: log the write error?
        }
        Ok(name)
    }

    pub fn load_from(
        name: &str,
        gen: Generation,
        aio: &aio::AsyncIO,
    ) -> io::Result<Self> {
        let name = Name::try_deserialize(name, gen, aio)?;

        if name.digest.len() != DIGEST_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parsed digest has wrong size: {}", name.digest.len()),
            ));
        }

        Ok(name)
    }

    pub(crate) fn load_from_any(
        name: &str,
        gens: &[Generation],
        aio: &aio::AsyncIO,
    ) -> io::Result<Self> {
        for gen in gens.iter().rev() {
            match Name::load_from(name, *gen, aio) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                res => return res,
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ))
    }
}

impl<'a> From<DataAddressRef<'a>> for Name {
    fn from(da: DataAddressRef<'_>) -> Self {
        Name {
            digest: da.digest.0.into(),
            index_level: da.index_level,
            created: chrono::Utc::now(),
        }
    }
}

impl From<DataAddress> for Name {
    fn from(da: DataAddress) -> Self {
        Name {
            digest: da.digest.0,
            index_level: da.index_level,
            created: chrono::Utc::now(),
        }
    }
}
