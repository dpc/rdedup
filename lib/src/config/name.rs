use std::io;
use asyncio;
use std::path::PathBuf;
use serde_yaml;
use SGData;
use util::*;
use DIGEST_SIZE;
use {DataAddress, Generation, OwnedDataAddress};

pub(crate) const NAME_SUBDIR: &'static str = "name";

#[derive(Serialize, Deserialize)]
pub(crate) struct Name {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    pub(crate) digest: Vec<u8>,
    pub(crate) index_level: u32,
}

impl Name {
    pub(crate) fn remove(
        name: &str,
        gen: Generation,
        aio: &asyncio::AsyncIO,
    ) -> io::Result<()> {
        let path = Name::path(name, gen);
        aio.remove(path).wait()
    }

    pub(crate) fn remove_any(
        name: &str,
        gens: &[Generation],
        aio: &asyncio::AsyncIO,
    ) -> io::Result<()> {
        for gen in gens.iter().rev() {
            match Name::remove(name, *gen, aio) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                res => return res,
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ));
    }

    // TODO: &self ?
    pub(crate) fn update_generation_to(
        name: &str,
        cur_generation: Generation,
        gens: &[Generation],
        aio: &asyncio::AsyncIO,
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

        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ));
    }

    pub(crate) fn path(name: &str, gen: Generation) -> PathBuf {
        let mut path: PathBuf = gen.to_string().into();
        path.push(NAME_SUBDIR);
        path.push(name);
        path.set_extension("yml");
        path
    }

    /// List all names
    pub(crate) fn list(
        gen: Generation,
        aio: &asyncio::AsyncIO,
    ) -> io::Result<Vec<String>> {
        let list = substitute_err_not_found(
            aio.list(PathBuf::from(gen.to_string()).join(NAME_SUBDIR))
                .wait(),
            || vec![],
        )?;

        Ok(
            list.iter()
                .map(|e| {
                    e.file_stem()
                        .expect(&format!("malformed name: {:?}", e))
                        .to_string_lossy()
                        .to_string()
                })
                .collect(),
        )
    }

    pub fn list_all(
        gens: &[Generation],
        aio: &asyncio::AsyncIO,
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
        aio: &asyncio::AsyncIO,
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

    pub fn load_from(
        name: &str,
        gen: Generation,
        aio: &asyncio::AsyncIO,
    ) -> io::Result<Self> {
        let path = Name::path(name, gen);

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

    pub(crate) fn load_from_any(
        name: &str,
        gens: &[Generation],
        aio: &asyncio::AsyncIO,
    ) -> io::Result<Self> {
        for gen in gens.iter().rev() {
            match Name::load_from(name, *gen, aio) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                res => return res,
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("name not found: {}", name),
        ));
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
