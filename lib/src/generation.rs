use std::io;
use std::path::PathBuf;

use chrono::prelude::*;
use hex::{self, FromHex};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::aio;
use crate::util::{as_rfc3339, from_rfc3339};
use crate::SGData;

pub const CONFIG_YML_FILE: &str = "config.yml";

/// Generation config, serialized in a file
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Config {
    #[serde(serialize_with = "as_rfc3339", deserialize_with = "from_rfc3339")]
    pub(crate) created: chrono::DateTime<Utc>,
}

impl Config {
    fn new() -> Self {
        Config {
            created: Utc::now(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct Generation {
    // Note: order important due to `#[derive(Ord)]`
    seq: u64,
    rand: u64,
}

impl Generation {
    pub(crate) fn try_from(s: &str) -> io::Result<Generation> {
        let mut parts: Vec<_> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Couldn't parse `Generation` string: {}", s),
            ));
        }

        let rand_s = parts.pop().unwrap();
        let seq_s = parts.pop().unwrap();

        if rand_s.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "`Generation`'s random part has wrong length string: {}",
                    rand_s
                ),
            ));
        }
        if seq_s.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "`Generation`'s sequence part has wrong length string: {}",
                    seq_s
                ),
            ));
        }
        let rand_bytes: std::result::Result<Vec<u8>, hex::FromHexError> =
            FromHex::from_hex(&rand_s.as_bytes());
        let rand: u64 = match rand_bytes {
            Ok(mut bytes) => {
                let bytes: Vec<u8> = bytes.drain(..).rev().collect();
                bytevec::ByteDecodable::decode::<u64>(bytes.as_slice()).unwrap()
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "`Generation`'s random part can't be parsed: {}",
                        rand_s
                    ),
                ))
            }
        };

        let seq_bytes: std::result::Result<Vec<u8>, hex::FromHexError> =
            FromHex::from_hex(&seq_s.as_bytes());
        let seq: u64 = match seq_bytes {
            Ok(mut bytes) => {
                let bytes: Vec<u8> = bytes.drain(..).rev().collect();
                bytevec::ByteDecodable::decode::<u64>(bytes.as_slice()).unwrap()
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "`Generation`'s sequence part can't be parsed: {}",
                        seq_s
                    ),
                ))
            }
        };

        Ok(Generation { seq, rand })
    }

    pub(crate) fn gen_next(&self) -> Self {
        Generation {
            seq: self.seq + 1,
            rand: rand::thread_rng().next_u64(),
        }
    }

    pub(crate) fn gen_first() -> Self {
        Generation {
            seq: 0,
            rand: rand::thread_rng().next_u64(),
        }
    }

    pub(crate) fn config_path(&self) -> PathBuf {
        PathBuf::from(self.to_string()).join(CONFIG_YML_FILE)
    }

    pub(crate) fn write(&self, aio: &aio::AsyncIO) -> io::Result<()> {
        let config = Config::new();

        let config_str =
            serde_yaml::to_string(&config).expect("yaml serialization failed");

        aio.write(
            self.config_path(),
            SGData::from_single(config_str.into_bytes()),
        )
        .wait()?;

        Ok(())
    }

    pub(crate) fn load_config(&self, aio: &aio::AsyncIO) -> io::Result<Config> {
        let path = self.config_path();
        let sg = aio.read(path).wait()?;

        let config_data = sg.to_linear_vec();

        let config: Config = serde_yaml::from_reader(config_data.as_slice())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("couldn't parse yaml: {}", e.to_string()),
                )
            })?;

        Ok(config)
    }
}

impl std::fmt::Display for Generation {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{seq:0width$x}-{rand:0width$x}",
            seq = self.seq,
            rand = self.rand,
            width = 16,
        )
    }
}

#[test]
fn generation_from_str() {
    assert!(Generation::try_from("0").is_err());
    assert!(Generation::try_from("-0").is_err());
    assert!(Generation::try_from("").is_err());
    let gen =
        Generation::try_from("0123456701234567-1234123412341234").unwrap();
    println!("{:x}", gen.seq);
    println!("{:x}", gen.rand);
    assert_eq!(
        gen,
        Generation {
            seq: 0x0123456701234567,
            rand: 0x1234123412341234,
        }
    )
}
