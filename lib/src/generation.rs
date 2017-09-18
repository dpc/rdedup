use std;
use hex::{self, FromHex};
use bytevec;
use std::io;
use rand::{self, Rng};
use chrono::prelude::*;
use chrono;
use asyncio;
use util::{as_rfc3339, from_rfc3339};
use serde_yaml;
use std::path::Path;
use SGData;

/// Generation config, serialized in a file
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Config {
    #[serde(serialize_with = "as_rfc3339", deserialize_with = "from_rfc3339")]
    created: chrono::DateTime<Utc>,
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
        let mut parts: Vec<_> = s.split("-").collect();
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

        Ok(Generation {
            seq: seq,
            rand: rand,
        })
    }

    pub(crate) fn to_string(&self) -> String {
        format!(
            "{seq:0width$x}-{rand:0width$x}",
            seq = self.seq,
            rand = self.rand,
            width = 16,
        )
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

    pub(crate) fn write(&self, aio: &asyncio::AsyncIO) -> io::Result<()> {
        let config = Config::new();

        let config_str =
            serde_yaml::to_string(&config).expect("yaml serialization failed");

        aio.write(
            Path::new(&self.to_string()).join("config.yaml"),
            SGData::from_single(config_str.into_bytes()),
        ).wait()?;

        Ok(())
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
    assert!(
        gen == Generation {
            seq: 0x0123456701234567,
            rand: 0x1234123412341234,
        }
    )
}
