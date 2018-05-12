use chunking;

pub const DEFAULT_BUP_CHUNK_BITS: u32 = 17;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
/// `Chunking` are the algorithms supported by rdedup
pub enum Chunking {
    /// `Bup` is the default algorithm, the chunk_bits value provided with
    /// bup
    /// is the bit shift to be used by rollsum. The valid range is between
    /// 10
    /// and 30 (1KB to 1GB)
    #[serde(rename = "bup")]
    Bup { chunk_bits: u32 },
    #[serde(rename = "gear")]
    Gear { chunk_bits: u32 },
    #[serde(rename = "fastcdc")]
    FastCDC { chunk_bits: u32 },
}

/// Default implementation for the `Chunking`
impl Default for Chunking {
    fn default() -> Chunking {
        Chunking::Bup {
            chunk_bits: DEFAULT_BUP_CHUNK_BITS,
        }
    }
}

impl Chunking {
    pub fn valid(self) -> bool {
        match self {
            Chunking::Bup {
                chunk_bits: bits,
            }
            | Chunking::Gear {
                chunk_bits: bits,
            }
            | Chunking::FastCDC {
                chunk_bits: bits,
            } => 30 >= bits && bits >= 10,
        }
    }

    pub(crate) fn to_engine(&self) -> Box<chunking::Chunking> {
        match *self {
            Chunking::Bup { chunk_bits } => {
                Box::new(chunking::Bup::new(chunk_bits))
            }
            Chunking::Gear { chunk_bits } => {
                Box::new(chunking::Gear::new(chunk_bits))
            }
            Chunking::FastCDC { chunk_bits } => {
                Box::new(chunking::FastCDC::new(chunk_bits))
            }
        }
    }
}
