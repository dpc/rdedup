use std::io::Write;
use std::sync::Arc;

use owning_ref::ArcRef;

/// Scattered, gathered, immutable, arc-ed data
///
/// Allows zero-copy processing of streamed data, read into fixed-size buffers.
/// Especially useful for high-performance, parallel data processing.
///
/// A piece of data potentially scattered between multiple parts, which
/// themselves might be slices of shared-ownership underlying data.
///
/// `SGData` is essentially semantic wrapper over `Vec<ArcRef<Vec<u8>, [u8]>>`
///
///
/// For illustration:
///
/// ``` norust
/// frames:      [    Buf    ][    Buf    ][    Buf    ][    Buf    ]
/// edges:       |                |    |                      |     |
///              |                |    |                      |     |
///               \          /\  / \  / \ /\           /\    / \   /
///                \        /  ||   ||  | | \         /  \  /   \ /
/// sgdata parts:      C1[0] C1[1] C2[0] C3[0]   C3[1]   C3[2]  C4[0]
/// ```
///
/// Arbitrary-sized data is being read into `frames` and edges between
/// logical parts are being found. Then `sgdata` objects are created,
/// aggregating parts of `frames` while holding reference-counted shared
/// ownership over `frames`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SGData(Vec<ArcRef<Vec<u8>, [u8]>>);

impl SGData {
    pub fn empty() -> Self {
        SGData::from_many(vec![])
    }

    pub fn from_single(v: Vec<u8>) -> Self {
        SGData::from_many(vec![v])
    }

    pub fn from_vec(v: Vec<ArcRef<Vec<u8>, [u8]>>) -> Self {
        SGData(v)
    }

    pub fn from_many(mut v: Vec<Vec<u8>>) -> Self {
        SGData(
            v.drain(..)
                .map(|v| ArcRef::new(Arc::new(v)).map(|v| &v[..]))
                .collect(),
        )
    }

    /// Total len of all parts
    pub fn len(&self) -> usize {
        self.0.iter().fold(0, |sum, part| sum + part.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_parts(&self) -> &[ArcRef<Vec<u8>, [u8]>] {
        &self.0
    }

    pub fn as_vec(&self) -> &Vec<ArcRef<Vec<u8>, [u8]>> {
        &self.0
    }

    pub fn as_vec_mut(&mut self) -> &mut Vec<ArcRef<Vec<u8>, [u8]>> {
        &mut self.0
    }

    pub fn push_vec(&mut self, v: Vec<u8>) {
        self.0.push(ArcRef::new(Arc::new(v)).map(|v| &v[..]))
    }

    pub fn push_arcref(&mut self, arcref: ArcRef<Vec<u8>, [u8]>) {
        self.0.push(arcref)
    }

    /// Convert to linear (single vector) form
    ///
    /// If `self` is empty or already contains only one piece,
    /// this is cheap.
    ///
    /// If `self` is scattered between many pices, this requires
    /// copying all the data into a new, big chunk.
    pub fn to_linear(&self) -> ArcRef<Vec<u8>, [u8]> {
        match self.0.len() {
            0 => ArcRef::new(Arc::new(vec![])).map(|v| &v[..]),
            1 => self.0[0].clone(),
            _ => {
                let mut v = Vec::with_capacity(self.len());
                for sg_part in &self.0 {
                    v.write_all(sg_part).unwrap();
                }
                ArcRef::new(Arc::new(v)).map(|v| &v[..])
            }
        }
    }

    pub fn into_linear_vec(mut self) -> Vec<u8> {
        match self.0.len() {
            0 => vec![],
            1 => {
                let e = self.0.pop().unwrap();
                Arc::try_unwrap(e.into_owner())
                    .unwrap_or_else(|a| a.as_ref().clone())
            }
            _ => {
                let mut v = Vec::with_capacity(self.len());
                for sg_part in &self.0 {
                    v.write_all(sg_part).unwrap();
                }
                v
            }
        }
    }
}
