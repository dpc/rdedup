

use DIGEST_SIZE;
use SGData;
use sha2;
use std::sync::Arc;

pub type ArcHasher = Arc<Hasher + Send + Sync>;

pub trait Hasher {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8>;
}

pub struct Sha256;

impl Hasher for Sha256 {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8> {
        use sha2::Digest;
        let mut sha256 = sha2::Sha256::default();

        for sg_part in sg.as_parts() {
            sha256.input(sg_part);
        }

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.result());

        vec_result
    }
}
