use blake2;
use digest::Digest;
use sha2;
use SGData;
use DIGEST_SIZE;

use std::sync::Arc;

pub type ArcHasher = Arc<dyn Hasher + Send + Sync>;

pub trait Hasher {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8>;
    fn calculate_digest_simple(&self, sg: &[u8]) -> Vec<u8>;
}

pub struct Sha256;

impl Hasher for Sha256 {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::default();

        for sg_part in sg.as_parts() {
            sha256.update(sg_part);
        }

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.finalize());

        vec_result
    }

    fn calculate_digest_simple(&self, data: &[u8]) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::default();

        sha256.update(data);

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.finalize());

        vec_result
    }
}

pub struct Blake2b;

impl Hasher for Blake2b {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8> {
        let mut blake2 = blake2::Blake2b::default();

        for sg_part in sg.as_parts() {
            blake2.update(sg_part);
        }

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&blake2.finalize()[..DIGEST_SIZE]);

        vec_result
    }

    fn calculate_digest_simple(&self, data: &[u8]) -> Vec<u8> {
        let mut blake2 = blake2::Blake2b::default();

        blake2.update(data);

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&blake2.finalize()[..DIGEST_SIZE]);

        vec_result
    }
}
