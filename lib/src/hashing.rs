

use DIGEST_SIZE;
use SGData;
use blake2;

use digest::FixedOutput;
use digest::Input;
use sha2;
use std::sync::Arc;

pub type ArcHasher = Arc<Hasher + Send + Sync>;

pub trait Hasher {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8>;
    fn calculate_digest_simple(&self, sg: &[u8]) -> Vec<u8>;
}

pub struct Sha256;

impl Hasher for Sha256 {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::default();

        for sg_part in sg.as_parts() {
            sha256.process(sg_part);
        }

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.fixed_result());

        vec_result
    }

    fn calculate_digest_simple(&self, data: &[u8]) -> Vec<u8> {
        let mut sha256 = sha2::Sha256::default();

        sha256.process(data);

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&sha256.fixed_result());

        vec_result
    }
}

pub struct Blake2b;


impl Hasher for Blake2b {
    fn calculate_digest(&self, sg: &SGData) -> Vec<u8> {
        let mut blake2 = blake2::Blake2b::default();

        for sg_part in sg.as_parts() {
            blake2.process(sg_part);
        }

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&blake2.fixed_result()[..DIGEST_SIZE]);

        vec_result
    }


    fn calculate_digest_simple(&self, data: &[u8]) -> Vec<u8> {
        let mut blake2 = blake2::Blake2b::default();

        blake2.process(data);

        let mut vec_result = vec![0u8; DIGEST_SIZE];
        vec_result.copy_from_slice(&blake2.fixed_result()[..DIGEST_SIZE]);

        vec_result
    }
}
