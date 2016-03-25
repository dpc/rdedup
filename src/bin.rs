extern crate rollsum;
extern crate crypto;

use std::io;
use std::io::Read;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

fn main() {
    let mut stdin = io::stdin();

    let mut buf = [0u8; 16 * 1024];

    let mut total_ofs = 0usize;
    let mut total_chunks = 0usize;

    let mut b = rollsum::Bup::new();
    let mut sha256 = sha2::Sha256::new();

    loop {
        let len = stdin.read(&mut buf).unwrap();

        if len == 0 {
            break;
        }

        let mut ofs : usize = 0;
        while ofs < len {
            if let Some(count) = b.find_chunk_edge(&buf[ofs..len]) {
                println!("found edge at {}; sum: {:x}", total_ofs + ofs + count, b.digest());
                sha256.input(&mut buf[ofs..ofs+count]);
                println!("sha256 hash: {}", sha256.result_str());
                sha256.reset();

                ofs += count;
                total_chunks += 1;
            } else {
                sha256.input(&mut buf[ofs..len]);
                break
            }
        }

        total_ofs += len;
    }
    println!("chunks found: {}", total_chunks);
}
