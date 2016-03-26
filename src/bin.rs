extern crate rollsum;
extern crate crypto;

use std::io;
use std::io::Read;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

enum Message {
    Data(Vec<u8>),
    ChunkEdge(Vec<u8>), // Sha256 hash of the data sent since the last ChunkEdge
}

struct Chunker {
    roll : rollsum::Bup,
    sha256 : sha2::Sha256,
    bytes_total : usize,
    bytes_chunk: usize,
    chunks_total : usize,
}

impl Chunker {
    pub fn new() -> Self {
        Chunker {
            roll: rollsum::Bup::new(),
            sha256: sha2::Sha256::new(),
            bytes_total: 0,
            bytes_chunk: 0,
            chunks_total: 0,
        }
    }

    pub fn chunk_found(&mut self) {

        println!("found edge at {}; sum: {:x}",
                 self.bytes_total,
                 self.roll.digest());

        println!("sha256 hash: {}",
                 self.sha256.result_str());

        self.chunks_total += 1;
        self.bytes_chunk += 0;

        self.sha256.reset();
        self.roll = rollsum::Bup::new();
    }

    pub fn feed(&mut self, buf : &[u8]) {
        let mut ofs : usize = 0;
        let len = buf.len();
        while ofs < len {
            if let Some(count) = self.roll.find_chunk_edge(&buf[ofs..len]) {
                self.sha256.input(&buf[ofs..ofs+count]);

                ofs += count;

                self.bytes_chunk += count;
                self.bytes_total += count;
                self.chunk_found();
            } else {
                let count = len - ofs;
                self.sha256.input(&buf[ofs..len]);
                self.bytes_chunk += count;
                self.bytes_total += count;
                break
            }
        }
    }

    pub fn finish(&mut self) {
        if self.bytes_chunk != 0 {
            self.chunk_found();
        }
    }
}

fn main() {
    let mut stdin = io::stdin();

    let mut buf = [0u8; 16 * 1024];


    let mut chunker = Chunker::new();

    loop {
        let len = stdin.read(&mut buf).unwrap();

        if len == 0 {
            break;
        }

        chunker.feed(&buf[..len]);
    }
    chunker.finish();
    println!("chunks found: {}", chunker.chunks_total);
}
