extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;

use std::io;
use std::io::Read;
use std::mem;
use std::thread;

use std::sync::mpsc;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

enum Message {
    Data(Vec<u8>, Vec<Edge>),
    Exit,
}

/// Edge: offset in the input and sha256 sum of the chunk
type Edge = (usize, Vec<u8>);

struct Chunker {
    roll : rollsum::Bup,
    sha256 : sha2::Sha256,
    bytes_total : usize,
    bytes_chunk: usize,
    chunks_total : usize,

    edges : Vec<Edge>,
}


impl Chunker {
    pub fn new() -> Self {
        Chunker {
            roll: rollsum::Bup::new(),
            sha256: sha2::Sha256::new(),
            bytes_total: 0,
            bytes_chunk: 0,
            chunks_total: 0,
            edges: vec!(),
        }
    }

    pub fn edge_found(&mut self, input_ofs : usize) {
        debug!("found edge at {}; sum: {:x}",
                 self.bytes_total,
                 self.roll.digest());

        debug!("sha256 hash: {}",
                 self.sha256.result_str());

        let mut sha256 = vec![0u8; 32];
        self.sha256.result(&mut sha256);

        self.edges.push((input_ofs, sha256));

        self.chunks_total += 1;
        self.bytes_chunk += 0;

        self.sha256.reset();
        self.roll = rollsum::Bup::new();
    }

    pub fn input(&mut self, buf : &[u8]) -> Vec<Edge> {
        let mut ofs : usize = 0;
        let len = buf.len();
        while ofs < len {
            if let Some(count) = self.roll.find_chunk_edge(&buf[ofs..len]) {
                self.sha256.input(&buf[ofs..ofs+count]);

                ofs += count;

                self.bytes_chunk += count;
                self.bytes_total += count;
                self.edge_found(ofs);
            } else {
                let count = len - ofs;
                self.sha256.input(&buf[ofs..len]);
                self.bytes_chunk += count;
                self.bytes_total += count;
                break
            }
        }
        mem::replace(&mut self.edges, vec!())
    }

    pub fn finish(&mut self) -> Vec<Edge> {
        if self.bytes_chunk != 0 {
            self.edge_found(0);
        }
        mem::replace(&mut self.edges, vec!())
    }
}

fn stdio_chunker(tx : mpsc::Sender<Message>) {
    let mut stdin = io::stdin();
    let mut chunker = Chunker::new();

    loop {
        let mut buf = vec![0u8; 16 * 1024];
        let len = stdin.read(&mut buf).unwrap();

        if len == 0 {
            break;
        }

        let edges = chunker.input(&buf[..len]);

        tx.send(Message::Data(buf, edges)).unwrap();
    }
    let edges = chunker.finish();
    tx.send(Message::Data(vec!(), edges)).unwrap();
    tx.send(Message::Exit).unwrap();

    println!("chunks found: {}", chunker.chunks_total);
}

fn chunk_writer(rx : mpsc::Receiver<Message>) {

    loop {
        match rx.recv().unwrap() {
            Message::Exit => return,
            _ => {}
        }
    }
}

fn main() {
    let (tx, rx) = mpsc::channel();

    let chunk_writer_join = thread::spawn(|| chunk_writer(rx));

    stdio_chunker(tx);

    chunk_writer_join.join().unwrap();
}
