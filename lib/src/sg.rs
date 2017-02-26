//! Scattered-gathered buffers
//!

use {DIGEST_SIZE, BUFFER_SIZE};
use DataType;
use crypto::digest::Digest;
use flate2;
use owning_ref::ArcRef;
use rollsum;
use sha2;
use sodiumoxide::crypto::{box_, pwhash, secretbox};
use std::{io, mem};
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::result::Result;
use std::sync::Arc;

pub trait EdgeFinder {
    fn find_edges(&mut self, buf: &[u8]) -> Vec<usize>;
}

/// Finds edges using rolling sum
pub struct BupEdgeFinder {
    chunk_bits: u32,
    roll: rollsum::Bup,
}

impl BupEdgeFinder {
    pub fn new(chunk_bits: u32) -> Self {
        BupEdgeFinder {
            chunk_bits: chunk_bits,
            roll: rollsum::Bup::new_with_chunk_bits(chunk_bits),
        }
    }
}

impl EdgeFinder for BupEdgeFinder {
    fn find_edges(&mut self, buf: &[u8]) -> Vec<usize> {
        let mut ofs: usize = 0;
        let len = buf.len();
        let mut edges = vec![];

        while ofs < len {
            if let Some(count) = self.roll.find_chunk_edge(&buf[ofs..len]) {
                ofs += count;

                self.roll = rollsum::Bup::new_with_chunk_bits(self.chunk_bits);
                edges.push(ofs);
            } else {
                break;
            }
        }
        edges
    }
}

pub struct ReaderVecIter<R: io::Read> {
    reader: R,
    buf_size: usize,
}

impl<R> ReaderVecIter<R>
    where R: io::Read
{
    pub fn new(reader: R, buf_size: usize) -> Self {

        ReaderVecIter {
            reader: reader,
            buf_size: buf_size,
        }
    }
}

impl<R> Iterator for ReaderVecIter<R>
    where R: io::Read
{
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {

        let mut buf: Vec<u8> = vec![0u8; self.buf_size];
        match self.reader.read(&mut buf) {
            Ok(len) => {
                if len == 0 {
                    return None;
                }
                buf.truncate(len);
                Some(Ok(buf))
            }
            Err(e) => Some(Err(e)),
        }
    }
}


pub struct WhileOk<I, E> {
    e: Option<E>,
    i: I,
}

impl<I, E> WhileOk<I, E> {
    pub fn new<O>(into_iter: I) -> WhileOk<I, E>
        where I: Iterator<Item = Result<O, E>>
    {

        WhileOk {
            e: None,
            i: into_iter.into_iter(),
        }
    }
}
impl<I, O, E> Iterator for WhileOk<I, E>
    where I: Iterator<Item = Result<O, E>>
{
    type Item = O;

    fn next(&mut self) -> Option<Self::Item> {
        if self.e.is_some() {
            return None;
        }
        match self.i.next() {
            Some(Ok(o)) => Some(o),
            Some(Err(e)) => {
                self.e = Some(e);
                None
            }
            None => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Chunk {
    sg: SGBuf,
    chunk_type: DataType,
    data_type: DataType,
}

/// Scattered-gathered buffer
///
/// A pice of data potentially scattered between
/// multiple buffers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SGBuf(Vec<ArcRef<Vec<u8>, [u8]>>);


impl SGBuf {
    fn new() -> Self {
        SGBuf(vec![])
    }
    pub fn from_single(v: Vec<u8>) -> Self {
        SGBuf::from_vec(vec![v])
    }
    fn from_vec(mut v: Vec<Vec<u8>>) -> Self {
        SGBuf(v.drain(..)
            .map(|v| ArcRef::new(Arc::new(v)).map(|v| &v[..]))
            .collect())
    }

    /// Calculate digest
    pub fn calculate_digest(&self) -> Vec<u8> {
        let mut sha = sha2::Sha256::new();

        for sg_part in &self.0 {
            sha.input(&sg_part);
        }

        let mut sha256 = vec![0u8; DIGEST_SIZE];
        sha.result(&mut sha256);

        sha256
    }

    pub fn compress(&self) -> SGBuf {
        let mut compressor =
            flate2::write::DeflateEncoder::new(vec![],
                                               flate2::Compression::Default);

        for sg_part in &self.0 {
            compressor.write_all(&sg_part).unwrap();
        }

        SGBuf::from_single(compressor.finish().unwrap())
    }

    fn to_linear(&self) -> ArcRef<Vec<u8>, [u8]> {
        match self.0.len() {
            0 => ArcRef::new(Arc::new(vec![])).map(|v| &v[..]),
            1 => self.0[0].clone(),
            _ => {
                let mut v = vec![];
                for sg_part in &self.0 {
                    v.write_all(&sg_part).unwrap();
                }
                ArcRef::new(Arc::new(v)).map(|v| &v[..])
            }
        }
    }

    pub fn encrypt(&self, pub_key: &box_::PublicKey, digest: &[u8]) -> SGBuf {
        let mut encrypted = Vec::with_capacity(BUFFER_SIZE);
        let nonce = box_::Nonce::from_slice(digest)
            .expect("Nonce::from_slice failed");

        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();
        let cipher =
            box_::seal(&self.to_linear(), &nonce, pub_key, &ephemeral_sec);
        encrypted.write_all(&ephemeral_pub.0).unwrap();
        encrypted.write_all(&cipher).unwrap();
        SGBuf::from_single(encrypted)
    }
}

impl Deref for SGBuf {
    type Target = Vec<ArcRef<Vec<u8>, [u8]>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SGBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct Chunker<I, EF> {
    iter: I,
    data_type: DataType,
    cur_buf_edges: Option<(Arc<Vec<u8>>, Vec<usize>)>,
    cur_buf_i: usize,
    cur_edge_i: usize,
    cur_sgbuf: SGBuf,
    chunks_returned: usize,
    edge_finder: EF,
}

impl<I, EF> Chunker<I, EF> {
    pub fn new(iter: I, edge_finder: EF, data_type: DataType) -> Self {
        Chunker {
            iter: iter,
            data_type: data_type,
            cur_buf_edges: None,
            cur_buf_i: 0,
            cur_edge_i: 0,
            cur_sgbuf: SGBuf::new(),
            chunks_returned: 0,
            edge_finder: edge_finder,
        }
    }
}

impl<I: Iterator<Item = Vec<u8>>, EF> Iterator for Chunker<I, EF>
    where EF: EdgeFinder
{
    type Item = SGBuf;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.cur_buf_edges = if let Some((buf, edges)) =
                self.cur_buf_edges.clone() {
                if self.cur_edge_i < edges.len() {
                    let edge = edges[self.cur_edge_i];
                    let aref = ArcRef::new(buf.clone())
                        .map(|a| &a[self.cur_buf_i..edge]);
                    self.cur_sgbuf.push(aref);
                    self.cur_edge_i += 1;
                    self.cur_buf_i = edge;
                    self.chunks_returned += 1;
                    return Some(mem::replace(&mut self.cur_sgbuf,
                                             SGBuf::new()));
                } else {
                    if self.cur_buf_i != buf.len() {
                        let aref = ArcRef::new(buf.clone())
                            .map(|a| &a[self.cur_buf_i..]);
                        self.cur_sgbuf.push(aref);
                    }
                    self.cur_buf_i = 0;
                    None
                }
            } else {
                if let Some(buf) = self.iter.next() {
                    self.cur_edge_i = 0;
                    let edges = self.edge_finder.find_edges(&buf[..]);
                    Some((Arc::new(buf), edges))
                } else {
                    if self.cur_sgbuf.is_empty() {
                        if self.chunks_returned == 0 {
                            // at least one, zero sized chunk
                            self.chunks_returned += 1;
                            return Some(SGBuf::new());
                        } else {
                            return None;
                        }
                    } else {
                        self.chunks_returned += 1;
                        return Some(mem::replace(&mut self.cur_sgbuf,
                                                 SGBuf::new()));
                    }
                }
            }
        }
    }
}

/*
fn chunk_and_send_to_assembler<R: Read>(
    tx: &mpsc::SyncSender<ChunkAssemblerMessage>,
    mut reader: &mut R,
    data_type: DataType,
    chunking_algo: ChunkingAlgorithm)
-> Result<Vec<u8>> {
    let chunk_bits = match chunking_algo {
        ChunkingAlgorithm::Bup { chunk_bits: bits } => bits,
    };
    let mut chunker = BupEdgeFinder::new(chunk_bits);

    let mut index: Vec<u8> = vec![];
    loop {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let len = reader.read(&mut buf)?;

        if len == 0 {
            break;
        }
        buf.truncate(len);

        let edges = chunker.input(&buf[..len]);

        for &(_, ref sum) in &edges {
            index.append(&mut sum.clone());
        }
        tx.send(ChunkAssemblerMessage::Data(buf,
                                              edges,
                                              DataType::Data,
                                              data_type))
            .unwrap();
    }
    let edges = chunker.finish();

    for &(_, ref sum) in &edges {
        index.append(&mut sum.clone());
    }
    tx.send(ChunkAssemblerMessage::Data(vec![],
                                          edges,
                                          DataType::Data,
                                          data_type))
        .unwrap();

    if index.len() > DIGEST_SIZE {
        let digest = chunk_and_send_to_assembler(tx,
                                                 &mut io::Cursor::new(index),
                                                 DataType::Index,
                                                 chunking_algo)?;
        assert!(digest.len() == DIGEST_SIZE);
        let index_digest = quick_sha256(&digest);
        tx.send(ChunkAssemblerMessage::Data(digest.clone(),
                                              vec![(digest.len(),
                                                    index_digest.clone())],
                                              DataType::Index,
                                              DataType::Index))
            .unwrap();
        Ok(index_digest)
    } else {
        Ok(index)
    }
}
*/


#[cfg(test)]
include!("sg_tests.rs");
