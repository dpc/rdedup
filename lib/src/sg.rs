//! Scattered-gathered buffers
//!

use DataType;
use owning_ref::ArcRef;
use rollsum;
use sgdata::SGData;
use std::{io, mem};
use std::result::Result;
use std::sync::Arc;

pub trait EdgeFinder {
    fn find_edges(&mut self, buf: &[u8]) -> Vec<usize>;
}

/// Finds edges using rolling sum
pub struct BupEdgeFinder {
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
where
    R: io::Read,
{
    pub fn new(reader: R, buf_size: usize) -> Self {

        ReaderVecIter {
            reader: reader,
            buf_size: buf_size,
        }
    }
}

impl<R> Iterator for ReaderVecIter<R>
where
    R: io::Read,
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
    where
        I: Iterator<Item = Result<O, E>>,
    {

        WhileOk {
            e: None,
            i: into_iter.into_iter(),
        }
    }
}
impl<I, O, E> Iterator for WhileOk<I, E>
where
    I: Iterator<Item = Result<O, E>>,
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
    sg: SGData,
    chunk_type: DataType,
    data_type: DataType,
}

pub struct Chunker<I, EF> {
    iter: I,
    cur_buf_edges: Option<(Arc<Vec<u8>>, Vec<usize>)>,
    cur_buf_i: usize,
    cur_edge_i: usize,
    cur_sgbuf: SGData,
    chunks_returned: usize,
    edge_finder: EF,
}

impl<I, EF> Chunker<I, EF> {
    pub fn new(iter: I, edge_finder: EF) -> Self {
        Chunker {
            iter: iter,
            cur_buf_edges: None,
            cur_buf_i: 0,
            cur_edge_i: 0,
            cur_sgbuf: SGData::empty(),
            chunks_returned: 0,
            edge_finder: edge_finder,
        }
    }
}

impl<I: Iterator<Item = Vec<u8>>, EF> Iterator for Chunker<I, EF>
where
    EF: EdgeFinder,
{
    type Item = SGData;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.cur_buf_edges = if let Some((buf, edges)) =
                self.cur_buf_edges.clone()
            {
                if self.cur_edge_i < edges.len() {
                    let edge = edges[self.cur_edge_i];
                    let aref = ArcRef::new(buf.clone())
                        .map(|a| &a[self.cur_buf_i..edge]);
                    self.cur_sgbuf.as_vec_mut().push(aref);
                    self.cur_edge_i += 1;
                    self.cur_buf_i = edge;
                    self.chunks_returned += 1;
                    return Some(
                        mem::replace(&mut self.cur_sgbuf, SGData::empty()),
                    );
                } else {
                    if self.cur_buf_i != buf.len() {
                        let aref = ArcRef::new(buf.clone())
                            .map(|a| &a[self.cur_buf_i..]);
                        self.cur_sgbuf.as_vec_mut().push(aref);
                    }
                    self.cur_buf_i = 0;
                    None
                }
            } else if let Some(buf) = self.iter.next() {
                self.cur_edge_i = 0;
                let edges = self.edge_finder.find_edges(&buf[..]);
                Some((Arc::new(buf), edges))
            } else if self.cur_sgbuf.as_parts().is_empty() {
                if self.chunks_returned == 0 {
                    // at least one, zero sized chunk
                    self.chunks_returned += 1;
                    return Some(SGData::empty());
                } else {
                    return None;
                }
            } else {
                self.chunks_returned += 1;
                return Some(mem::replace(&mut self.cur_sgbuf, SGData::empty()));
            }
        }
    }
}

#[cfg(test)]
include!("sg_tests.rs");
