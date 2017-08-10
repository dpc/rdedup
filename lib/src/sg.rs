//! Scattered-gathered buffers
//!

use DataType;
use chunking;
use owning_ref::ArcRef;
use sgdata::SGData;
use std::{io, mem};
use std::result::Result;
use std::sync::Arc;

/*
/// For mocking in tests
pub trait EdgeFinderTrait {
    fn find_edges(&mut self, buf: &[u8]) -> Vec<usize>;
}

/// Finds edges using rolling sum
pub struct EdgeFinder {
    chunking: Box<chunking::Chunking>,
}

impl EdgeFinder {
    pub(crate) fn new(chunking: Box<chunking::Chunking>) -> Self {
        EdgeFinder { chunking: chunking }
    }
}

impl EdgeFinderTrait for EdgeFinder {
    fn find_edges(&mut self, buf: &[u8]) -> Vec<usize> {
        let mut ofs: usize = 0;
        let len = buf.len();
        let mut edges = vec![];

        while ofs < len {
            if let Some(count) = self.chunking.find_chunk(&buf[ofs..len]) {
                ofs += count;

                edges.push(ofs);
            } else {
                break;
            }
        }
        edges
    }
}
*/
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

pub(crate) struct Chunker<I> {
    iter: I,
    cur_sg: Vec<ArcRef<Vec<u8>, [u8]>>,
    cur_buf: Option<ArcRef<Vec<u8>, [u8]>>,

    chunks_returned: usize,
    chunking: Box<chunking::Chunking>,
}

impl<I> Chunker<I> {
    pub fn new(iter: I, chunking: Box<chunking::Chunking>) -> Self {
        Chunker {
            iter: iter,
            cur_sg: Vec::new(),
            cur_buf: None,
            chunks_returned: 0,
            chunking: chunking,
        }
    }
}

impl<I: Iterator<Item = Vec<u8>>> Iterator for Chunker<I> {
    type Item = SGData;

    fn next(&mut self) -> Option<Self::Item> {

        loop {
            if self.cur_buf.is_none() {
                self.cur_buf = self.iter
                    .next()
                    .map(|v| ArcRef::new(Arc::new(v)).map(|a| a.as_slice()));
            }

            if let Some(buf) = self.cur_buf.take() {
                if let Some((last, rest)) = self.chunking.find_chunk(&*buf) {
                    self.cur_sg.push(buf.clone().map(|cur| &cur[..last.len()]));
                    self.cur_buf = if rest.is_empty() {
                        None
                    } else {
                        Some(buf.clone().map(|cur| &cur[last.len()..]))
                    };
                    self.chunks_returned += 1;
                    return Some(SGData::from_vec(
                        mem::replace(&mut self.cur_sg, vec![]),
                    ));
                }
                self.cur_sg.push(buf);
            } else {
                if self.cur_sg.is_empty() {
                    if self.chunks_returned == 0 {
                        // at least one, zero sized chunk
                        self.chunks_returned += 1;
                        return Some(SGData::empty());
                    } else {
                        return None;
                    }
                } else {
                    self.chunks_returned += 1;
                    return Some(SGData::from_vec(
                        mem::replace(&mut self.cur_sg, vec![]),
                    ));
                }
            }
        }
    }

    /*fn next(&mut self) -> Option<Self::Item> {
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
    }*/
}

#[cfg(test)]
include!("sg_tests.rs");
