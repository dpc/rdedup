//! Scattered-gathered buffers
//!

use DataType;
use chunking;
use owning_ref::ArcRef;
use sgdata::SGData;
use std::{io, mem};
use std::result::Result;
use std::sync::Arc;

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
    /// Pieces of chunk to return next, but yet
    /// not complete
    incomplete_chunk: SGData,
    /// Data that wasn't chunked yet
    pending: Option<ArcRef<Vec<u8>, [u8]>>,

    chunks_returned: usize,
    chunking: Box<chunking::Chunking>,
}

impl<I> Chunker<I> {
    pub fn new(iter: I, chunking: Box<chunking::Chunking>) -> Self {
        Chunker {
            iter: iter,
            incomplete_chunk: SGData::empty(),
            pending: None,
            chunks_returned: 0,
            chunking: chunking,
        }
    }
}

impl<I: Iterator<Item = Vec<u8>>> Iterator for Chunker<I> {
    type Item = SGData;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(buf) = self.pending.take().or_else(|| {
                self.iter
                    .next()
                    .map(|v| ArcRef::new(Arc::new(v)).map(|a| a.as_slice()))
            }) {
                if let Some((last, rest)) = self.chunking.find_chunk(&*buf) {
                    debug_assert_eq!(last.len() + rest.len(), buf.len());
                    self.incomplete_chunk
                        .push_arcref(buf.clone().map(|cur| &cur[..last.len()]));
                    if !rest.is_empty() {
                        self.pending =
                            Some(buf.clone().map(|cur| &cur[last.len()..]))
                    };

                    // While cryptographic hashes should not have collisions,
                    // in practice it's possible to have identical data and
                    // index chunks  (and thus same hash), which leads to
                    // index/data overwriting themselves (with vs without
                    // encryption). To prevent that we
                    // impose a 64-byte minimum limit on chunks, no matter what
                    // do chunker returns.
                    if self.incomplete_chunk.len() >= 64 {
                        self.chunks_returned += 1;
                        return Some(mem::replace(
                            &mut self.incomplete_chunk,
                            SGData::empty(),
                        ));
                    } else {
                        continue;
                    }
                }
                self.incomplete_chunk.push_arcref(buf);
            } else if !self.incomplete_chunk.is_empty() {
                self.chunks_returned += 1;
                return Some(
                    mem::replace(&mut self.incomplete_chunk, SGData::empty()),
                );
            } else {
                if self.chunks_returned == 0 {
                    // at least one, zero sized chunk
                    self.chunks_returned += 1;
                    return Some(SGData::empty());
                } else {
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
include!("sg_tests.rs");
