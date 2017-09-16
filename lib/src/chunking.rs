use rollsum;
use SGData;
use rollsum::CDC;
use owning_ref::ArcRef;
use std::mem;
use std::sync::Arc;


/// Abstraction over the specific chunking algorithms being used
pub(crate) trait Chunking {
    fn find_chunk<'a>(&mut self, buf: &'a [u8])
        -> Option<(&'a [u8], &'a [u8])>;
}

pub(crate) struct Bup {
    engine: rollsum::Bup,
}

impl Bup {
    pub fn new(bits: u32) -> Self {
        Bup {
            engine: rollsum::Bup::new_with_chunk_bits(bits),
        }
    }
}

impl Chunking for Bup {
    fn find_chunk<'a>(
        &mut self,
        buf: &'a [u8],
    ) -> Option<(&'a [u8], &'a [u8])> {
        self.engine.find_chunk(buf)
    }
}

pub(crate) struct Gear {
    engine: rollsum::Gear,
}


impl Gear {
    pub fn new(bits: u32) -> Self {
        Gear {
            engine: rollsum::Gear::new_with_chunk_bits(bits),
        }
    }
}


impl Chunking for Gear {
    fn find_chunk<'a>(
        &mut self,
        buf: &'a [u8],
    ) -> Option<(&'a [u8], &'a [u8])> {
        self.engine.find_chunk(buf)
    }
}

pub(crate) struct FastCDC {
    engine: rollsum::FastCDC,
}


impl FastCDC {
    pub fn new(bits: u32) -> Self {
        FastCDC {
            engine: rollsum::FastCDC::new_with_chunk_bits(bits),
        }
    }
}


impl Chunking for FastCDC {
    fn find_chunk<'a>(
        &mut self,
        buf: &'a [u8],
    ) -> Option<(&'a [u8], &'a [u8])> {
        self.engine.find_chunk(buf)
    }
}


pub(crate) struct Chunker<I> {
    iter: I,
    /// Pieces of chunk to return next, but yet
    /// not complete
    incomplete_chunk: SGData,
    /// Data that wasn't chunked yet
    pending: Option<ArcRef<Vec<u8>, [u8]>>,

    chunks_returned: usize,
    chunking: Box<Chunking>,
}

impl<I> Chunker<I> {
    pub fn new(iter: I, chunking: Box<Chunking>) -> Self {
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
            } else if self.chunks_returned == 0 {
                // at least one, zero sized chunk
                self.chunks_returned += 1;
                return Some(SGData::empty());
            } else {
                return None;
            }
        }
    }
}
