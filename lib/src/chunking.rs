use rollsum;

use rollsum::CDC;

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
