use rollsum;

/// Abstraction over the specific chunking algorithms being used
pub(crate) trait Chunking {
    fn find_chunk_edge(&mut self, &[u8]) -> Option<usize>;
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
    fn find_chunk_edge(&mut self, data: &[u8]) -> Option<usize> {
        self.engine.find_chunk_edge(data)
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
    fn find_chunk_edge(&mut self, data: &[u8]) -> Option<usize> {
        self.engine.find_chunk_edge(data)

    }
}
