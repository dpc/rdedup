use std::collections::BTreeMap;
use std::default::Default;

// Iterator that sorts enumerated elements
// by their index
//
// This is useful for sorting elements
// that were processed by a pool of workers
// and not necessarily returned in order.
//
// Note: `early_items` is unbounded, which
// shouldn't be a problem if pool of workers
// picks elements in order - the distortions
// should be minimal anyway.
pub struct SortingIterator<T, I> {
    early_items: BTreeMap<u64, T>,
    iter: I,
    next_i: u64,
}

impl<T, I> SortingIterator<T, I> {
    pub fn new(iter: I) -> Self {
        SortingIterator {
            iter: iter,
            early_items: Default::default(),
            next_i: 0,
        }
    }
}

impl<T, I> Iterator for SortingIterator<T, I>
where
    I: Iterator<Item = (u64, T)>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.early_items.remove(&self.next_i) {
                self.next_i += 1;
                return Some(item);
            }

            if let Some((i, item)) = self.iter.next() {
                if i == self.next_i {
                    self.next_i += 1;
                    return Some(item);
                } else {
                    assert!(i > self.next_i);
                    self.early_items.insert(i, item);
                }
            } else {
                assert!(self.early_items.is_empty());
                return None;
            }
        }
    }
}
