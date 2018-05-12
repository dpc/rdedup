use std::io;

mod serde;
pub(crate) use self::serde::*;

mod whileok;
pub(crate) use self::whileok::*;

mod readerveciter;
pub(crate) use self::readerveciter::*;

/// Writer that counts how many bytes were written to it
pub struct CounterWriter {
    pub count: u64,
}

impl CounterWriter {
    pub fn new() -> Self {
        CounterWriter { count: 0 }
    }
}

impl io::Write for CounterWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Substitute Err(NotFound) with something else
///
/// Many places in the code ignore `NotFound`, so this function makes it
/// convenient.
pub(crate) fn substitute_err_not_found<T, F>(
    res: io::Result<T>,
    f: F,
) -> io::Result<T>
where
    F: Fn() -> T,
{
    match res {
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(f()),
        res => res,
    }
}

/// Like `enumerate` from stdlib,
/// only guaranteed to be `u64`
///
/// Copied & modified from stdlib.
///
/// -- dpc
pub(crate) struct EnumerateU64<I> {
    iter: I,
    count: u64,
}

impl<I> EnumerateU64<I> {
    pub(crate) fn new(i: I) -> Self {
        Self {
            iter: i,
            count: 0,
        }
    }
}

impl<I> Iterator for EnumerateU64<I>
where
    I: Iterator,
{
    type Item = (u64, <I as Iterator>::Item);

    /// # Overflow Behavior
    ///
    /// The method does no guarding against overflows, so enumerating more
    /// than
    /// `u64::MAX` elements either produces the wrong result or panics. If
    /// debug assertions are enabled, a panic is guaranteed.
    ///
    /// # Panics
    ///
    /// Might panic if the index of the element overflows a `u64`.
    #[inline]
    fn next(&mut self) -> Option<(u64, <I as Iterator>::Item)> {
        self.iter.next().map(|a| {
            let ret = (self.count, a);
            // Possible undefined overflow.
            self.count += 1;
            ret
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<(u64, I::Item)> {
        self.iter.nth(n).map(|a| {
            let i = self.count + n as u64;
            self.count = i + 1;
            (i, a)
        })
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }
}
