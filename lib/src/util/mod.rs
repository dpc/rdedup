use std::io;

mod serde;
pub(crate) use self::serde::*;

mod whileok;
pub(crate) use self::whileok::*;

mod readerveciter;
pub(crate) use self::readerveciter::*;

mod crypto;
pub(crate) use self::crypto::*;

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
/// Many places in the code ignore NotFound, so this function makes it
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
        res => {
            return res;
        }
    }
}
