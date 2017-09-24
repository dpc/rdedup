use std::io;

mod serde;
pub(crate) use self::serde::*;

mod whileok;
pub(crate) use self::whileok::*;

mod readerveciter;
pub(crate) use self::readerveciter::*;

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
