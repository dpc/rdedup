use std;

/// Iterator stopping on error
pub struct WhileOk<I, E>
where
    E: std::error::Error,
{
    e: Option<E>,
    i: I,
}

impl<I, E> WhileOk<I, E>
where
    E: std::error::Error,
{
    pub fn new<O>(into_iter: I) -> WhileOk<I, E>
    where
        I: Iterator<Item = Result<O, E>>,
    {
        WhileOk {
            e: None,
            i: into_iter,
        }
    }

    pub fn finish(mut self) -> Option<E> {
        self.e.take()
    }
}

impl<I, E> Drop for WhileOk<I, E>
where
    E: std::error::Error,
{
    fn drop(&mut self) {
        if !std::thread::panicking() {
            if let Some(e) = self.e.take() {
                panic!("Unhandled error in `WhileOk` iterator: {}", e);
            }
        }
    }
}

impl<I, O, E> Iterator for WhileOk<I, E>
where
    I: Iterator<Item = Result<O, E>>,
    E: std::error::Error,
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
