// {{{ use
use {Digest, DigestRef, Name};
// }}}

// {{{ DataAddress & DataAddressRef
/// An unique id representing some stored in the `Repo`
///
/// Holds `digest` as a reference
pub(crate) struct DataAddressRef<'a> {
    // number of times the data index
    // was written (and then index of an index and so forth)
    // until it was reduced to a final digest
    pub(crate) index_level: u32,
    // final digest
    pub(crate) digest: DigestRef<'a>,
}

#[derive(Clone)]
/// An unique id representing some stored in the `Repo`
///
/// With owned `digest`
pub(crate) struct DataAddress {
    // number of times the data index
    // was written (and then index of an index and so forth)
    // until it was reduced to a final digest
    pub(crate) index_level: u32,
    // final digest
    pub(crate) digest: Digest,
}

impl DataAddress {
    pub(crate) fn as_ref(&self) -> DataAddressRef {
        DataAddressRef {
            index_level: self.index_level,
            digest: self.digest.as_digest_ref(),
        }
    }
}

impl From<Name> for DataAddress {
    fn from(name: Name) -> Self {
        DataAddress {
            index_level: name.index_level,
            digest: Digest(name.digest),
        }
    }
}
// }}}

// {{{ Digest & DigestRef
#[derive(Clone)]
struct Digest(Vec<u8>);

impl Digest {
    fn as_digest_ref(&self) -> DigestRef {
        DigestRef(self.0.as_slice())
    }
}

#[derive(Copy, Clone)]
struct DigestRef<'a>(&'a [u8]);
// }}}

/// Opaque wrapper over secret key
struct SecretKey(box_::SecretKey);

// vim: foldmethod=marker foldmarker={{{,}}}
