use {serde, box_, secretbox, pwhash, base64};
use serde::Deserialize;
use std::io;

pub trait MyTryFromBytes: Sized {
    type Err: 'static + Sized + ::std::error::Error;
    fn try_from(&[u8]) -> Result<Self, Self::Err>;
}

impl MyTryFromBytes for box_::PublicKey {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        box_::PublicKey::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive PublicKey from invalid binary data")
        })
    }
}

impl MyTryFromBytes for secretbox::Nonce {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        secretbox::Nonce::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive Nonce from invalid binary data")
        })
    }
}

impl MyTryFromBytes for pwhash::Salt {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        pwhash::Salt::from_slice(slice).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData,
                           "can't derive Nonce from invalid binary data")
        })
    }
}

impl MyTryFromBytes for Vec<u8> {
    type Err = io::Error;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Err> {
        Ok(Vec::from(slice))
    }
}


pub fn from_base64<T, D>(deserializer: D) -> Result<T, D::Error>
    where D: serde::Deserializer,
          T: MyTryFromBytes
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| {
                      base64::decode(&string)
                .map_err(|err| Error::custom(err.to_string()))
                  })
        .and_then(|ref bytes| {
                      T::try_from(bytes).map_err(|err| {
                Error::custom(format!("{}", &err as &::std::error::Error))
            })
                  })
}

pub fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: AsRef<[u8]>,
          S: serde::Serializer
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}
