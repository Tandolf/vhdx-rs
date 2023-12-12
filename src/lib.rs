use std::io::{Read, Seek};

use error::VhdxError;

pub mod error;
pub mod vhdx;

pub trait DeSerialise<T> {
    type Item;

    fn deserialize(fs: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek;
}

pub trait Crc32 {
    fn crc32(&self) -> u32;
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
