use std::io::{Read, Seek};

use error::VhdxError;

pub mod bat;
pub mod bits_parsers;
pub mod error;
pub mod log;
pub mod meta_data;
pub mod parse_utils;
pub mod vhdx;
pub mod vhdx_header;

pub trait DeSerialise<T> {
    type Item;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek;
}

pub trait Crc32 {
    fn crc32(&self) -> u32;
    fn crc32_from_digest(&self, digest: &mut crc::Digest<u32>);
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Signature {
    Vhdxfile,
    Head,
    Regi,
    Loge,
    Zero,
    Data,
    Desc,
    MetaData,
    Unknown,
}
