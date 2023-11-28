use std::io::{Read, Seek, SeekFrom};

use crate::DeSerialise;

use super::{header::Header, log::log::Log};

#[derive(Debug)]
pub struct Vhdx {
    header: Header,
    log: Log,
}

impl Vhdx {
    pub fn new<T>(reader: &mut T) -> Self
    where
        T: Read + Seek,
    {
        let header = Header::deserialize(reader).unwrap();
        let h = &header.header_1;

        let _ = reader.seek(SeekFrom::Start(h.log_offset));

        let log = Log::deserialize(reader).unwrap();

        Vhdx { header, log }
    }
}
