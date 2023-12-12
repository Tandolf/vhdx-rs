use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

use nom::{bytes::complete::take, combinator::map, sequence::tuple, Finish, IResult};
use uuid::Uuid;

use crate::{
    error::{VhdxError, VhdxParseError},
    DeSerialise,
};

use super::{
    parse_utils::{t_bool_u32, t_guid, t_sign_u32, t_u32, t_u64},
    signatures::{Signature, BAT_ENTRY, META_DATA_ENTRY},
};

const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 32;
const RT_HEADER_SIZE: usize = 65536;

// The region table consists of a header followed by a variable number of entries, which specify
// the identity and location of regions within the file. There are two copies of the region table,
// stored at file offset 192 KB and file offset 256 KB. Updates to the region table structures must
// be made through the log.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RTHeader {
    // MUST be 0x72656769, which is a UTF-8 string representing "regi".
    signature: Signature,
    // A CRC-32C hash over the entire 64-KB table, with the Checksum field taking the value of zero
    // during the computation of the checksum value.
    checksum: u32,
    entry_count: usize,

    pub table_entries: HashMap<KnowRegion, RTEntry>,
}
impl RTHeader {
    fn new(signature: Signature, checksum: u32, entry_count: usize) -> Self {
        Self {
            signature,
            checksum,
            entry_count,
            table_entries: HashMap::with_capacity(entry_count),
        }
    }
}

fn reserved(buffer: &[u8]) -> IResult<&[u8], &[u8], VhdxParseError<&[u8]>> {
    take(4usize)(buffer)
}

fn parse_header(buffer: &[u8]) -> IResult<&[u8], RTHeader, VhdxParseError<&[u8]>> {
    map(
        tuple((t_sign_u32, t_u32, t_u32, reserved)),
        |(signature, checksum, entry_count, _)| {
            RTHeader::new(signature, checksum, entry_count as usize)
        },
    )(buffer)
}

impl<T> DeSerialise<T> for RTHeader {
    type Item = RTHeader;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; HEADER_SIZE];
        reader.read_exact(&mut buffer)?;
        let (_, mut header) = parse_header(&buffer).finish()?;
        let mut offset = RT_HEADER_SIZE - HEADER_SIZE;
        for _ in 0..header.entry_count {
            let entry = RTEntry::deserialize(reader)?;
            let known_region = match entry.guid {
                BAT_ENTRY => Ok(KnowRegion::Bat),
                META_DATA_ENTRY => Ok(KnowRegion::MetaData),
                _ => Err(VhdxError::UnknownRTEntryFound(entry.guid.to_string())),
            }?;
            header.table_entries.insert(known_region, entry);
            offset -= ENTRY_SIZE;
        }

        reader.seek(SeekFrom::Current(offset as i64))?;

        Ok(header)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RTEntry {
    // Guid (16 bytes): Specifies a 128-bit identifier for the object (a GUID in binary form) and
    // MUST be unique within the table.
    pub guid: Uuid,
    // FileOffset (8 bytes): Specifies the 64-bit byte offset of the object within the file. The
    // value MUST be a multiple of 1 MB and MUST be at least 1 MB.
    pub file_offset: u64,
    // Length (4 bytes): Specifies the 32-bit byte length of the object within the file. The value
    // MUST be a multiple of 1 MB.
    length: u32,
    // Required (4 bytes): Specifies whether this region must be recognized by the implementation
    // in order to load the VHDX file. If this field's value is 1 and the impleme
    required: bool,
}
impl RTEntry {
    fn new(guid: Uuid, file_offset: u64, length: u32, required: bool) -> Self {
        Self {
            guid,
            file_offset,
            length,
            required,
        }
    }
}

fn parse_entry(buffer: &[u8]) -> IResult<&[u8], RTEntry, VhdxParseError<&[u8]>> {
    map(
        tuple((t_guid, t_u64, t_u32, t_bool_u32)),
        |(guid, file_offset, length, required)| RTEntry::new(guid, file_offset, length, required),
    )(buffer)
}

impl<T> DeSerialise<T> for RTEntry {
    type Item = RTEntry;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 32];

        reader.read_exact(&mut buffer)?;
        let (_, entry) = parse_entry(&buffer).finish()?;
        Ok(entry)
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum KnowRegion {
    Bat,
    MetaData,
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::*;

    #[test]
    fn should_deserialize_rth() {
        let mut values = vec![
            0x72, 0x65, 0x67, 0x69, 0xae, 0x8c, 0x6b, 0xc6, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e,
            0x9b, 0xfd, 0x4a, 0x08, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b,
            0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        values.resize(RT_HEADER_SIZE, 0);

        let mut values = Cursor::new(values);

        let rth = RTHeader::deserialize(&mut values).unwrap();

        assert_eq!(Signature::Regi, rth.signature);
    }
}
