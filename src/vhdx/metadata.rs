use std::collections::HashMap;

use nom::{
    bits,
    bytes::complete::take,
    combinator::map,
    number::{
        complete::{le_u16, le_u32},
        streaming::be_u32,
    },
    sequence::tuple,
    IResult,
};
use uuid::Uuid;

use crate::DeSerialise;

use super::{
    parse_utils::{parse_bool, t_guid, t_sign_u64, BitInput},
    signatures::Signature,
};

#[derive(Debug)]
pub struct MetaData {
    // Signature (8 bytes): MUST be 0x617461646174656D ("metadata" as ASCII).
    signature: Signature,

    // EntryCount (2 bytes): Specifies the number of entries in the table. This value must be less
    // than or equal to 2,047. The free space in the metadata region may contain data that can be
    // disregarded.
    pub entry_count: u16,

    pub entries: Vec<Entry>,
}
impl MetaData {
    fn new(signature: Signature, entry_count: u16) -> Self {
        Self {
            signature,
            entry_count,
            entries: Vec::new(),
        }
    }
}

impl<T> DeSerialise<T> for MetaData {
    type Item = MetaData;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let (_, meta_data) = parse_meta_data(&buffer).unwrap();
        Ok(meta_data)
    }
}

fn parse_meta_data(reader: &[u8]) -> IResult<&[u8], MetaData> {
    map(
        tuple((t_sign_u64, le_u16, le_u16, take(20usize))),
        |(signature, _, entry_count, _)| MetaData::new(signature, entry_count),
    )(reader)
}

#[derive(Debug)]
pub struct Entry {
    item_id: Uuid,
    offset: usize,
    length: usize,
    is_user: bool,
    is_virtual_disk: bool,
    is_required: bool,
}
impl Entry {
    fn new(
        item_id: Uuid,
        offset: usize,
        length: usize,
        is_user: bool,
        is_virtual_disk: bool,
        is_required: bool,
    ) -> Entry {
        Self {
            item_id,
            offset,
            length,
            is_user,
            is_virtual_disk,
            is_required,
        }
    }
}

impl<T> DeSerialise<T> for Entry {
    type Item = Entry;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let (_, entry) = parse_entry(&buffer).unwrap();
        Ok(entry)
    }
}

fn parse_entry(buffer: &[u8]) -> IResult<&[u8], Entry> {
    map(
        tuple((t_guid, le_u32, le_u32, bits(parse_flags), take(7usize))),
        |(guid, offset, length, (is_user, is_virtual_disk, is_required), _)| {
            Entry::new(
                guid,
                offset as usize,
                length as usize,
                is_user,
                is_virtual_disk,
                is_required,
            )
        },
    )(buffer)
}

fn parse_flags(input: BitInput) -> IResult<BitInput, (bool, bool, bool)> {
    dbg!(input);
    map(
        tuple((
            nom::bits::complete::take(5usize),
            parse_bool,
            parse_bool,
            parse_bool,
        )),
        |(_, a, b, c): (u8, bool, bool, bool)| (c, b, a),
    )(input)
}

pub enum MetaDataItems {
    FileParameters {
        block_size: u32,
        leave_block_allocated: bool,
        has_parent: bool,
    },
    VirtualDiskSize(u64),
    VirtualDiskID(Uuid),
    LogicalSectorSize(SectorSize),
    PhysicalSectorSize(SectorSize),
    ParentLocatorHeader {
        locator_type: Uuid,
        key_value_count: u8,
        entries: HashMap<String, LocatorTypeEntry>,
    },
}

pub enum SectorSize {
    Small = 512,
    Large = 4096,
}

pub enum LocatorTypeEntry {
    Guid(Uuid),
    Path(String),
}
