use std::{collections::HashMap, io::SeekFrom};

use nom::{
    bits,
    bytes::complete::take,
    combinator::map,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
    IResult,
};
use uuid::Uuid;

use crate::{vhdx::signatures::PHYSICAL_SECTOR_SIZE, DeSerialise};

use super::{
    bits_parsers::{t_2_flags_u32, t_3_flags_u32},
    parse_utils::{t_guid, t_sign_u64},
    signatures::{
        Signature, FILE_PARAMETERS, LOGICAL_SECTOR_SIZE, VIRTUAL_DISK_ID, VIRTUAL_DISK_SIZE,
    },
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
    fn new(signature: Signature, entry_count: u16, entries: Vec<Entry>) -> Self {
        Self {
            signature,
            entry_count,
            entries,
        }
    }
}

impl<T> DeSerialise<T> for MetaData {
    type Item = MetaData;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: std::io::Read + std::io::Seek,
    {
        let start_pos = reader.stream_position()?;

        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let (_, (signature, entry_count)) = parse_header(&buffer).unwrap();

        let mut entries = Vec::new();
        for _ in 0..5 {
            let mut buffer = [0; 32];
            reader.read_exact(&mut buffer)?;

            let (_, (signature, offset, length, a, b, c)) = parse_entry(&buffer).unwrap();

            let start_next = reader.stream_position()?;

            dbg!(&signature);
            let entry = match signature {
                FILE_PARAMETERS => {
                    reader.seek(SeekFrom::Start(start_pos + offset as u64))?;
                    let mut buffer = [0; 8];
                    reader.read_exact(&mut buffer)?;
                    let (_, file_parameters) = parse_file_params(&buffer).unwrap();
                    Entry::new(signature, offset, length, a, b, c, file_parameters)
                }
                VIRTUAL_DISK_SIZE => {
                    reader.seek(SeekFrom::Start(start_pos + offset as u64))?;
                    let mut buffer = [0; 8];
                    reader.read_exact(&mut buffer)?;
                    let (_, vds) = t_v_disk_size(&buffer).unwrap();
                    Entry::new(
                        signature,
                        offset,
                        length,
                        a,
                        b,
                        c,
                        MDKnownEntries::VirtualDiskSize(vds),
                    )
                }
                VIRTUAL_DISK_ID => {
                    reader.seek(SeekFrom::Start(start_pos + offset as u64))?;
                    let mut buffer = [0; 16];
                    reader.read_exact(&mut buffer)?;
                    let (_, vd_id) = t_guid(&buffer).unwrap();
                    Entry::new(
                        signature,
                        offset,
                        length,
                        a,
                        b,
                        c,
                        MDKnownEntries::VirtualDiskID(vd_id),
                    )
                }
                LOGICAL_SECTOR_SIZE => {
                    reader.seek(SeekFrom::Start(start_pos + offset as u64))?;
                    let mut buffer = [0; 4];
                    reader.read_exact(&mut buffer)?;
                    let (_, sector_size) = t_sector_size(&buffer).unwrap();
                    Entry::new(
                        signature,
                        offset,
                        length,
                        a,
                        b,
                        c,
                        MDKnownEntries::LogicalSectorSize(sector_size),
                    )
                }
                PHYSICAL_SECTOR_SIZE => {
                    reader.seek(SeekFrom::Start(start_pos + offset as u64))?;
                    let mut buffer = [0; 4];
                    reader.read_exact(&mut buffer)?;
                    let (_, sector_size) = t_sector_size(&buffer).unwrap();
                    Entry::new(
                        signature,
                        offset,
                        length,
                        a,
                        b,
                        c,
                        MDKnownEntries::PhysicalSectorSize(sector_size),
                    )
                }
                _ => panic!("foobar"),
            };
            entries.push(entry);
            reader.seek(SeekFrom::Start(start_next))?;
        }
        Ok(MetaData::new(signature, entry_count, entries))
    }
}

fn t_sector_size(buffer: &[u8]) -> IResult<&[u8], SectorSize> {
    map(le_u32, |v: u32| match v {
        512 => SectorSize::Small,
        4096 => SectorSize::Large,
        _ => SectorSize::Unknown,
    })(buffer)
}

fn parse_header(reader: &[u8]) -> IResult<&[u8], (Signature, u16)> {
    map(
        tuple((t_sign_u64, le_u16, le_u16, take(20usize))),
        |(signature, _, entry_count, _)| (signature, entry_count),
    )(reader)
}

fn t_v_disk_size(buffer: &[u8]) -> IResult<&[u8], u64> {
    le_u64(buffer)
}

#[derive(Debug)]
pub struct Entry {
    pub item_id: Uuid,
    pub offset: usize,
    pub length: usize,
    is_user: bool,
    is_virtual_disk: bool,
    is_required: bool,
    data: MDKnownEntries,
}
impl Entry {
    fn new(
        item_id: Uuid,
        offset: usize,
        length: usize,
        is_user: bool,
        is_virtual_disk: bool,
        is_required: bool,
        data: MDKnownEntries,
    ) -> Entry {
        Self {
            item_id,
            offset,
            length,
            is_user,
            is_virtual_disk,
            is_required,
            data,
        }
    }
}

fn parse_entry(buffer: &[u8]) -> IResult<&[u8], (Uuid, usize, usize, bool, bool, bool)> {
    map(
        tuple((t_guid, le_u32, le_u32, bits(t_3_flags_u32), take(7usize))),
        |(guid, offset, length, (is_user, is_virtual_disk, is_required), _)| {
            (
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

fn parse_file_params(buffer: &[u8]) -> IResult<&[u8], MDKnownEntries> {
    map(
        tuple((le_u32, bits(t_2_flags_u32))),
        |(block_size, (leave_block_allocated, has_parent)): (u32, (bool, bool))| {
            MDKnownEntries::FileParameters {
                block_size: block_size as usize,
                leave_block_allocated,
                has_parent,
            }
        },
    )(buffer)
}

#[derive(Debug)]
pub enum MDKnownEntries {
    FileParameters {
        block_size: usize,
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

#[derive(Debug)]
pub enum SectorSize {
    Small = 512,
    Large = 4096,
    Unknown = -1,
}

#[derive(Debug)]
pub enum LocatorTypeEntry {
    Guid(Uuid),
    Path(String),
}
