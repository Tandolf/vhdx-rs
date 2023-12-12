use std::{collections::HashMap, io::SeekFrom};

use super::Signature;
use nom::{
    bits,
    bytes::complete::take,
    combinator::map,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
    IResult,
};
use uuid::Uuid;

use crate::{
    bat::{
        calc_chunk_ratio, calc_payload_blocks_count, calc_sector_bitmap_blocks_count,
        calc_total_bat_entries_differencing, calc_total_bat_entries_fixed_dynamic,
    },
    error::{VhdxError, VhdxParseError},
    signatures::PHYSICAL_SECTOR_SIZE,
    DeSerialise,
};

use super::{
    bits_parsers::{t_2_flags_u32, t_3_flags_u32},
    parse_utils::{t_guid, t_sign_u64},
    signatures::{FILE_PARAMETERS, LOGICAL_SECTOR_SIZE, VIRTUAL_DISK_ID, VIRTUAL_DISK_SIZE},
};

#[allow(dead_code)]
#[derive(Debug)]
pub struct MetaData {
    // Signature (8 bytes): MUST be 0x617461646174656D ("metadata" as ASCII).
    signature: Signature,

    // EntryCount (2 bytes): Specifies the number of entries in the table. This value must be less
    // than or equal to 2,047. The free space in the metadata region may contain data that can be
    // disregarded.
    pub entry_count: u16,
    pub file_parameters: FileParameters,
    pub virtual_disk_size: usize,
    pub virtual_disk_id: Uuid,
    pub logical_sector_size: SectorSize,
    pub physical_sector_size: SectorSize,
    pub chunk_ratio: u64,
    pub payload_blocks_count: u64,
    pub sector_bitmaps_blocks_count: u64,
    pub total_bat_entries_fixed_dynamic: u64,
    pub total_bat_entries_differencing: u64,
    pub(crate) entries: HashMap<Uuid, Entry>,
}

impl MetaData {
    fn new(
        signature: Signature,
        entry_count: u16,
        entries: HashMap<Uuid, Entry>,
        file_parameters: FileParameters,
        virtual_disk_size: usize,
        virtual_disk_id: Uuid,
        logical_sector_size: SectorSize,
        physical_sector_size: SectorSize,
        chunk_ratio: u64,
        payload_blocks_count: u64,
        sector_bitmaps_blocks_count: u64,
        total_bat_entries_fixed_dynamic: u64,
        total_bat_entries_differencing: u64,
    ) -> Self {
        Self {
            signature,
            entry_count,
            entries,
            file_parameters,
            virtual_disk_size,
            virtual_disk_id,
            logical_sector_size,
            physical_sector_size,
            chunk_ratio,
            payload_blocks_count,
            sector_bitmaps_blocks_count,
            total_bat_entries_fixed_dynamic,
            total_bat_entries_differencing,
        }
    }
}

impl<T> DeSerialise<T> for MetaData {
    type Item = MetaData;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: std::io::Read + std::io::Seek,
    {
        let start_pos = reader.stream_position()?;

        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let (_, (signature, entry_count)) = parse_header(&buffer).unwrap();

        let mut entries = HashMap::new();
        for _ in 0..5 {
            let mut buffer = [0; 32];
            reader.read_exact(&mut buffer)?;

            let (_, (signature, offset, length, a, b, c)) = parse_entry(&buffer).unwrap();

            let start_next = reader.stream_position()?;

            let entry = Entry::new(signature, offset, length, a, b, c);
            match signature {
                FILE_PARAMETERS => {
                    entries.insert(FILE_PARAMETERS, entry);
                }
                VIRTUAL_DISK_SIZE => {
                    entries.insert(VIRTUAL_DISK_SIZE, entry);
                }
                VIRTUAL_DISK_ID => {
                    entries.insert(VIRTUAL_DISK_ID, entry);
                }
                LOGICAL_SECTOR_SIZE => {
                    entries.insert(LOGICAL_SECTOR_SIZE, entry);
                }
                PHYSICAL_SECTOR_SIZE => {
                    entries.insert(PHYSICAL_SECTOR_SIZE, entry);
                }
                _ => panic!("Could not identify signature for read metadata entry"),
            }
            reader.seek(SeekFrom::Start(start_next))?;
        }

        let entry = entries[&FILE_PARAMETERS];
        reader.seek(SeekFrom::Start(start_pos + entry.offset as u64))?;
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer)?;
        let (_, file_parameters) = parse_file_params(&buffer).unwrap();

        let entry = entries[&VIRTUAL_DISK_SIZE];
        reader.seek(SeekFrom::Start(start_pos + entry.offset as u64))?;
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer)?;
        let (_, virtual_disk_size) = t_v_disk_size(&buffer).unwrap();

        let entry = entries[&VIRTUAL_DISK_ID];
        reader.seek(SeekFrom::Start(start_pos + entry.offset as u64))?;
        let mut buffer = [0; 16];
        reader.read_exact(&mut buffer)?;
        let (_, virtual_disk_id) = t_guid(&buffer).unwrap();

        let entry = entries[&LOGICAL_SECTOR_SIZE];
        reader.seek(SeekFrom::Start(start_pos + entry.offset as u64))?;
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer)?;
        let (_, logical_sector_size) = t_sector_size(&buffer).unwrap();

        let entry = entries[&PHYSICAL_SECTOR_SIZE];
        reader.seek(SeekFrom::Start(start_pos + entry.offset as u64))?;
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer)?;
        let (_, physical_sector_size) = t_sector_size(&buffer).unwrap();

        let chunk_ratio = calc_chunk_ratio(logical_sector_size, file_parameters.block_size);

        let payload_blocks_count =
            calc_payload_blocks_count(virtual_disk_size, file_parameters.block_size);

        let sector_bitmaps_blocks_count =
            calc_sector_bitmap_blocks_count(payload_blocks_count as usize, chunk_ratio as usize);

        let total_bat_entries_fixed_dynamic =
            calc_total_bat_entries_fixed_dynamic(payload_blocks_count, chunk_ratio);
        let total_bat_entries_differencing =
            calc_total_bat_entries_differencing(sector_bitmaps_blocks_count, chunk_ratio);

        Ok(MetaData::new(
            signature,
            entry_count,
            entries,
            file_parameters,
            virtual_disk_size,
            virtual_disk_id,
            logical_sector_size,
            physical_sector_size,
            chunk_ratio,
            payload_blocks_count,
            sector_bitmaps_blocks_count,
            total_bat_entries_fixed_dynamic,
            total_bat_entries_differencing,
        ))
    }
}

fn t_sector_size(buffer: &[u8]) -> IResult<&[u8], SectorSize> {
    map(le_u32, |v: u32| match v.try_into() {
        Ok(SectorSize::Sector512) => SectorSize::Sector512,
        Ok(SectorSize::Sector4096) => SectorSize::Sector4096,
        Err(_) => todo!(),
    })(buffer)
}

fn parse_header(reader: &[u8]) -> IResult<&[u8], (Signature, u16), VhdxParseError<&[u8]>> {
    map(
        tuple((t_sign_u64, le_u16, le_u16, take(20usize))),
        |(signature, _, entry_count, _)| (signature, entry_count),
    )(reader)
}

fn t_v_disk_size(buffer: &[u8]) -> IResult<&[u8], usize> {
    map(le_u64, |v| v as usize)(buffer)
}

#[derive(Debug, Copy, Clone)]
pub struct Entry {
    pub item_id: Uuid,
    pub offset: usize,
    pub length: usize,
    pub is_user: bool,
    pub is_virtual_disk: bool,
    pub is_required: bool,
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

fn parse_entry(
    buffer: &[u8],
) -> IResult<&[u8], (Uuid, usize, usize, bool, bool, bool), VhdxParseError<&[u8]>> {
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

fn parse_file_params(buffer: &[u8]) -> IResult<&[u8], FileParameters, VhdxParseError<&[u8]>> {
    map(
        tuple((le_u32, bits(t_2_flags_u32))),
        |(block_size, (leave_block_allocated, has_parent)): (u32, (bool, bool))| FileParameters {
            block_size: block_size as usize,
            leave_block_allocated,
            has_parent,
        },
    )(buffer)
}

#[derive(Debug, Clone, Copy)]
pub enum SectorSize {
    Sector512 = 512,
    Sector4096 = 4096,
}

impl TryFrom<u32> for SectorSize {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == SectorSize::Sector512 as u32 => Ok(SectorSize::Sector512),
            x if x == SectorSize::Sector4096 as u32 => Ok(SectorSize::Sector512),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub enum LocatorTypeEntry {
    Guid(Uuid),
    Path(String),
}

#[derive(Debug)]
pub struct FileParameters {
    pub block_size: usize,
    pub leave_block_allocated: bool,
    pub has_parent: bool,
}
