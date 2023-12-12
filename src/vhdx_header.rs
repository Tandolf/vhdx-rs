use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crc::{Crc, CRC_32_ISCSI};
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
use uuid::Uuid;

use crate::error::{Result, VhdxError, VhdxParseError};
use crate::parse_utils::{
    t_bool_u32, t_creator, t_guid, t_sign_u32, t_sign_u64, t_u16, t_u32, t_u64,
};
use crate::signatures::{BAT_ENTRY, META_DATA_ENTRY};
use crate::{Crc32, DeSerialise, Signature};

pub const SECTION_SIZE: usize = 64000;
pub const HEADER_TOTAL_SIZE: usize = 1000000;

#[allow(dead_code)]
#[derive(Debug)]
pub struct MainHeader {
    fti: FileTypeIdentifier,
    pub header_1: Header,
    pub header_2: Header,
    pub region_table_1: RegionTable,
    pub region_table_2: RegionTable,
}
impl MainHeader {
    fn new(
        fti: FileTypeIdentifier,
        header_1: Header,
        header_2: Header,
        region_table_1: RegionTable,
        region_table_2: RegionTable,
    ) -> Self {
        Self {
            fti,
            header_1,
            header_2,
            region_table_1,
            region_table_2,
        }
    }
}

impl<T> DeSerialise<T> for MainHeader {
    type Item = MainHeader;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let fti = FileTypeIdentifier::deserialize(reader)?;
        let header_1 = Header::deserialize(reader)?;
        let header_2 = Header::deserialize(reader)?;
        let rt_1 = RegionTable::deserialize(reader)?;
        let rt_2 = RegionTable::deserialize(reader)?;

        Ok(MainHeader::new(fti, header_1, header_2, rt_1, rt_2))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct FileTypeIdentifier {
    signature: Signature,
    creator: String,
}

impl FileTypeIdentifier {
    const SIZE: usize = 65536;

    fn new(signature: Signature, creator: String) -> FileTypeIdentifier {
        Self { signature, creator }
    }
}

impl<T> DeSerialise<T> for FileTypeIdentifier {
    type Item = FileTypeIdentifier;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; FileTypeIdentifier::SIZE];
        reader.read_exact(&mut buffer)?;

        let (_, fti) = map(tuple((t_sign_u64, t_creator)), |(signature, creator)| {
            FileTypeIdentifier::new(signature, creator)
        })(&buffer)?;
        Ok(fti)
    }
}

// Since the header is used to locate the log, updates to the headers cannot be made through the
// log. To provide power failure consistency, there are two headers in every VHDX file. Each of the
// two headers is a 4-KB structure that is aligned to a 64-KB boundary.<1> One header is stored at
// offset 64 KB and the other at 128 KB. Only one header is considered current and in use at any
// point in time.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub struct Header {
    // MUST be 0x68656164 which is a UTF-8 string representing "head".
    signature: Signature,

    // A CRC-32C hash over the entire 4-KB structure, with the Checksum field taking the value of
    // zero during the computation of the checksum value.
    checksum: u32,

    // A 64-bit unsigned integer. A header is valid if the Signature and Checksum fields both
    // validate correctly. A header is current if it is the only valid header or if it is valid and
    // its SequenceNumber field is greater than the other header's SequenceNumber field. The
    // implementation MUST only use data from the current header. If there is no current header,
    // then the VHDX file is corrupt.
    seq_number: u64,

    // Specifies a 128-bit unique identifier that identifies the file's contents. On every open of
    // a VHDX file, an implementation MUST change this GUID to a new and unique identifier before
    // the first modification is made to the file, including system and user metadata as well as
    // log playback. The implementation can skip updating this field if the storage media on which
    // the file is stored is read-only, or if the file is opened in read-only mode.
    file_write_guid: Uuid,

    // Specifies a 128-bit unique identifier that identifies the contents of the user visible data.
    // On every open of the VHDX file, an implementation MUST change this field to a new and unique
    // identifier before the first modification is made to user-visible data. If the user of the
    // virtual disk can observe the change through a virtual disk read, then the implementation
    // MUST update this field.<2> This includes changing the system and user metadata, raw block
    // data, or disk size, or any block state transitions that will result in a virtual disk sector
    // read being different from a previous read. This does not include movement of blocks within a
    // file, which changes only the physical layout of the file, not the virtual identity.
    data_write_guid: Uuid,

    // Specifies a 128-bit unique identifier used to determine the validity of log entries. If this
    // field is zero, then the log is empty or has no valid entries and MUST not be replayed.
    // Otherwise, only log entries that contain this identifier in their header are valid log
    // entries. Upon open, the implementation MUST update this field to a new nonzero value before
    // overwriting existing space within the log region.
    log_guid: Uuid,

    // Specifies the version of the log format used within the VHDX file. This field MUST be set to
    // zero. If it is not, the implementation MUST NOT continue to process the file unless the
    // LogGuid field is zero, indicating that there is no log to replay.
    log_version: u16,

    // Specifies the version of the VHDX format used within the VHDX file. This field MUST be set
    // to 1. If it is not, an implementation MUST NOT attempt to process the file using the details
    // from this format specification.
    version: u16,

    // A 32-bit unsigned integer. Specifies the size, in bytes of the log. This value MUST be a
    // multiple of 1MB.
    pub log_length: u32,

    // A 64-bit unsigned integer. Specifies the byte offset in the file of the log. This
    // value MUST be a multiple of 1MB. The log MUST NOT overlap any other structures.
    pub log_offset: u64,
}

impl Header {
    const SIZE: usize = 65536;
    const SIGN: &'static [u8] = &[0x68, 0x65, 0x61, 0x64];
    fn new(
        signature: Signature,
        checksum: u32,
        seq_number: u64,
        file_write_guid: Uuid,
        data_write_guid: Uuid,
        log_guid: Uuid,
        log_version: u16,
        version: u16,
        log_length: u32,
        log_offset: u64,
    ) -> Header {
        Self {
            signature,
            checksum,
            seq_number,
            file_write_guid,
            data_write_guid,
            log_guid,
            log_version,
            version,
            log_length,
            log_offset,
        }
    }
}

impl Crc32 for Header {
    fn crc32(&self) -> u32 {
        let crc = Crc::<u32>::new(&CRC_32_ISCSI);
        let mut hasher = crc.digest();

        hasher.update(Header::SIGN);
        hasher.update(&[0; 4]);
        hasher.update(&self.seq_number.to_le_bytes());
        hasher.update(&self.file_write_guid.to_bytes_le());
        hasher.update(&self.data_write_guid.to_bytes_le());
        hasher.update(&self.log_guid.to_bytes_le());
        hasher.update(&self.log_version.to_le_bytes());
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.log_length.to_le_bytes());
        hasher.update(&self.log_offset.to_le_bytes());
        hasher.update(&[0; 4016]);
        hasher.finalize()
    }
}

fn parse_headers(buffer: &[u8]) -> IResult<&[u8], Header, VhdxParseError<&[u8]>> {
    map(
        tuple((
            t_sign_u32, t_u32, t_u64, t_guid, t_guid, t_guid, t_u16, t_u16, t_u32, t_u64,
        )),
        |(
            signature,
            checksum,
            seq_number,
            file_write_guid,
            data_write_guid,
            log_guid,
            log_version,
            version,
            log_length,
            log_offset,
        )| {
            Header::new(
                signature,
                checksum,
                seq_number,
                file_write_guid,
                data_write_guid,
                log_guid,
                log_version,
                version,
                log_length,
                log_offset,
            )
        },
    )(buffer)
}

impl<T> DeSerialise<T> for Header {
    type Item = Header;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; Header::SIZE];
        reader.read_exact(&mut buffer)?;
        let (_, headers) = parse_headers(&buffer)?;
        Ok(headers)
    }
}

// The region table consists of a header followed by a variable number of entries, which specify
// the identity and location of regions within the file. There are two copies of the region table,
// stored at file offset 192 KB and file offset 256 KB. Updates to the region table structures must
// be made through the log.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RegionTable {
    // MUST be 0x72656769, which is a UTF-8 string representing "regi".
    signature: Signature,
    // A CRC-32C hash over the entire 64-KB table, with the Checksum field taking the value of zero
    // during the computation of the checksum value.
    checksum: u32,
    entry_count: usize,

    pub table_entries: HashMap<KnowRegion, RTEntry>,
}

impl RegionTable {
    const HEADER_SIZE: usize = 16;
    const ENTRY_SIZE: usize = 32;
    const RT_HEADER_SIZE: usize = 65536;

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

fn parse_header(buffer: &[u8]) -> IResult<&[u8], RegionTable, VhdxParseError<&[u8]>> {
    map(
        tuple((t_sign_u32, t_u32, t_u32, reserved)),
        |(signature, checksum, entry_count, _)| {
            RegionTable::new(signature, checksum, entry_count as usize)
        },
    )(buffer)
}

impl<T> DeSerialise<T> for RegionTable {
    type Item = RegionTable;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; RegionTable::HEADER_SIZE];
        reader.read_exact(&mut buffer)?;
        let (_, mut header) = parse_header(&buffer)?;
        let mut offset = RegionTable::RT_HEADER_SIZE - RegionTable::HEADER_SIZE;
        for _ in 0..header.entry_count {
            let entry = RTEntry::deserialize(reader)?;
            let known_region = match entry.guid {
                BAT_ENTRY => Ok(KnowRegion::Bat),
                META_DATA_ENTRY => Ok(KnowRegion::MetaData),
                _ => Err(VhdxError::UnknownRTEntryFound(entry.guid.to_string())),
            }?;
            header.table_entries.insert(known_region, entry);
            offset -= RegionTable::ENTRY_SIZE;
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
        let (_, entry) = parse_entry(&buffer)?;
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

    use crate::Signature;
    use uuid::uuid;

    use super::*;

    #[test]
    fn parse_file_header() {
        // FTI
        let mut b_fti = vec![
            0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6c, 0x65, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
            0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00,
            0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
            0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x30,
        ];

        b_fti.resize(64000, 0);

        // 2 header sections
        let mut b_header_1 = vec![
            0x68, 0x65, 0x61, 0x64, 0x6c, 0xef, 0x07, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xcc, 0xe0, 0x65, 0xb3, 0xaa, 0xf1, 0xd8, 0x4b, 0x9c, 0x8d, 0x16, 0x09,
            0xd9, 0x38, 0xb5, 0xec, 0x59, 0xe3, 0xca, 0x76, 0xef, 0xf9, 0xab, 0x45, 0xad, 0x4a,
            0x77, 0xda, 0xae, 0xce, 0xf6, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        b_header_1.resize(64000, 0);

        let mut b_header_2 = b_header_1.clone();

        let mut b_region_table_1 = vec![
            0x72, 0x65, 0x67, 0x69, 0xae, 0x8c, 0x6b, 0xc6, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e,
            0x9b, 0xfd, 0x4a, 0x08, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b,
            0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        b_region_table_1.resize(64000, 0);
        let mut b_region_table_2 = b_region_table_1.clone();

        let mut bytes = Vec::new();
        bytes.append(&mut b_fti);
        bytes.append(&mut b_header_1);
        bytes.append(&mut b_header_2);
        bytes.append(&mut b_region_table_1);
        bytes.append(&mut b_region_table_2);

        let mut bytes = Cursor::new(bytes);

        let header = MainHeader::deserialize(&mut bytes).unwrap();

        dbg!(&header);

        assert_eq!(Signature::Vhdxfile, header.fti.signature);
    }

    #[test]
    fn parse_fti() {
        let mut values = vec![
            0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6c, 0x65, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
            0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00,
            0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
            0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x30,
        ];

        values.resize(FileTypeIdentifier::SIZE, 0);

        let mut values = Cursor::new(values);

        let fti = FileTypeIdentifier::deserialize(&mut values).unwrap();

        assert_eq!(Signature::Vhdxfile, fti.signature);
        assert_eq!("Microsoft Windows 10.0.19045.0", fti.creator);
    }

    #[test]
    fn parse_headers() {
        let mut values = vec![
            0x68, 0x65, 0x61, 0x64, 0x6c, 0xef, 0x07, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xcc, 0xe0, 0x65, 0xb3, 0xaa, 0xf1, 0xd8, 0x4b, 0x9c, 0x8d, 0x16, 0x09,
            0xd9, 0x38, 0xb5, 0xec, 0x59, 0xe3, 0xca, 0x76, 0xef, 0xf9, 0xab, 0x45, 0xad, 0x4a,
            0x77, 0xda, 0xae, 0xce, 0xf6, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        values.resize(Header::SIZE, 0);

        let mut values = Cursor::new(values);
        let headers = Header::deserialize(&mut values).unwrap();

        assert_eq!(Signature::Head, headers.signature);
        assert_eq!(2148003692, headers.checksum);
        assert_eq!(4, headers.seq_number);
        assert_eq!(
            uuid!("b365e0cc-f1aa-4bd8-9c8d-1609d938b5ec"),
            headers.file_write_guid
        );
        assert_eq!(
            uuid!("76cae359-f9ef-45ab-ad4a-77daaecef617"),
            headers.data_write_guid
        );

        // 0 means there are no log entries
        assert_eq!(
            uuid!("00000000-0000-0000-0000-000000000000"),
            headers.log_guid
        );
        assert_eq!(0, headers.log_version);
        assert_eq!(1, headers.version);

        // 1 mb in binary equals 1048576 (2^20)
        assert_eq!(1048576, headers.log_length);
        assert_eq!(1048576, headers.log_offset);
    }
}
