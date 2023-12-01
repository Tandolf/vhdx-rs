#![allow(dead_code)]
use std::io::{Read, Seek};

use nom::{
    bytes::complete::take,
    combinator::{map, peek},
    number::complete::{le_u32, le_u64},
    sequence::tuple,
    IResult,
};

use crate::{
    vhdx::{parse_utils::t_sign_u32, signatures::Signature},
    DeSerialise,
};

use super::entry_header::Header;

pub const SECTOR_SIZE: usize = 4096;
pub const DESC_SIZE: usize = 32;
pub const LOG_HEADER_SIZE: usize = 64;

#[derive(Debug)]
pub struct LogEntry {
    pub header: Header,
    descriptors: Vec<Descriptor>,
}

impl LogEntry {
    fn new(header: Header, descriptors: Vec<Descriptor>) -> Self {
        Self {
            header,
            descriptors,
        }
    }
}

impl<T> DeSerialise<T> for LogEntry {
    type Item = LogEntry;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        let start_pos = reader.stream_position()?;
        let header = Header::deserialize(reader)?;
        let mut descriptors = Vec::with_capacity(header.descript_count);
        if header.descript_count != 0 {
            for _ in 0..header.descript_count {
                let desc = Descriptor::deserialize(reader)?;
                descriptors.push(desc);
            }
        }
        let current_pos = reader.stream_position()?;
        let offset = SECTOR_SIZE as u64 - (current_pos - start_pos);
        reader.seek(std::io::SeekFrom::Current(offset as i64))?;

        for desc in descriptors.iter_mut().filter(|v| {
            matches!(
                v,
                Descriptor::Data {
                    signature: _,
                    trailing_bytes: _,
                    leading_bytes: _,
                    file_offset: _,
                    seq_number: _,
                    data_sector: _,
                }
            )
        }) {
            let d_sector = DataSector::deserialize(reader)?;
            if let Descriptor::Data {
                signature: _,
                trailing_bytes: _,
                leading_bytes: _,
                file_offset: _,
                seq_number: _,
                data_sector,
            } = desc
            {
                *data_sector = Some(d_sector);
            }
        }

        let log_entry = LogEntry::new(header, descriptors);
        Ok(log_entry)
    }
}

#[derive(Debug)]
enum Descriptor {
    Zero {
        // ZeroSignature (4 bytes): MUST be 0x6F72657A ("zero" as ASCII).
        signature: Signature,

        // ZeroLength (8 bytes): Specifies the length of the section to zero. The value MUST be a
        // multiple of 4 KB.
        zero_length: u64,

        // FileOffset (8 bytes): Specifies the file offset to which zeros MUST be written. The
        // value MUST be a multiple of 4 KB.
        file_offset: u64,

        // SequenceNumber (8 bytes): MUST match the SequenceNumber field of the log entry's header.
        seq_number: u64,
    },
    Data {
        // DataSignature (4 bytes): MUST be 0x63736564 ("desc" as ASCII).
        signature: Signature,

        // TrailingBytes (4 bytes): Contains the four trailing bytes that were removed from the
        // update when it was converted to a data sector. These trailing bytes MUST be restored
        // before the data sector is written to its final location on disk.
        trailing_bytes: Vec<u8>,

        // LeadingBytes (8 bytes): Contains the first eight bytes that were removed from the update
        // when it was converted to a data sector. These leading bytes MUST be restored before the
        // data sector is written to its final location on disk.
        leading_bytes: Vec<u8>,

        // FileOffset (8 bytes): Specifies the file offset to which the data described by this
        // descriptor MUST be written. The value MUST be a multiple of 4 KB.
        file_offset: u64,

        // SequenceNumber (8 bytes): MUST match the SequenceNumber field of the entry's header.
        seq_number: u64,

        // Data sector belonging to this descriptor
        data_sector: Option<DataSector>,
    },
}

impl<T> DeSerialise<T> for Descriptor {
    type Item = Descriptor;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let mut peeker = peek(t_sign_u32);
        let (buffer, signature) = peeker(&buffer).unwrap();
        let (_, descriptor) = match signature {
            Signature::Desc => parse_desc(buffer).unwrap(),
            Signature::Zero => parse_zero(buffer).unwrap(),
            _ => panic!("Unknown file format, expected Data/Zero descriptor"),
        };
        Ok(descriptor)
    }
}

fn parse_zero(buffer: &[u8]) -> IResult<&[u8], Descriptor> {
    map(
        tuple((t_sign_u32, le_u32, le_u64, le_u64, le_u64)),
        |(signature, _, zero_length, file_offset, seq_number)| Descriptor::Zero {
            signature,
            zero_length,
            file_offset,
            seq_number,
        },
    )(buffer)
}

fn parse_desc(buffer: &[u8]) -> IResult<&[u8], Descriptor> {
    map(
        tuple((t_sign_u32, take(4usize), take(8usize), le_u64, le_u64)),
        |(signature, trailing_bytes, leading_bytes, file_offset, seq_number)| Descriptor::Data {
            signature,
            trailing_bytes: trailing_bytes.to_vec(),
            leading_bytes: leading_bytes.to_vec(),
            file_offset,
            seq_number,
            data_sector: None,
        },
    )(buffer)
}

struct DataSector {
    // DataSignature (4 bytes): MUST be 0x61746164 ("data" as ASCII).
    signature: Signature,

    // SequenceHigh (4 bytes): MUST
    // contain the four most significant bytes of the SequenceNumber field of the associated entry.
    seq_high: Vec<u8>,

    // Data (4084 bytes): Contains the raw data associated with the update, bytes 8 through 4,091,
    // inclusive. Bytes 0 through 7 and 4,092 through 4,096 are stored in the data descriptor, in
    // the LeadingBytes and TrailingBytes fields, respectively.
    data: Vec<u8>,
    //
    // SequenceLow (4 bytes): MUST contain
    // the four least significant bytes of the SequenceNumber field of the associated entry.
    seq_low: Vec<u8>,
}
impl DataSector {
    fn new(signature: Signature, seq_high: &[u8], data: &[u8], seq_low: &[u8]) -> Self {
        Self {
            signature,
            seq_high: seq_high.to_vec(),
            data: data.to_vec(),
            seq_low: seq_low.to_vec(),
        }
    }
}

impl<T> DeSerialise<T> for DataSector {
    type Item = DataSector;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 4096];
        reader.read_exact(&mut buffer)?;
        let (_, data_sector) = map(
            tuple((t_sign_u32, take(4usize), take(4084usize), take(4usize))),
            |(signature, sequence_high, data, sequence_low)| {
                DataSector::new(signature, sequence_high, data, sequence_low)
            },
        )(&buffer)
        .unwrap();

        Ok(data_sector)
    }
}

impl std::fmt::Debug for DataSector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataSector")
            .field("signature", &self.signature)
            .finish()
    }
}
