use nom::Finish;
use std::io::{Read, Seek};
use uuid::Uuid;

use nom::{
    bytes::complete::take,
    combinator::{map, peek},
    number::complete::{le_u32, le_u64},
    sequence::tuple,
};

use crate::{
    error::{VhdxError, VhdxParseError},
    parse_utils::{t_guid, t_sign_u32, t_u32, t_u64},
    DeSerialise, Signature,
};

#[derive(Debug)]
pub struct Log {
    pub log_entries: Vec<LogEntry>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct LogEntry {
    pub header: LogHeader,
    descriptors: Vec<Descriptor>,
}

impl LogEntry {
    const SECTOR_SIZE: usize = 4096;

    fn new(header: LogHeader, descriptors: Vec<Descriptor>) -> Self {
        Self {
            header,
            descriptors,
        }
    }
}

impl<T> DeSerialise<T> for LogEntry {
    type Item = LogEntry;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let start_pos = reader.stream_position()?;

        let header = LogHeader::deserialize(reader)?;
        let mut descriptors = Vec::with_capacity(header.descript_count as usize);
        if header.descript_count != 0 {
            for _ in 0..header.descript_count {
                let desc = Descriptor::deserialize(reader)?;
                descriptors.push(desc);
            }
        }
        let current_pos = reader.stream_position()?;
        let offset = LogEntry::SECTOR_SIZE as u64 - (current_pos - start_pos);
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
pub struct LogHeader {
    // Signature (4 bytes): MUST be 0x65676F6C ("loge" as UTF8).
    pub signature: Signature,

    // Checksum (4 bytes): A CRC-32C hash computed over the entire entry specified by the
    // EntryLength field, with the Checksum field taking the value of zero during the computation
    // of the checksum value.
    pub checksum: u32,

    // EntryLength (4 bytes): Specifies the total length of the entry in bytes. The value MUST be a
    // multiple of 4 KB.
    pub entry_length: u32,

    // Tail (4 bytes): The offset, in bytes, from the beginning of the log to the beginning log
    // entry of a sequence ending with this entry. The value MUST be a multiple of 4 KB. A tail
    // entry could point to itself, as would be the case when a log is initialized.
    pub tail: u32,

    // SequenceNumber (8 bytes): A 64-bit integer incremented between each log entry. It must be
    // larger than zero.
    pub seq_number: u64,

    // DescriptorCount (4 bytes): Specifies the number of descriptors that are contained in this
    // log entry. The value can be zero.
    pub descript_count: u32,

    // LogGuid (16 bytes): Contains the LogGuid value in the file header that was present when this
    // log entry was written. When replaying, if this LogGuid does not match the LogGuid field in
    // the file header, this entry MUST NOT be considered valid.
    pub log_guid: Uuid,

    // FlushedFileOffset (8 bytes): Stores the VHDX file size in bytes that MUST be at least as
    // large as the size of the VHDX file at the time the log entry was written. The file size
    // specified in the log entry must have been stable on the host disk such that, even in the
    // case of a system power failure, a noncorrupted VHDX file will be at least as large as the
    // size specified by the log entry. Before shrinking a file while the log is in use, an
    // implementation MUST write the target size to a log entry and flush the entry so that the
    // update is stable on the log that is on the host-disk storage media; this will ensure that
    // the VHDX file is not treated as truncated during log replay. An implementation SHOULD write
    // the largest possible value that satisfies these requirements. The value MUST be a multiple
    // of 1 MB. LastFileOffset (8 bytes): Stores a file size in bytes that all allocated file
    // structures fit into, at the time the log entry was written. An implementation SHOULD write
    // the smallest possible value that satisfies these requirements. The value MUST be a multiple
    // of 1 MB.
    pub flushed_file_offset: u64,

    // LastFileOffset (8 bytes): Stores a file size in bytes that all allocated file structures fit
    // into, at the time the log entry was written. An implementation SHOULD write the smallest
    // possible value that satisfies these requirements. The value MUST be a multiple of 1 MB.
    pub last_file_offset: u64,
}
impl LogHeader {
    pub const SIGN: &'static [u8] = &[0x6C, 0x6F, 0x67, 0x65];
    fn new(
        signature: Signature,
        checksum: u32,
        entry_length: u32,
        tail: u32,
        seq_number: u64,
        descript_count: u32,
        log_guid: Uuid,
        flushed_file_offset: u64,
        last_file_offset: u64,
    ) -> Self {
        Self {
            signature,
            checksum,
            entry_length,
            tail,
            seq_number,
            descript_count,
            log_guid,
            flushed_file_offset,
            last_file_offset,
        }
    }
}

impl<T> DeSerialise<T> for LogHeader {
    type Item = LogHeader;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 64];
        reader.read_exact(&mut buffer)?;

        let (_, header) = map(
            tuple((
                t_sign_u32, t_u32, t_u32, t_u32, t_u64, t_u32, t_u32, t_guid, t_u64, t_u64,
            )),
            |(
                signature,
                checksum,
                entry_length,
                tail,
                seq_number,
                descript_count,
                _,
                log_guid,
                flushed_file_offset,
                last_file_offset,
            )| {
                LogHeader::new(
                    signature,
                    checksum,
                    entry_length,
                    tail,
                    seq_number,
                    descript_count,
                    log_guid,
                    flushed_file_offset,
                    last_file_offset,
                )
            },
        )(&buffer)
        .finish()?;
        Ok(header)
    }
}

#[allow(dead_code)]
pub(crate) enum Descriptor {
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

impl Descriptor {
    pub const SIGN: &'static [u8] = &[0x64, 0x65, 0x73, 0x63];
    pub const ZERO_SIGN: &'static [u8] = &[0x6F, 0x72, 0x65, 0x7A];
    pub const DATA_SIGN: &'static [u8] = &[0x64, 0x61, 0x74, 0x61];
}

impl<T> DeSerialise<T> for Descriptor {
    type Item = Descriptor;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer)?;
        let mut peeker = peek(t_sign_u32);
        let (buffer, signature) = peeker(&buffer)?;
        let (_, descriptor) = match signature {
            Signature::Desc => parse_desc(buffer)?,
            Signature::Zero => parse_zero(buffer)?,
            _ => Err(VhdxParseError::UnknownSignature)?,
        };

        Ok(descriptor)
    }
}

fn parse_zero(buffer: &[u8]) -> Result<(&[u8], Descriptor), VhdxParseError<&[u8]>> {
    map(
        tuple((t_sign_u32, le_u32, le_u64, le_u64, le_u64)),
        |(signature, _, zero_length, file_offset, seq_number)| Descriptor::Zero {
            signature,
            zero_length,
            file_offset,
            seq_number,
        },
    )(buffer)
    .finish()
}

fn parse_desc(buffer: &[u8]) -> Result<(&[u8], Descriptor), VhdxParseError<&[u8]>> {
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
    .finish()
}

impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Descriptor::Zero {
                signature,
                zero_length: _,
                file_offset,
                seq_number,
            } => f
                .debug_struct("Descriptor")
                .field("signature", signature)
                .field("file_offset", file_offset)
                .field("seq_number", seq_number)
                .finish(),
            Descriptor::Data {
                signature,
                trailing_bytes: _,
                leading_bytes: _,
                file_offset,
                seq_number,
                data_sector: _,
            } => f
                .debug_struct("Data")
                .field("signature", signature)
                .field("file_offset", file_offset)
                .field("seq_number", seq_number)
                .finish(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct DataSector {
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

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
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
        )(&buffer)?;

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

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::*;

    #[test]
    fn should_deserialize_entry_header() {
        // FTI
        let bytes = vec![
            0x6c, 0x6f, 0x67, 0x65, 0xbc, 0x30, 0xfd, 0xe9, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x8d, 0xec, 0x92, 0x41, 0x0f, 0x51, 0x28, 0x36, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x46, 0xdd, 0xb4, 0x1d, 0x13, 0x4d, 0xad, 0x70,
            0xdc, 0x30, 0x93, 0xaf, 0xd5, 0xc2, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut bytes = Cursor::new(bytes);

        // 2 header sections
        let entry_header = LogHeader::deserialize(&mut bytes).unwrap();

        assert_eq!(Signature::Loge, entry_header.signature);
    }
}
