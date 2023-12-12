use std::io::{Read, Seek};

use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{le_u128, le_u32, le_u64},
    sequence::tuple,
    Finish, IResult,
};
use uuid::{Builder, Uuid};

use crate::{
    error::{VhdxError, VhdxParseError},
    DeSerialise,
};

#[derive(Debug)]
pub struct Header {
    // Signature (4 bytes): MUST be 0x65676F6C ("loge" as UTF8).
    pub signature: String,

    // Checksum (4 bytes): A CRC-32C hash computed over the entire entry specified by the
    // EntryLength field, with the Checksum field taking the value of zero during the computation
    // of the checksum value.
    pub checksum: u32,

    // EntryLength (4 bytes): Specifies the total length of the entry in bytes. The value MUST be a
    // multiple of 4 KB.
    pub entry_length: usize,

    // Tail (4 bytes): The offset, in bytes, from the beginning of the log to the beginning log
    // entry of a sequence ending with this entry. The value MUST be a multiple of 4 KB. A tail
    // entry could point to itself, as would be the case when a log is initialized.
    pub tail: usize,

    // SequenceNumber (8 bytes): A 64-bit integer incremented between each log entry. It must be
    // larger than zero.
    pub seq_number: usize,

    // DescriptorCount (4 bytes): Specifies the number of descriptors that are contained in this
    // log entry. The value can be zero.
    pub descript_count: usize,

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
    pub flushed_file_offset: usize,

    // LastFileOffset (8 bytes): Stores a file size in bytes that all allocated file structures fit
    // into, at the time the log entry was written. An implementation SHOULD write the smallest
    // possible value that satisfies these requirements. The value MUST be a multiple of 1 MB.
    pub last_file_offset: usize,
}
impl Header {
    fn new(
        signature: String,
        checksum: u32,
        entry_length: usize,
        tail: usize,
        seq_number: usize,
        descript_count: usize,
        log_guid: Uuid,
        flushed_file_offset: usize,
        last_file_offset: usize,
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

fn t_signature(buffer: &[u8]) -> IResult<&[u8], String> {
    map(take(4usize), |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec()).unwrap()
    })(buffer)
}

fn t_checksum(buffer: &[u8]) -> IResult<&[u8], u32> {
    le_u32(buffer)
}

fn t_4bytes_usize(buffer: &[u8]) -> IResult<&[u8], usize> {
    map(le_u32, |v: u32| v as usize)(buffer)
}

fn t_8bytes_usize(buffer: &[u8]) -> IResult<&[u8], usize> {
    map(le_u64, |v: u64| v as usize)(buffer)
}

fn t_guid(buffer: &[u8]) -> IResult<&[u8], Uuid> {
    map(le_u128, |v: u128| Builder::from_u128_le(v).into_uuid())(buffer)
}

impl<T> DeSerialise<T> for Header {
    type Item = Header;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; 64];
        reader.read_exact(&mut buffer)?;

        let (_, header) = map(
            tuple((
                t_signature,
                t_checksum,
                t_4bytes_usize,
                t_4bytes_usize,
                t_8bytes_usize,
                t_4bytes_usize,
                t_4bytes_usize,
                t_guid,
                t_8bytes_usize,
                t_8bytes_usize,
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
                Header::new(
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
        .finish()
        .map_err(VhdxParseError::Nom)?;
        Ok(header)
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
        let entry_header = Header::deserialize(&mut bytes).unwrap();

        dbg!(&entry_header);

        assert_eq!("loge", entry_header.signature);
    }
}
