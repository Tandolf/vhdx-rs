#![allow(dead_code)]
use super::{
    parse_utils::{t_guid, t_sign_u32},
    signatures::Signature,
};
use crate::DeSerialise;
use nom::{
    combinator::map,
    number::complete::{le_u128, le_u16, le_u32, le_u64},
    sequence::tuple,
    Finish, IResult,
};
use std::io::{Read, Seek};
use uuid::{Builder, Uuid};

const HEADER_SIZE: usize = 65536;

// Since the header is used to locate the log, updates to the headers cannot be made through the
// log. To provide power failure consistency, there are two headers in every VHDX file. Each of the
// two headers is a 4-KB structure that is aligned to a 64-KB boundary.<1> One header is stored at
// offset 64 KB and the other at 128 KB. Only one header is considered current and in use at any
// point in time.
#[derive(Debug)]
pub struct Headers {
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
impl Headers {
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
    ) -> Headers {
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

fn t_checksum(buffer: &[u8]) -> IResult<&[u8], u32> {
    le_u32(buffer)
}

fn t_seq(buffer: &[u8]) -> IResult<&[u8], u64> {
    le_u64(buffer)
}

fn t_log_version(buffer: &[u8]) -> IResult<&[u8], u16> {
    le_u16(buffer)
}

fn t_version(buffer: &[u8]) -> IResult<&[u8], u16> {
    le_u16(buffer)
}

fn t_log_length(buffer: &[u8]) -> IResult<&[u8], u32> {
    le_u32(buffer)
}

fn t_log_offset(buffer: &[u8]) -> IResult<&[u8], u64> {
    le_u64(buffer)
}

fn parse_headers(buffer: &[u8]) -> IResult<&[u8], Headers> {
    map(
        tuple((
            t_sign_u32,
            t_checksum,
            t_seq,
            t_guid,
            t_guid,
            t_guid,
            t_log_version,
            t_version,
            t_log_length,
            t_log_offset,
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
            Headers::new(
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

impl<T> DeSerialise<T> for Headers {
    type Item = Headers;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; HEADER_SIZE];
        reader.read_exact(&mut buffer)?;
        let (_, headers) = parse_headers(&buffer).finish().unwrap();
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use uuid::uuid;

    use super::*;

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

        values.resize(HEADER_SIZE, 0);

        let mut values = Cursor::new(values);
        let headers = Headers::deserialize(&mut values).unwrap();

        assert_eq!(Signature::Head, headers.signature);
        assert_eq!(2148003692, headers.checksum);
        assert_eq!(4, headers.seq_number);
        assert_eq!(
            uuid!("cce065b3-aaf1-d84b-9c8d-1609d938b5ec"),
            headers.file_write_guid
        );
        assert_eq!(
            uuid!("59e3ca76-eff9-ab45-ad4a-77daaecef617"),
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
