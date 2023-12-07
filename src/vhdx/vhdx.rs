use nom::combinator::peek;
use uuid::Uuid;

use crate::{
    vhdx::{parse_utils::t_sign_u32, signatures::Signature},
    Crc32, DeSerialise,
};

use std::io::{Read, Seek, SeekFrom};

use super::{
    bat_entry::BatEntry,
    header::Header,
    log::{log::Log, log_entry::LogEntry},
    metadata::MetaData,
};

#[derive(Debug)]
pub struct Vhdx {
    pub header: Header,
    pub log: Log,
    pub meta_data: MetaData,
    pub bat_table: Vec<BatEntry>,
}

impl Vhdx {
    pub fn new<T>(reader: &mut T) -> Self
    where
        T: Read + Seek,
    {
        let header = Header::deserialize(reader).unwrap();

        // Hardcoded to read the first header
        let h = &header.header_1;
        let h2 = &header.header_2;

        // Calculating crc-32c for headers
        let _calc_crc = h.crc32();
        let _calc_crc2 = h2.crc32();

        let _ = reader.seek(SeekFrom::Start(h.log_offset));
        let mut log_entries = Vec::new();
        let log_end = h.log_offset + h.log_length as u64;
        while reader.stream_position().unwrap() != log_end {
            let log_entry = LogEntry::deserialize(reader).unwrap();
            log_entries.push(log_entry);

            // peeking to see if there are any more logs
            let mut buffer = [0; 4];
            reader.read_exact(&mut buffer).unwrap();
            let mut peeker = peek(t_sign_u32);
            let (_, signature) = peeker(&buffer).unwrap();
            match signature {
                //if there are logs we back up and let the loop run again
                Signature::Loge => {
                    reader.seek(SeekFrom::Current(-4)).unwrap();
                }
                // Otherwise that was last entry we break
                _ => break,
            }
        }

        let meta_data_info = header
            .rt_1
            .table_entries
            .iter()
            .find(|v| v.guid == Uuid::parse_str("8B7CA20647904B9AB8FE575F050F886E").unwrap())
            .unwrap();

        let bat_table_info = header
            .rt_1
            .table_entries
            .iter()
            .find(|v| v.guid == Uuid::parse_str("2DC27766F62342009D64115E9BFD4A08").unwrap())
            .unwrap();

        reader
            .seek(SeekFrom::Start(meta_data_info.file_offset))
            .unwrap();

        let meta_data = MetaData::deserialize(reader).unwrap();

        reader
            .seek(SeekFrom::Start(bat_table_info.file_offset))
            .unwrap();

        let bat_table: Vec<BatEntry> = (0..meta_data.total_bat_entries_fixed_dynamic)
            .map(|_| BatEntry::deserialize(reader).unwrap())
            .collect();

        Vhdx {
            header,
            log: Log { log_entries },
            meta_data,
            bat_table,
        }
    }
}
