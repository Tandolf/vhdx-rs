use crate::error::{Result, VhdxError};
use nom::combinator::peek;

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
    region_table::KnowRegion,
};

#[derive(Debug)]
pub struct Vhdx {
    pub header: Header,
    pub log: Log,
    pub meta_data: MetaData,
    pub bat_table: Vec<BatEntry>,
}

impl Vhdx {
    pub fn new<T>(reader: &mut T) -> Result<Self, VhdxError>
    where
        T: Read + Seek,
    {
        let header = Header::deserialize(reader)?;

        // Hardcoded to read the first header
        let h = &header.header_1;
        let h2 = &header.header_2;

        // Calculating crc-32c for headers
        let _calc_crc = h.crc32();
        let _calc_crc2 = h2.crc32();

        let _ = reader.seek(SeekFrom::Start(h.log_offset));
        let mut log_entries = Vec::new();
        let log_end = h.log_offset + h.log_length as u64;

        while reader.stream_position()? != log_end {
            let log_entry = LogEntry::deserialize(reader)?;
            log_entries.push(log_entry);

            // peeking to see if there are any more logs
            let mut buffer = [0; 4];
            reader.read_exact(&mut buffer)?;
            let mut peeker = peek(t_sign_u32);
            let (_, signature) = peeker(&buffer)?;
            match signature {
                //if there are logs we back up and let the loop run again
                Signature::Loge => {
                    reader.seek(SeekFrom::Current(-4))?;
                }
                // Otherwise that was last entry we break
                _ => break,
            }
        }

        let meta_data_info = &header.rt_1.table_entries[&KnowRegion::MetaData];
        let bat_table_info = &header.rt_1.table_entries[&KnowRegion::Bat];

        reader.seek(SeekFrom::Start(meta_data_info.file_offset))?;
        let meta_data = MetaData::deserialize(reader).unwrap();

        reader.seek(SeekFrom::Start(bat_table_info.file_offset))?;
        let bat_table: Vec<BatEntry> = (0..meta_data.total_bat_entries_fixed_dynamic)
            .map(|_| BatEntry::deserialize(reader).unwrap())
            .collect();

        Ok(Vhdx {
            header,
            log: Log { log_entries },
            meta_data,
            bat_table,
        })
    }
}
