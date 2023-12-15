use crate::bat::BatEntry;
use crate::vhdx_header::Header;
use crate::DeSerialise;
use crate::{
    error::{Result, VhdxError},
    log::{Log, LogEntry},
    meta_data::MetaData,
    parse_utils::t_sign_u32,
    vhdx_header::{KnowRegion, VhdxHeader},
    Crc32, Signature,
};
use nom::combinator::peek;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug)]
pub struct Vhdx {
    pub(crate) file: File,
    pub header: VhdxHeader,
    pub log: Log,
    pub meta_data: MetaData,
    pub bat_table: Vec<BatEntry>,
}

impl Vhdx {
    pub(crate) const KB: u64 = 1024;
    pub(crate) const MB: u64 = Vhdx::KB * Vhdx::KB;

    pub fn new(path: &impl AsRef<Path>) -> Result<Self, VhdxError> {
        let mut reader = File::options().read(true).write(true).open(path)?;

        let header = VhdxHeader::deserialize(&mut reader)?;

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
            let log_entry = LogEntry::deserialize(&mut reader)?;
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

        let meta_data_info = &header
            .region_table_1
            .table_entries
            .get(&KnowRegion::MetaData)
            .ok_or(VhdxError::MissingKnownRegion("MetaData"))?;

        let bat_table_info = &header
            .region_table_1
            .table_entries
            .get(&KnowRegion::Bat)
            .ok_or(VhdxError::MissingKnownRegion("Bat"))?;

        // Read MetaData
        reader.seek(SeekFrom::Start(meta_data_info.file_offset))?;
        let meta_data = MetaData::deserialize(&mut reader).unwrap();

        // Read BAT Table
        reader.seek(SeekFrom::Start(bat_table_info.file_offset))?;
        let bat_table: Vec<BatEntry> = (0..meta_data.total_bat_entries_fixed_dynamic)
            .map(|_| BatEntry::deserialize(&mut reader).unwrap())
            .collect();

        let v = &log_entries[0];
        dbg!(v.crc32());
        let v = &log_entries[1];
        dbg!(v.crc32());

        let mut vhdx = Vhdx {
            file: reader,
            header,
            log: Log { log_entries },
            meta_data,
            bat_table,
        };

        vhdx.try_log_replay()?;

        Ok(vhdx)
    }

    fn try_log_replay(&mut self) -> Result<(), VhdxError> {
        if Uuid::is_nil(&self.header().log_guid) {
            return Ok(());
        }

        let active_log = self.try_get_log();

        Ok(())
    }

    fn header(&self) -> &Header {
        &self.header.header_1
    }

    fn try_get_log(&mut self) -> Result<(), VhdxError> {
        let header = self.header();
        let log_guid = header.log_guid;
        let log_offset = header.log_offset;
        let log_length = header.log_length;

        let mut current_tail = log_offset;
        let mut old_tail = log_offset;

        loop {
            let mut head_value = current_tail;
            self.file.seek(SeekFrom::Start(current_tail))?;
            let mut sequence = LogSequence {
                sequence_number: 0,
                entries: Vec::new(),
            };

            loop {
                let entry_offset = self.file.stream_position()?;
                let signature = self.peek_signature()?;
                match signature {
                    Signature::Loge => {
                        match LogEntry::deserialize(&mut self.file) {
                            Ok(entry) => {
                                // If we read too far we break
                                if entry.header.log_guid != log_guid {
                                    break;
                                } else if sequence.is_empty() {
                                    sequence.sequence_number = entry.header.seq_number;
                                    sequence.entries.push(entry);
                                    head_value = entry_offset;
                                } else if entry.header.seq_number
                                    == sequence
                                        .entries
                                        .last()
                                        .expect("Should never happen")
                                        .header
                                        .seq_number
                                        + 1
                                {
                                    sequence.entries.push(entry);
                                    head_value = entry_offset;
                                }
                            }
                            Err(e) => {
                                VhdxError::ParseError("Could not parse log entry".to_owned());
                            }
                        }
                    }
                    // Otherwise that was last entry we break
                    _ => break,
                }
            }
            break;
        }

        Ok(())
    }

    fn peek_signature(&mut self) -> Result<Signature, VhdxError> {
        let mut buffer = [0; 4];
        self.file.read_exact(&mut buffer)?;
        let mut peeker = peek(t_sign_u32);
        let (_, signature) = peeker(&buffer)?;
        self.file.seek(SeekFrom::Current(-4))?;
        Ok(signature)
    }
}

struct LogSequence {
    sequence_number: u64,
    entries: Vec<LogEntry>,
}
impl LogSequence {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn is_valid() -> bool {
        false
    }
}
