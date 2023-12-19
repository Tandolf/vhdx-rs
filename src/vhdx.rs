#![allow(dead_code)]

use crate::bat::BatEntry;
use crate::log::LogSequence;
use crate::vhdx_header::Header;
use crate::{
    error::{Result, VhdxError},
    log::{Log, LogEntry},
    meta_data::MetaData,
    parse_utils::t_sign_u32,
    vhdx_header::{KnowRegion, VhdxHeader},
    Signature,
};
use crate::{meta_data, Crc32, DeSerialise, Validation};
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
        let (header_no, h) = get_current_header(&header.header_1, &header.header_2)?;
        h.validate()?;

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

        let r = match header_no {
            1 => &header.region_table_1,
            2 => &header.region_table_2,
            _ => panic!("Impossiburru"),
        };

        r.validate()?;

        let meta_data_info = &r
            .table_entries
            .get(&KnowRegion::MetaData)
            .ok_or(VhdxError::MissingKnownRegion("MetaData"))?;

        let bat_table_info = &r
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

        let log = Log::new(log_entries);
        let vhdx = Vhdx {
            file: reader,
            header,
            log,
            meta_data,
            bat_table,
        };

        // vhdx.try_log_replay()?;

        Ok(vhdx)
    }

    fn try_log_replay(&mut self) -> Result<(), VhdxError> {
        if Uuid::is_nil(&self.header().log_guid) {
            return Ok(());
        }

        let _active_log = Vhdx::try_get_log_sequence(&self.log.log_entries);

        Ok(())
    }

    fn header(&self) -> &Header {
        &self.header.header_1
    }

    pub(crate) fn try_get_log_sequence(
        log_entries: &Vec<LogEntry>,
    ) -> Result<LogSequence, VhdxError> {
        let mut active = LogSequence {
            sequence_number: 0,
            entries: Vec::new(),
            head_value: 0,
            tail_value: 0,
        };

        let mut read_items = 0;
        let mut current_head_offset = 0;
        let mut seq_tail_offset = 0;

        loop {
            let mut candidate = LogSequence {
                sequence_number: 0,
                entries: Vec::new(),
                head_value: 0,
                tail_value: 0,
            };

            candidate.tail_value = seq_tail_offset;

            for (i, entry) in log_entries[read_items..].iter().enumerate() {
                if entry.validate().is_err() {
                    read_items = i;
                    break;
                }

                if candidate.is_empty() {
                    candidate.sequence_number = entry.header.seq_number;
                    candidate.entries.push(entry.clone());
                    candidate.head_value = current_head_offset;
                } else if entry.header.seq_number == candidate.sequence_number + 1 {
                    candidate.entries.push(entry.clone());
                    candidate.head_value = current_head_offset;
                }

                seq_tail_offset += entry.header.entry_length as u64;
                current_head_offset += entry.header.entry_length as u64;
                read_items += 1;
            }

            // Step 4
            if !candidate.is_valid() {
                // candidate is empty or not valid break and try the next entries
                break;
            }

            // Step 5
            if candidate.sequence_number > active.sequence_number {
                active = candidate;
            }

            if read_items == log_entries.len() {
                break;
            }
        }

        Ok(active)
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

#[allow(clippy::if_same_then_else)]
fn get_current_header<'a>(h1: &'a Header, h2: &'a Header) -> Result<(u32, &'a Header), VhdxError> {
    let r1 = check_sign_and_crc(h1);
    let r2 = check_sign_and_crc(h2);

    let current = if r1.is_err() && r2.is_err() {
        // TODO: Better error handling
        return Err(VhdxError::VhdxHeaderError);
    } else if r1.is_err() && r2.is_ok() {
        (2, h2)
    } else if r1.is_ok() && r2.is_err() {
        (1, h1)
    } else if h1.sequence_number() > h2.sequence_number() {
        (1, h1)
    } else {
        (2, h2)
    };
    Ok(current)
}

fn check_sign_and_crc(header: &Header) -> Result<(), VhdxError> {
    if header.signature != Signature::Head {
        return Err(VhdxError::SignatureError(
            Signature::Head,
            header.signature.clone(),
        ));
    }

    let crc = header.crc32();
    if header.checksum != crc {
        return Err(VhdxError::Crc32Error(header.checksum, crc));
    }

    Ok(())
}
