use std::io::{Read, Seek};

use crate::DeSerialise;

use super::log_entry::LogEntry;

#[derive(Debug)]
pub struct Log {
    log_entries: Vec<LogEntry>,
}

impl<T> DeSerialise<T> for Log {
    type Item = Log;

    fn deserialize(_buffer: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        Ok(Self {
            log_entries: Vec::new(),
        })
    }
}
