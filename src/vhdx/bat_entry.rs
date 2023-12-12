use crate::{error::VhdxError, DeSerialise};
use bitvec::prelude::*;

#[allow(dead_code)]
#[derive(Debug)]
pub struct BatEntry {
    state: BatEntryState,
    file_offset_mb: usize,
}
impl BatEntry {
    fn new(state: BatEntryState, file_offset_mb: usize) -> BatEntry {
        Self {
            state,
            file_offset_mb,
        }
    }
}

pub fn t_entry(input: &[u8]) -> (BatEntryState, usize) {
    let bits = input.view_bits::<Lsb0>();
    let (head, rest) = bits.split_at(3);
    let state = match head.load::<u8>() {
        1 => BatEntryState::PayLoadBlockUndefined,
        2 => BatEntryState::PayLoadBlockZero,
        3 => BatEntryState::PayLoadBlockUnmapped,
        6 => BatEntryState::PayLoadBlockFullyPresent,
        7 => BatEntryState::PayLoadBlockPartiallyPresent,
        _ => BatEntryState::Unknown,
    };

    let (_, rest) = rest.split_at(17);
    let (head, _) = rest.split_at(44);
    (state, head.load::<usize>())
}

impl<T> DeSerialise<T> for BatEntry {
    type Item = BatEntry;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer)?;
        let (state, file_offset) = t_entry(&buffer);
        Ok(BatEntry::new(state, file_offset))
    }
}

#[derive(Debug)]
pub enum BatEntryState {
    PayLoadBlockUndefined = 1,
    PayLoadBlockZero = 2,
    PayLoadBlockUnmapped = 3,
    PayLoadBlockFullyPresent = 6,
    PayLoadBlockPartiallyPresent = 7,
    Unknown,
}
