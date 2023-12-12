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

impl<T> DeSerialise<T> for BatEntry {
    type Item = BatEntry;

    fn deserialize(reader: &mut T) -> Result<Self::Item, VhdxError>
    where
        T: std::io::Read + std::io::Seek,
    {
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer)?;
        let bits = buffer.view_bits::<Lsb0>();
        let (head, rest) = bits.split_at(3);
        let head_value = head.load::<u8>();
        let state = BatEntryState::from_bits(head_value);
        let (_, rest) = rest.split_at(17);
        let (head, _) = rest.split_at(44);
        Ok(BatEntry::new(state, head.load::<usize>()))
    }
}

#[derive(Debug)]
pub enum BatEntryState {
    NotPresent = 0,
    Undefined = 1,
    Zero = 2,
    Unmapped = 3,
    FullyPresent = 6,
    PartiallyPresent = 7,
    Unknown,
}

impl BatEntryState {
    fn from_bits(value: u8) -> Self {
        match value {
            0 => BatEntryState::NotPresent,
            1 => BatEntryState::Undefined,
            2 => BatEntryState::Zero,
            3 => BatEntryState::Unmapped,
            6 => BatEntryState::FullyPresent,
            7 => BatEntryState::PartiallyPresent,
            _ => BatEntryState::Unknown,
        }
    }
}
