use bitvec::view::BitView;
use bitvec::{field::BitField, prelude::Lsb0};

use crate::{error::VhdxError, meta_data::SectorSize, DeSerialise};

#[allow(dead_code)]
pub struct BatTable {
    entries: Vec<BatEntry>,
}

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

pub(crate) fn calc_chunk_ratio(sector_size: SectorSize, block_size: usize) -> u64 {
    ((2_u64.pow(23)) * sector_size as u64) / block_size as u64
}

pub(crate) fn calc_payload_blocks_count(virtual_disk_size: usize, block_size: usize) -> u64 {
    (virtual_disk_size as f64 / block_size as f64).ceil() as u64
}

pub(crate) fn calc_sector_bitmap_blocks_count(
    payload_blocks_count: usize,
    chunk_ratio: usize,
) -> u64 {
    (payload_blocks_count as f64 / chunk_ratio as f64).ceil() as u64
}

pub(crate) fn calc_total_bat_entries_fixed_dynamic(
    payload_blocks_count: u64,
    chunk_ratio: u64,
) -> u64 {
    ((payload_blocks_count - 1) as f64 / chunk_ratio as f64).floor() as u64 + payload_blocks_count
}

pub(crate) fn calc_total_bat_entries_differencing(
    sector_bitmap_blocks_count: u64,
    chunk_ratio: u64,
) -> u64 {
    sector_bitmap_blocks_count * (chunk_ratio + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn ceil_correctly() {
        assert_eq!(4, calc_payload_blocks_count(10, 3))
    }
}
