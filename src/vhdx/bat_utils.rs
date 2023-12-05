use super::metadata::SectorSize;

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
