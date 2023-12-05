use nom::{bits::complete::take, combinator::map, sequence::tuple, IResult};

use super::bat_entry::BatEntryState;

pub type BitInput<'a> = (&'a [u8], usize);

pub fn t_3_flags_u32(input: BitInput) -> IResult<BitInput, (bool, bool, bool)> {
    map(
        tuple((take(5usize), t_flag_u8, t_flag_u8, t_flag_u8)),
        |(_, a, b, c): (u8, bool, bool, bool)| (c, b, a),
    )(input)
}

pub fn t_2_flags_u32(input: BitInput) -> IResult<BitInput, (bool, bool)> {
    map(
        tuple((take(4usize), t_flag_u8, t_flag_u8)),
        |(_, b, a): (u8, bool, bool)| (a, b),
    )(input)
}

pub fn t_flag_u8(i: BitInput) -> IResult<BitInput, bool> {
    map(take(1usize), |bits: u8| bits > 0)(i)
}

pub fn t_state(i: BitInput) -> IResult<BitInput, BatEntryState> {
    map(take(8u8), |bits: u8| match bits {
        1 => BatEntryState::PayLoadBlockUndefined,
        2 => BatEntryState::PayLoadBlockZero,
        3 => BatEntryState::PayLoadBlockUnmapped,
        6 => BatEntryState::PayLoadBlockFullyPresent,
        7 => BatEntryState::PayLoadBlockPartiallyPresent,
        _ => BatEntryState::Unknown,
    })(i)
}

pub fn t_reserved(i: BitInput, length: usize) -> IResult<BitInput, usize> {
    take(length)(i)
}

pub fn t_file_offset(i: BitInput) -> IResult<BitInput, usize> {
    take(44usize)(i)
}
