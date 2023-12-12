use nom::{bits::complete::take, combinator::map, sequence::tuple, IResult};

use crate::error::VhdxParseError;

pub type BitInput<'a> = (&'a [u8], usize);

pub fn t_3_flags_u32(
    input: BitInput,
) -> IResult<BitInput, (bool, bool, bool), VhdxParseError<(&[u8], usize)>> {
    map(
        tuple((take(5usize), t_flag_u8, t_flag_u8, t_flag_u8)),
        |(_, a, b, c): (u8, bool, bool, bool)| (c, b, a),
    )(input)
}

pub fn t_2_flags_u32(
    input: BitInput,
) -> IResult<BitInput, (bool, bool), VhdxParseError<(&[u8], usize)>> {
    map(
        tuple((take(4usize), t_flag_u8, t_flag_u8)),
        |(_, b, a): (u8, bool, bool)| (a, b),
    )(input)
}

pub fn t_flag_u8(i: BitInput) -> IResult<BitInput, bool, VhdxParseError<(&[u8], usize)>> {
    map(take(1usize), |bits: u8| bits > 0)(i)
}

pub fn t_reserved(i: BitInput, length: usize) -> IResult<BitInput, usize> {
    take(length)(i)
}

pub fn t_file_offset(i: BitInput) -> IResult<BitInput, usize> {
    take(44usize)(i)
}
