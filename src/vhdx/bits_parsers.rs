use nom::{bits::complete::take, combinator::map, sequence::tuple, IResult};

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
