use super::signatures::{
    Signature, DATA_SIGN, DESC_SIGN, FTI_SIGN, HEAD_SIGN, LOGE_SIGN, META_DATA_SIGN, RGT_SIGN,
    ZERO_SIGN,
};
use nom::{bits, bytes::complete::take, combinator::map, IResult};
use uuid::{Builder, Uuid};

pub type BitInput<'a> = (&'a [u8], usize);

pub fn t_sign_u64(buffer: &[u8]) -> IResult<&[u8], Signature> {
    map(take(8usize), |bytes: &[u8]| match bytes {
        FTI_SIGN => Signature::Vhdxfile,
        META_DATA_SIGN => Signature::MetaData,
        _ => Signature::Unknown,
    })(buffer)
}

pub fn t_sign_u32(buffer: &[u8]) -> IResult<&[u8], Signature> {
    map(take(4usize), |bytes: &[u8]| match bytes {
        HEAD_SIGN => Signature::Head,
        RGT_SIGN => Signature::Regi,
        DESC_SIGN => Signature::Desc,
        ZERO_SIGN => Signature::Zero,
        DATA_SIGN => Signature::Data,
        LOGE_SIGN => Signature::Loge,
        _ => Signature::Unknown,
    })(buffer)
}

pub fn t_guid(buffer: &[u8]) -> IResult<&[u8], Uuid> {
    map(take(16usize), |bytes: &[u8]| {
        Builder::from_slice_le(bytes).unwrap().into_uuid()
    })(buffer)
}

pub fn parse_bool(i: BitInput) -> IResult<BitInput, bool> {
    map(bits::complete::take(1usize), |bits: u8| bits > 0)(i)
}
