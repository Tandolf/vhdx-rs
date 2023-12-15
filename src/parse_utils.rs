use crate::{
    error::VhdxParseError,
    log::{DataDesc, Descriptor, LogHeader, ZeroDesc},
    meta_data::MetaData,
    vhdx_header::{FileTypeIdentifier, Header, RegionTable},
    Signature,
};

use nom::{
    bytes::complete::take,
    combinator::{map, map_res},
    number::complete::{le_u16, le_u32, le_u64},
    IResult,
};
use uuid::{Builder, Uuid};

pub fn t_sign_u64(buffer: &[u8]) -> IResult<&[u8], Signature, VhdxParseError<&[u8]>> {
    map(take(8usize), |bytes: &[u8]| match bytes {
        FileTypeIdentifier::SIGN => Signature::Vhdxfile,
        MetaData::SIGN => Signature::MetaData,
        _ => Signature::Unknown,
    })(buffer)
}

pub fn t_sign_u32(buffer: &[u8]) -> IResult<&[u8], Signature, VhdxParseError<&[u8]>> {
    map(take(4usize), |bytes: &[u8]| match bytes {
        Header::SIGN => Signature::Head,
        RegionTable::SIGN => Signature::Regi,
        Descriptor::SIGN => Signature::Desc,
        ZeroDesc::SIGN => Signature::Zero,
        DataDesc::SIGN => Signature::Data,
        LogHeader::SIGN => Signature::Loge,
        _ => Signature::Unknown,
    })(buffer)
}

pub fn t_guid(buffer: &[u8]) -> nom::IResult<&[u8], Uuid, VhdxParseError<&[u8]>> {
    map_res(take(16usize), |bytes: &[u8]| {
        Ok(Builder::from_slice_le(bytes)?.into_uuid())
    })(buffer)
}

pub fn t_u32(buffer: &[u8]) -> IResult<&[u8], u32, VhdxParseError<&[u8]>> {
    le_u32(buffer)
}

pub fn t_u64(buffer: &[u8]) -> IResult<&[u8], u64, VhdxParseError<&[u8]>> {
    le_u64(buffer)
}

pub fn t_bool_u32(buffer: &[u8]) -> IResult<&[u8], bool, VhdxParseError<&[u8]>> {
    map(le_u32, |value: u32| value > 0)(buffer)
}

pub fn t_u16(buffer: &[u8]) -> IResult<&[u8], u16, VhdxParseError<&[u8]>> {
    le_u16(buffer)
}

pub fn t_creator(buffer: &[u8]) -> IResult<&[u8], String, VhdxParseError<&[u8]>> {
    map(take(512usize), |bytes: &[u8]| {
        let bytes: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b: &[u8]| ((b[1] as u16) << 8) | (b[0] as u16))
            .collect();
        String::from_utf16(&bytes)
            // Handle utf error
            .unwrap()
            .trim_end_matches(char::from(0))
            .to_string()
    })(buffer)
}
