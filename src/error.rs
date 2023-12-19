use std::io;

use nom::{
    error::{make_error, FromExternalError, ParseError},
    ErrorConvert,
};
use thiserror::Error;

use crate::Signature;

pub type Result<T, E = VhdxParseError<T>> = core::result::Result<T, E>;

#[derive(Error, Debug)]
pub enum VhdxError {
    #[error("ParseError: {0}")]
    ParseError(String),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("Unknown RT Entry found: {0}")]
    UnknownRTEntryFound(String),

    #[error("Missing region in Region Table: {0}")]
    MissingKnownRegion(&'static str),

    #[error("Signature validation failed expected: {0:?}, got: {1:?}")]
    SignatureError(Signature, Signature),

    #[error("Calculate crc doesn't match expected: {0}, got: {1}")]
    Crc32Error(u32, u32),

    #[error("No valid VHDX header found")]
    VhdxHeaderError,

    #[error("VHDX Version error should be 1 got: {0}")]
    VersionError(u16),

    #[error("VHDX LogVersion error should be 10 got: {0}")]
    LogVersionError(u16),

    #[error("LogLength should be a multiple of 1 MB length is currently: {0}")]
    LogLengthError(u16),

    #[error("LogOffset should be a multiple of 1 MB length is currently: {0}")]
    LogOffsetError(u16),

    #[error("RegionTable EntryCount must be less than 2047 bytes got: {0} bytes")]
    RTEntryCountError(u32),
}

impl From<VhdxParseError<&[u8]>> for VhdxError {
    fn from(value: VhdxParseError<&[u8]>) -> Self {
        VhdxError::ParseError(format!("{:?}", value))
    }
}

impl From<nom::Err<VhdxParseError<&[u8]>>> for VhdxError {
    fn from(value: nom::Err<VhdxParseError<&[u8]>>) -> Self {
        match value {
            nom::Err::Error(v) => v.into(),
            nom::Err::Failure(v) => v.into(),
            nom::Err::Incomplete(_) => panic!("No support for streaming parsers"),
        }
    }
}

#[derive(Error, Debug)]
pub enum VhdxParseError<I> {
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    Nom(#[from] nom::error::Error<I>),

    #[error("Unknown signature detected")]
    UnknownSignature,
}

impl<I> ParseError<I> for VhdxParseError<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        VhdxParseError::Nom(make_error(input, kind))
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> FromExternalError<I, uuid::Error> for VhdxParseError<I> {
    fn from_external_error(_input: I, _kind: nom::error::ErrorKind, e: uuid::Error) -> Self {
        VhdxParseError::Uuid(e)
    }
}

impl<I> ErrorConvert<VhdxParseError<I>> for VhdxParseError<(I, usize)> {
    fn convert(self) -> VhdxParseError<I> {
        match self {
            VhdxParseError::Uuid(e) => VhdxParseError::Uuid(e),
            VhdxParseError::Nom(e) => VhdxParseError::Nom(make_error(e.input.0, e.code)),
            VhdxParseError::UnknownSignature => VhdxParseError::UnknownSignature,
        }
    }
}
