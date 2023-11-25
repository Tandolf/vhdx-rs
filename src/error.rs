use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError<'a> {
    #[error("`{0:?}` is not a valid utf-8 string")]
    InvalidUtf8Data(&'a [u8]),
    #[error("`{0:?}` is not a valid utf-16 string")]
    InvalidUtf16Data(&'a [u16]),
    #[error("unknown data store error")]
    Unknown,
}
