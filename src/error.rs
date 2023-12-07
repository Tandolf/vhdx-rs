use nom::{
    error::{self, make_error, FromExternalError, ParseError},
    ErrorConvert,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorKind<I> {
    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    Nom(#[from] nom::error::Error<I>),
}

impl<I> ParseError<I> for ErrorKind<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        ErrorKind::Nom(make_error(input, kind))
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other
    }
}

impl<I> FromExternalError<I, uuid::Error> for ErrorKind<I> {
    fn from_external_error(input: I, kind: nom::error::ErrorKind, e: uuid::Error) -> Self {
        ErrorKind::Uuid(e)
    }
}

impl<I> ErrorConvert<ErrorKind<I>> for ErrorKind<(I, usize)> {
    fn convert(self) -> ErrorKind<I> {
        match self {
            ErrorKind::Uuid(e) => ErrorKind::Uuid(e),
            ErrorKind::Nom(e) => ErrorKind::Nom(make_error(e.input.0, e.code)),
        }
    }
}
