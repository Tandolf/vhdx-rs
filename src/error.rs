use nom::error::ParseError;

pub struct Error<I> {
    kind: ErrorKind<I>,
    backtrace: Vec<Error<I>>,
}

pub enum ErrorKind<I> {
    Nom(I, nom::error::ErrorKind),
}

impl<I> ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            kind: ErrorKind::Nom(input, kind),
            backtrace: Vec::new(),
        }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.backtrace.push(Self::from_error_kind(input, kind));
        other
    }
}
