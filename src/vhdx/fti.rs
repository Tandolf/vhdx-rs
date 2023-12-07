use super::{
    parse_utils::{t_creator, t_sign_u64},
    signatures::Signature,
};
use crate::DeSerialise;
use nom::{combinator::map, sequence::tuple};
use std::io::{Read, Seek};

const FTI_SIZE: usize = 65536;

#[derive(Debug)]
pub struct FileTypeIdentifier {
    pub signature: Signature,
    pub creator: String,
}

impl FileTypeIdentifier {
    fn new(signature: Signature, creator: String) -> FileTypeIdentifier {
        Self { signature, creator }
    }
}

impl<T> DeSerialise<T> for FileTypeIdentifier {
    type Item = FileTypeIdentifier;

    fn deserialize(reader: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek,
    {
        let mut buffer = [0; FTI_SIZE];
        reader.read_exact(&mut buffer)?;

        let (_, fti) = map(tuple((t_sign_u64, t_creator)), |(signature, creator)| {
            FileTypeIdentifier::new(signature, creator)
        })(&buffer)
        .unwrap();
        Ok(fti)
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use super::*;

    #[test]
    fn parse_fti() {
        let mut values = vec![
            0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6c, 0x65, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
            0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00,
            0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
            0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x30,
        ];

        values.resize(FTI_SIZE, 0);

        let mut values = Cursor::new(values);

        let fti = FileTypeIdentifier::deserialize(&mut values).unwrap();

        assert_eq!(Signature::Vhdxfile, fti.signature);
        assert_eq!("Microsoft Windows 10.0.19045.0", fti.creator);
    }
}
