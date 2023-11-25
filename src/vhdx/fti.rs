use nom::{bytes::complete::take, combinator::map, sequence::tuple, Finish, IResult};

use crate::DeSerialise;

const FTI_SIZE: usize = 64000;
const SIGNATURE_SIZE: usize = 8;
const CREATOR_SIZE: usize = 512;

#[derive(Debug)]
pub struct FileTypeIdentifier {
    pub signature: String,
    pub creator: String,
}

impl FileTypeIdentifier {
    fn new(signature: String, creator: String) -> FileTypeIdentifier {
        Self { signature, creator }
    }
}

fn t_signature(buffer: &[u8]) -> IResult<&[u8], String> {
    map(take(8usize), |bytes: &[u8]| {
        // Handle utf-8 error
        String::from_utf8(bytes.to_vec()).unwrap()
    })(buffer)
}

fn t_creator(buffer: &[u8]) -> IResult<&[u8], String> {
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

fn t_reserved(buffer: &[u8]) -> IResult<&[u8], &[u8]> {
    take(FTI_SIZE - SIGNATURE_SIZE - CREATOR_SIZE)(buffer)
}

impl<'a> DeSerialise<'a> for FileTypeIdentifier {
    type Item = (&'a [u8], FileTypeIdentifier);

    fn deserialize(buffer: &'a [u8]) -> anyhow::Result<Self::Item> {
        Ok(map(
            tuple((t_signature, t_creator, t_reserved)),
            |(signature, creator, _)| FileTypeIdentifier::new(signature, creator),
        )(buffer)
        .finish()
        .unwrap())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_deserialize_fti() {
        let mut values = vec![
            0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6c, 0x65, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
            0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x20, 0x00,
            0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
            0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00,
            0x39, 0x00, 0x30, 0x00, 0x34, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x30,
        ];

        values.resize(64000, 0);

        let (_, fti) = FileTypeIdentifier::deserialize(&values).unwrap();

        assert_eq!("vhdxfile", fti.signature);
        assert_eq!("Microsoft Windows 10.0.19045.0", fti.creator);
    }
}
