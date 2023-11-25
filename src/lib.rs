use anyhow::Result;

pub mod error;
pub mod vhdx;

pub trait DeSerialise<'a> {
    type Item;

    fn deserialize(buffer: &'a [u8]) -> Result<Self::Item>;
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
