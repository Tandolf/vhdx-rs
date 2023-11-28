use std::io::{Read, Seek};

pub mod error;
pub mod vhdx;

pub trait DeSerialise<T> {
    type Item;

    fn deserialize(fs: &mut T) -> anyhow::Result<Self::Item>
    where
        T: Read + Seek;
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {}
}
