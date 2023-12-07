use uuid::{uuid, Uuid};

pub const FTI_SIGN: &[u8] = &[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65];
pub const HEAD_SIGN: &[u8] = &[0x68, 0x65, 0x61, 0x64];
pub const RGT_SIGN: &[u8] = &[0x72, 0x65, 0x67, 0x69];
pub const DESC_SIGN: &[u8] = &[0x64, 0x65, 0x73, 0x63];
pub const DATA_SIGN: &[u8] = &[0x64, 0x61, 0x74, 0x61];
pub const LOGE_SIGN: &[u8] = &[0x6C, 0x6F, 0x67, 0x65];
pub const ZERO_SIGN: &[u8] = &[0x6F, 0x72, 0x65, 0x7A];
pub const META_DATA_SIGN: &[u8] = &[0x6D, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61];
pub const FILE_PARAMETERS: Uuid = uuid!("CAA16737FA364D43B3B633F0AA44E76B");
pub const VIRTUAL_DISK_SIZE: Uuid = uuid!("2FA54224CD1B4876B2115DBED83BF4B8");
pub const VIRTUAL_DISK_ID: Uuid = uuid!("BECA12ABB2E6452393EFC309E000C746");
pub const LOGICAL_SECTOR_SIZE: Uuid = uuid!("8141BF1DA96F4709BA47F233A8FAAB5F");
pub const PHYSICAL_SECTOR_SIZE: Uuid = uuid!("CDA348C7445D44719CC9E9885251C556");
pub const PARENT_LOCATOR: Uuid = uuid!("A8D35F2DB30B454DABF7D3D84834AB0C");

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Signature {
    Vhdxfile,
    Head,
    Regi,
    Loge,
    Zero,
    Data,
    Desc,
    MetaData,
    Unknown,
}

pub enum MDKnownItems {
    FileParamaters,
    VirtualDiskSize,
    VirtualDiskId,
    LogicalSectorSize,
    PhysicalSectorSize,
    ParentLocator,
}
