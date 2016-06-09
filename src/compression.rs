use super::negociation::{Named, Preferred};

pub enum CompressionAlgorithm {
    None
}
const COMPRESSION_NONE:&'static str = "none";
const COMPRESSIONS: &'static [&'static str;1] = &[
    COMPRESSION_NONE
];

impl Named for CompressionAlgorithm {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == COMPRESSION_NONE.as_bytes() {
            return Some(CompressionAlgorithm::None)
        }
        None
    }
}
impl Preferred for CompressionAlgorithm {
    fn preferred() -> &'static [&'static str] {
        COMPRESSIONS
    }
}
