use sodiumoxide;
use byteorder::{ByteOrder,BigEndian,WriteBytesExt};

use super::{SSHString, Named,Preferred,Error};
use super::msg;
use std;
use sodiumoxide::crypto::auth::hmacsha256;
#[derive(Debug,Clone)]
pub enum Mac {
    HmacSha256 // 
}
const MAC_SHA256:&'static str = "hmac-sha2-256";
const MACS: &'static [&'static str;1] = &[
    MAC_SHA256
];

impl Named for Mac {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == MAC_SHA256.as_bytes() {
            return Some(Mac::HmacSha256)
        }
        None
    }
}
impl Preferred for Mac {
    fn preferred() -> &'static [&'static str] {
        MACS
    }
}
