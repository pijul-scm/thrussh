use byteorder::{ByteOrder, BigEndian};
use regex::Regex;
use rustc_serialize::base64::{FromBase64};
use std::path::Path;
use std::fs::File;
use std::io::Read;

pub fn read_key<P:AsRef<Path>>(p:P) -> Result<Vec<u8>, super::Error> {

    let pubkey_regex = Regex::new(r"ssh-\S*\s*(?P<key>\S+)\s*").unwrap();
    let mut pubkey = String::new();
    let mut file = File::open(p.as_ref()).unwrap();
    file.read_to_string(&mut pubkey).unwrap();
    let p = pubkey_regex.captures(&pubkey).unwrap().name("key").unwrap().from_base64().unwrap();

    let key_type_len = BigEndian::read_u32(&p) as usize;
    let key_type = &p[4..key_type_len+4];
    if key_type == b"ssh-ed25519" {
        let key_len = BigEndian::read_u32(&p[4+key_type_len..]) as usize;
        Ok((&p[4+key_type_len .. 4+key_type_len+key_len]).to_vec())
    } else {
        Err(super::Error::CouldNotReadKey)
    }
}
