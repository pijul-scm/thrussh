use byteorder::{ByteOrder,BigEndian, WriteBytesExt};

use std::io::{ Write };


use sodiumoxide::crypto::sign::ed25519;
use super::SSHString;

#[derive(Debug,Clone)]
pub enum Name {
    Ed25519 // "ssh-ed25519"
}

#[derive(Debug,Clone)]
pub enum Algorithm {
    Ed25519 {
        public_host_key: ed25519::PublicKey,
        secret_host_key: ed25519::SecretKey
    } // "ssh-ed25519"
}


pub const KEY_ED25519:&'static str = "ssh-ed25519";
pub const KEY_ALGORITHMS: &'static [&'static str;1] = &[
    KEY_ED25519
];

impl super::Named for Name {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == KEY_ED25519.as_bytes() {
            return Some(Name::Ed25519)
        }
        None
    }
}

impl super::Preferred for Algorithm {
    fn preferred() -> &'static [&'static str] {
        KEY_ALGORITHMS
    }
}
impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            &Algorithm::Ed25519 { .. } => "ssh-ed25519"
        }
    }

    pub fn write_pubkey<W:Write>(&self, buffer:&mut W) -> Result<(),super::Error> {
        match self {
            &Algorithm::Ed25519 { ref public_host_key, .. } => {
                try!(buffer.write_u32::<BigEndian>(
                    (KEY_ED25519.len()
                     + ed25519::PUBLICKEYBYTES
                     + 8) as u32
                ));
                try!(buffer.write_ssh_string(KEY_ED25519.as_bytes()));
                try!(buffer.write_ssh_string(&public_host_key.0));
                Ok(())
            }
        }
    }
    
    pub fn add_signature(&self, buffer: &mut Vec<u8>, hash:&[u8])->Result<(),super::Error> {
        match self {
            &Algorithm::Ed25519 { ref secret_host_key, .. } => {

                let sign = ed25519::sign_detached(&hash, secret_host_key);

                try!(buffer.write_u32::<BigEndian>(
                    (KEY_ED25519.len()
                     + ed25519::SIGNATUREBYTES
                     + 8) as u32
                ));
                try!(buffer.write_ssh_string(KEY_ED25519.as_bytes()));
                try!(buffer.write_ssh_string(&sign.0));
                Ok(())
            }
        }
    }
}
