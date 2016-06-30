use super::negociation::{Named,Preferred};
use super::Error;
use std::io::{ BufRead };

pub mod chacha20poly1305;

#[derive(Debug)]
pub enum Name {
    Chacha20Poly1305
}

impl Name {
    pub fn key_size(&self) -> usize {
        match self {
            &Name::Chacha20Poly1305 => 64
        }
    }
}

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305(chacha20poly1305::Cipher)
}

#[derive(Debug)]
pub struct CipherPair {
    pub local_to_remote: Cipher,
    pub remote_to_local: Cipher,
}

pub trait CipherT {
    fn read<'a, R:BufRead>(&self, stream:&mut R, buffer: &'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error>;
    fn write(&self, packet:&[u8], buffer:&mut super::SSHBuffer);
}

impl CipherT for Cipher {
    fn read<'a, R:BufRead>(
        &self,
        stream:&mut R,
        buffer:&'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error> {

        match *self {
            Cipher::Chacha20Poly1305(ref cipher) => {
                cipher.read(stream, buffer)
            },
        }
    }
    fn write(&self, packet:&[u8], buffer:&mut super::SSHBuffer) {

        match *self {
            Cipher::Chacha20Poly1305(ref cipher) => {
                cipher.write(packet, buffer)
            },
        }
    }
}
impl CipherT for CipherPair {
    fn read<'a, R:BufRead>(
        &self,
        stream:&mut R,
        buffer:&'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error> {

        self.remote_to_local.read(stream, buffer)
    }
    fn write(&self, packet:&[u8], buffer:&mut super::SSHBuffer) {

        self.local_to_remote.write(packet, buffer)

    }
}


const CIPHER_CHACHA20_POLY1305:&'static str = "chacha20-poly1305@openssh.com";
const CIPHERS: &'static [&'static str;1] = &[
    CIPHER_CHACHA20_POLY1305
];
impl Named for Name {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == CIPHER_CHACHA20_POLY1305.as_bytes() {
            return Some(Name::Chacha20Poly1305)
        }
        None
    }
}
impl Preferred for Name {
    fn preferred() -> &'static [&'static str] {
        CIPHERS
    }
}
