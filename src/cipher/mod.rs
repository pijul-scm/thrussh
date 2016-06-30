use super::Error;
use std::io::{ BufRead };

pub mod chacha20poly1305;

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305(chacha20poly1305::Cipher)
}

pub fn key_size(c:&str) -> usize {
    match c {
        CHACHA20POLY1305 => 64,
        _ => 0
    }
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

pub const CHACHA20POLY1305:&'static str = "chacha20-poly1305@openssh.com";

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
