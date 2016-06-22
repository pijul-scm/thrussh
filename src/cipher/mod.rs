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
    /*pub fn init(&self, client_to_server:&[u8], server_to_client: &[u8]) -> Cipher {
        match self {
            &Name::Chacha20Poly1305 => {
                Cipher::Chacha20Poly1305 {
                    client_to_server: chacha20poly1305::Cipher::init(client_to_server),
                    server_to_client: chacha20poly1305::Cipher::init(server_to_client)
                }
            }
        }
    }*/
}

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305 {
        client_to_server:chacha20poly1305::Cipher,
        server_to_client:chacha20poly1305::Cipher
    }
}

use super::CryptoBuf;

pub trait CipherT {
    fn read_packet<'a, R:BufRead>(&self, stream:&mut R, buffer: &'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error>;
    fn write_packet(&self, seq:usize, packet:&[u8], buffer:&mut CryptoBuf);
}

impl Cipher {

    pub fn read_client_packet<'a, R:BufRead>(
        &mut self,
        stream:&mut R,
        buffer:&'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error> {

        match *self {
            Cipher::Chacha20Poly1305 { ref client_to_server, .. } => {

                client_to_server.read_packet(stream, buffer)

            },
            //_ => unimplemented!()
        }
    }
    pub fn read_server_packet<'a, R:BufRead>(
        &mut self,
        stream:&mut R,
        buffer:&'a mut super::SSHBuffer) -> Result<Option<&'a[u8]>,Error> {

        match *self {
            Cipher::Chacha20Poly1305 { ref server_to_client, .. } => {

                server_to_client.read_packet(stream, buffer)

            },
            //_ => unimplemented!()
        }
    }

    pub fn write_server_packet(&mut self, seq:usize, packet:&[u8], buffer:&mut CryptoBuf) {

        match *self {
            Cipher::Chacha20Poly1305 { ref server_to_client, .. } => {

                server_to_client.write_packet(seq, packet, buffer)
            },
            //_ => unimplemented!()
        }

        
    }
    pub fn write_client_packet(&mut self, seq:usize, packet:&[u8], buffer:&mut CryptoBuf) {

        match *self {
            Cipher::Chacha20Poly1305 { ref client_to_server, .. } => {

                client_to_server.write_packet(seq, packet, buffer)
            },
            //_ => unimplemented!()
        }

        
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
