use sodiumoxide;
use byteorder::{ByteOrder,BigEndian,WriteBytesExt};

use super::{SSHString, Named,Preferred,Error};
use super::msg;
use std;

use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::onetimeauth::poly1305;
use std::io::{Read,Write};

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305(Option<Chacha20Poly1305>) // "chacha20-poly1305@openssh.com"
}

impl Cipher {
    pub fn read_client_packet<R:Read>(&mut self, seq:&mut usize, stream:&mut R, buffer:&mut Vec<u8>) -> Result<(),Error> {

        match *self {
            Cipher::Chacha20Poly1305(Some(ref mut chacha)) => {

                // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

                let mut len = [0;4];
                stream.read_exact(&mut len);
                buffer.clear();
                buffer.extend(&len);

                let k1 = &chacha.key_client_to_server[32..64];
                let k1 = chacha20::Key::from_slice(k1).unwrap();

                let k2 = &chacha.key_client_to_server[0..32];
                let k2 = chacha20::Key::from_slice(k2).unwrap();

                let mut nonce = [0;8];
                BigEndian::write_u32(&mut nonce[4..], *seq as u32);
                let nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

                chacha20::stream_xor_inplace(
                    &mut len,
                    &nonce,
                    &k1);

                let packet_length = BigEndian::read_u32(&len) as usize;

                println!("chacha20: packet length: {:?}", &len[..]);

                buffer.resize(4 + packet_length + poly1305::TAGBYTES, 0);
                try!(stream.read_exact(&mut buffer[4..]));

                let mut poly_key = [0;32];
                chacha20::stream_xor_inplace(
                    &mut poly_key,
                    &nonce,
                    &k2);
                let poly_key = poly1305::Key::from_slice(&poly_key).unwrap();

                let tag = poly1305::authenticate(&buffer[0..4+packet_length], &poly_key);
                if sodiumoxide::utils::memcmp(&tag.0, &buffer[4+packet_length..]) {

                    println!("verif !");

                    *seq += 1;
                    Ok(())

                } else {
                    
                    println!("not verif :(");
                    unimplemented!()
                }
            },
            _ => unimplemented!()
        }
    }
}

/*
fn read_encrypted_packet<R:Read>(stream:&mut R,
                                 nonce:&mut sodiumoxide::crypto::aead::chacha20poly1305::Nonce,
                                 key:&sodiumoxide::crypto::aead::chacha20poly1305::Key,
                                 buf:&mut Vec<u8>) -> Result<usize, Error> {

}
*/





const CIPHER_CHACHA20_POLY1305:&'static str = "chacha20-poly1305@openssh.com";
const CIPHERS: &'static [&'static str;1] = &[
    CIPHER_CHACHA20_POLY1305
];
impl Named for Cipher {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == CIPHER_CHACHA20_POLY1305.as_bytes() {
            return Some(Cipher::Chacha20Poly1305(None))
        }
        None
    }
}
impl Preferred for Cipher {
    fn preferred() -> &'static [&'static str] {
        CIPHERS
    }
}

#[derive(Debug)]
pub struct Chacha20Poly1305 {
    pub iv_client_to_server: Vec<u8>,
    pub iv_server_to_client: Vec<u8>,
    pub key_client_to_server: Vec<u8>,
    pub key_server_to_client: Vec<u8>,
    pub integrity_client_to_server: Vec<u8>,
    pub integrity_server_to_client: Vec<u8>,
}

pub fn digest_dump(dd:&[u8]) {
    for i in dd {
        print!("{:02x} ", i);
    }
    println!("");
}
impl Chacha20Poly1305 {
    pub fn dump(&self) {
        println!("A");
        digest_dump(&self.iv_client_to_server);
        println!("B");
        digest_dump(&self.iv_server_to_client);
        println!("C");
        digest_dump(&self.key_client_to_server);
        println!("D");
        digest_dump(&self.key_server_to_client);
        println!("E");
        digest_dump(&self.integrity_client_to_server);
        println!("F");
        digest_dump(&self.integrity_server_to_client);
    }
}
