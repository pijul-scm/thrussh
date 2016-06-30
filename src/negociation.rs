use byteorder::{ByteOrder,BigEndian, ReadBytesExt};
use std;

use super::sodium::randombytes;

use super::{ Error };
use super::key;
use super::kex;
use super::cipher;
use super::mac;
use super::msg;
use super::compression;
use super::CryptoBuf;
use super::encoding::Reader;

// pub type Names = (super::kex::Name, super::key::Algorithm, super::cipher::Name, super::mac::Mac, bool);

#[derive(Debug)]
pub struct Names {
    pub kex: &'static str,
    pub key: key::Algorithm,
    pub cipher: &'static str,
    pub mac: &'static str,
    pub ignore_guessed: bool
}

#[derive(Debug)]
pub struct Preferred {
    pub kex: &'static [&'static str],
    pub key: &'static [&'static str],
    pub cipher: &'static [&'static str],
    pub mac: &'static [&'static str],
    pub compression: &'static [&'static str],
}

pub const PREFERRED: Preferred = Preferred {
    kex: &[kex::CURVE25519],
    key: &[key::ED25519],
    cipher: &[cipher::CHACHA20POLY1305],
    mac: &["hmac-sha2-256"],
    compression: &["none"]
};


pub trait Select {
    fn select(a:&'static [&'static str], b:&[u8]) -> Option<&'static str>;

    fn read_kex(buffer:&[u8], keys:&[key::Algorithm], pref: &Preferred) -> Result<Names,Error> {
        if buffer[0] != msg::KEXINIT {
            Err(Error::KexInit)
        } else {

            let mut r = buffer.reader(17);
            let kex_algorithm = Self::select( pref.kex, try!(r.read_string()) );
            let key_algorithm = Self::select( pref.key, try!(r.read_string()) )
                .and_then(|algo| keys.iter().find(|a| a.name() == algo));

            let cipher = Self::select( pref.cipher, try!(r.read_string()) );

            try!(r.read_string()); // SERVER_TO_CLIENT
            let mac = Self::select( pref.mac, try!(r.read_string()) );

            try!(r.read_string()); // SERVER_TO_CLIENT
            try!(r.read_string()); // 
            try!(r.read_string()); // 
            try!(r.read_string()); // 

            let follows = try!(r.read_byte()) != 0;
            match (kex_algorithm, key_algorithm, cipher, mac, follows) {
                (Some(kex), Some(key), Some(cip), Some(mac), fol) => Ok(Names {

                    kex: kex,
                    key: key.clone(),
                    cipher:cip,
                    mac:mac,
                    ignore_guessed:fol

                }),
                _ => Err(Error::KexInit)
            }
        }
    }
}

pub struct Server;
pub struct Client;

impl Select for Server {
    fn select(server_list:&'static [&'static str], client_list:&[u8]) -> Option<&'static str> {
        for c in client_list.split(|&x| x == b',') {
            for s in server_list {
                if c == s.as_bytes() {
                    return Some(s)
                }
            }
        }
        None
    }
}

impl Select for Client {
    fn select(client_list:&'static [&'static str], server_list:&[u8]) -> Option<&'static str> {
        for c in client_list {
            for s in server_list.split(|&x| x == b',') {
                if s == c.as_bytes() {
                    return Some(c)
                }
            }
        }
        None
    }
}


pub fn write_kex(prefs:&Preferred, buf:&mut CryptoBuf) {
    // buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0;16];
    randombytes::into(&mut cookie);

    buf.extend(&cookie); // cookie
    buf.extend_list(prefs.kex.iter()); // kex algo

    buf.extend_list(prefs.key.iter());

    buf.extend_list(prefs.cipher.iter()); // cipher client to server
    buf.extend_list(prefs.cipher.iter()); // cipher server to client

    buf.extend_list(prefs.mac.iter()); // mac client to server
    buf.extend_list(prefs.mac.iter()); // mac server to client
    buf.extend_list(prefs.compression.iter()); // compress client to server
    buf.extend_list(prefs.compression.iter()); // compress server to client

    buf.write_empty_list(); // languages client to server
    buf.write_empty_list(); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0,0,0,0]); // reserved
}
