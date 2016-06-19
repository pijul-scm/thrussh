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

pub type Names = (super::kex::Name, super::key::Algorithm, super::cipher::Name, super::mac::Mac, bool);

pub trait Named:Sized {
    fn from_name(&[u8]) -> Option<Self>;
}

pub trait Preferred:Sized {
    fn preferred() -> &'static [&'static str];
}

fn select<A:Named + 'static>(list:&[u8]) -> Option<A> {
    for l in list.split(|&x| x == b',') {
        if let Some(x) = A::from_name(l) {
            return Some(x)
        }
    }
    None
}

fn select_key(list:&[u8], keys:&[key::Algorithm]) -> Option<key::Algorithm> {
    for l in list.split(|&x| x == b',') {
        for k in keys {
            if l == k.name().as_bytes() {
                return Some(k.clone())
            }
        }
    }
    None
}


pub fn read_kex(buffer:&[u8], keys:&[key::Algorithm]) -> Result<Names,Error> {
    if buffer[0] != msg::KEXINIT {
        Err(Error::KexInit)
    } else {
        const FIELD_KEX_ALGORITHM: usize = 0;
        const FIELD_KEY_ALGORITHM: usize = 1;
        const FIELD_CIPHER_CLIENT_TO_SERVER: usize = 2;
        // const FIELD_CIPHER_SERVER_TO_CLIENT: usize = 3;
        const FIELD_MAC: usize = 4;
        const FIELD_FOLLOWS: usize = 9;
        let mut i = 17;
        let mut field = 0;
        let mut kex_algorithm = None;
        let mut key_algorithm = None;
        let mut cipher = None;
        let mut mac = None;
        let mut follows = None;
        while field < 10 {
            assert!(i+3 < buffer.len());
            let len = BigEndian::read_u32(&buffer[i..]) as usize;
            if field == FIELD_KEX_ALGORITHM {
                debug!("kex_algorithms: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                kex_algorithm = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_KEY_ALGORITHM {
                debug!("key_algorithms: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));

                key_algorithm = select_key(&buffer[(i+4)..(i+4+len)], keys)

            } else  if field == FIELD_CIPHER_CLIENT_TO_SERVER {
                debug!("ciphers_client_to_server: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                cipher = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_MAC {
                debug!("mac: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                mac = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_FOLLOWS {
                debug!("follows: {:?}", buffer[i] != 0);
                follows = Some(buffer[i] != 0)
            }
            i+=4+len;
            field += 1;
        }
        match (kex_algorithm, key_algorithm, cipher, mac, follows) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => Ok((a,b,c,d,e)),
            _ => Err(Error::KexInit)
        }
    }
}

pub fn client_read_kex(buffer:&[u8], keys:&[key::Algorithm]) -> Result<Names,Error> {
    if buffer[0] != msg::KEXINIT {
        Err(Error::KexInit)
    } else {
        const FIELD_KEX_ALGORITHM: usize = 0;
        const FIELD_KEY_ALGORITHM: usize = 1;
        const FIELD_CIPHER_CLIENT_TO_SERVER: usize = 2;
        // const FIELD_CIPHER_SERVER_TO_CLIENT: usize = 3;
        const FIELD_MAC: usize = 4;
        const FIELD_FOLLOWS: usize = 9;
        let mut i = 17;
        let mut field = 0;
        let mut kex_algorithm = None;
        let mut key_algorithm = None;
        let mut cipher = None;
        let mut mac = None;
        let mut follows = None;
        while field < 10 {
            assert!(i+3 < buffer.len());
            let len = BigEndian::read_u32(&buffer[i..]) as usize;
            if field == FIELD_KEX_ALGORITHM {
                debug!("kex_algorithms: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                kex_algorithm = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_KEY_ALGORITHM {
                debug!("key_algorithms: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));

                key_algorithm = select_key(&buffer[(i+4)..(i+4+len)], keys)

            } else  if field == FIELD_CIPHER_CLIENT_TO_SERVER {
                debug!("ciphers_client_to_server: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                cipher = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_MAC {
                debug!("mac: {:?}", std::str::from_utf8(&buffer[(i+4)..(i+4+len)]));
                mac = select(&buffer[(i+4)..(i+4+len)])
            } else  if field == FIELD_FOLLOWS {
                debug!("follows: {:?}", buffer[i] != 0);
                follows = Some(buffer[i] != 0)
            }
            i+=4+len;
            field += 1;
        }
        match (kex_algorithm, key_algorithm, cipher, mac, follows) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => Ok((a,b,c,d,e)),
            _ => Err(Error::KexInit)
        }
    }
}



pub fn write_kex(keys:&[key::Algorithm], buf:&mut CryptoBuf) {
    // buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0;16];
    randombytes::into(&mut cookie);

    buf.extend(&cookie); // cookie
    buf.extend_list(kex::Name::preferred().iter()); // kex algo

    buf.extend_list(keys.iter());

    buf.extend_list(cipher::Name::preferred().iter()); // cipher client to server
    buf.extend_list(cipher::Name::preferred().iter()); // cipher server to client

    buf.extend_list(mac::Mac::preferred().iter()); // mac client to server
    buf.extend_list(mac::Mac::preferred().iter()); // mac server to client
    buf.extend_list(compression::CompressionAlgorithm::preferred().iter()); // compress client to server
    buf.extend_list(compression::CompressionAlgorithm::preferred().iter()); // compress server to client

    buf.write_empty_list(); // languages client to server
    buf.write_empty_list(); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0,0,0,0]); // reserved
}
