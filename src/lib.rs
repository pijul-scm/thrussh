extern crate sodiumoxide;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate regex;
extern crate rustc_serialize;


use byteorder::{ByteOrder,BigEndian,WriteBytesExt};

use std::io::{ Read, Write, BufRead };

use std::sync::{Once, ONCE_INIT};

pub mod key;

static SODIUM_INIT: Once = ONCE_INIT;
#[derive(Debug)]
pub enum Error {
    CouldNotReadKey,
    KexInit,
    Version,
    Kex,
    DH,
    IO(std::io::Error)
}

impl From<std::io::Error> for Error {
    fn from(e:std::io::Error) -> Error {
        Error::IO(e)
    }
}

#[derive(Debug)]
pub struct Exchange {
    client_id:Option<Vec<u8>>,
    server_id:Option<Vec<u8>>,
    client_kex_init:Option<Vec<u8>>,
    server_kex_init:Option<Vec<u8>>,
    server_public_host_key:Option<Vec<u8>>,
    client_ephemeral:Option<Vec<u8>>,
    server_ephemeral:Option<Vec<u8>>
}
impl Exchange {
    fn new<T:AsRef<[u8]>>(pubkey:Option<&T>) -> Exchange {
        Exchange { client_id: None,
                   server_id: None,
                   client_kex_init: None,
                   server_kex_init: None,
                   server_public_host_key: pubkey.map(|x| x.as_ref().to_vec()),
                   client_ephemeral: None,
                   server_ephemeral: None }
    }
}
#[derive(Debug)]
pub enum Session {
    Init(Exchange),
    VersionOk(Exchange),
    KexInit {
        algo: Option<Names>,
        exchange: Exchange,
        sent: bool
    },
    KexDh {
        exchange: Exchange,
        kex:KexAlgorithm,
        key:KeyAlgorithm,
        cipher:CipherName,
        mac:MacName,
        follows:bool
    },
}

impl Session {
    pub fn new<T:AsRef<[u8]>>(pubkey:Option<&T>) -> Session {
        SODIUM_INIT.call_once(|| { sodiumoxide::init(); });
        Session::Init(Exchange::new(pubkey))
    }
}

pub type Names = (KexAlgorithm, KeyAlgorithm, CipherName, MacName, bool);

trait Named:Sized {
    fn from_name(&[u8]) -> Option<Self>;
}

trait Preferred:Sized {
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

mod msg;
mod kex;
use kex::*;



#[derive(Debug,Clone)]
pub enum KeyAlgorithm {
    Ed25519 // "ssh-ed25519"
}
const KEY_ED25519:&'static str = "ssh-ed25519";
const KEY_ALGORITHMS: &'static [&'static str;1] = &[
    KEY_ED25519
];

impl Named for KeyAlgorithm {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == KEY_ED25519.as_bytes() {
            return Some(KeyAlgorithm::Ed25519)
        }
        None
    }
}

impl Preferred for KeyAlgorithm {
    fn preferred() -> &'static [&'static str] {
        KEY_ALGORITHMS
    }
}


#[derive(Debug,Clone)]
pub enum CipherName {
    Chacha20Poly1305 // "chacha20-poly1305@openssh.com"
}

impl CipherName {
    fn blocksize(&self) -> usize {
        sodiumoxide::crypto::stream::chacha20::NONCEBYTES
    }
}

const CIPHER_CHACHA20_POLY1305:&'static str = "chacha20-poly1305@openssh.com";
const CIPHERS: &'static [&'static str;1] = &[
    CIPHER_CHACHA20_POLY1305
];
impl Named for CipherName {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == CIPHER_CHACHA20_POLY1305.as_bytes() {
            return Some(CipherName::Chacha20Poly1305)
        }
        None
    }
}
impl Preferred for CipherName {
    fn preferred() -> &'static [&'static str] {
        CIPHERS
    }
}

#[derive(Debug,Clone)]
pub enum MacName {
    HmacSha256 // 
}
const MAC_SHA256:&'static str = "hmac-sha2-256";
const MACS: &'static [&'static str;1] = &[
    MAC_SHA256
];

impl Named for MacName {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == MAC_SHA256.as_bytes() {
            return Some(MacName::HmacSha256)
        }
        None
    }
}
impl Preferred for MacName {
    fn preferred() -> &'static [&'static str] {
        MACS
    }
}

enum CompressionAlgorithm {
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



fn read_packet<R:Read>(stream:&mut R, buf:&mut Vec<u8>) -> Result<usize,Error> {
    let mut b = [0;5];
    try!(stream.read_exact(&mut b[0..5]));
    let packet_length = BigEndian::read_u32(&b) as usize;
    println!("packet: {:?}, padding: {:?}", packet_length, b[4]);
    buf.resize(packet_length - 1, 0);
    try!(stream.read_exact(&mut buf[0..(packet_length - 1)]));
    // return the read length without padding.
    Ok(packet_length - 1 - (b[4] as usize))
}

fn write_packet<W:Write>(stream:&mut W, buf:&[u8], c:Option<CipherName>) -> Result<(),Error> {


    let block_size = if let Some(c) = c { std::cmp::max(8, c.blocksize()) } else { 8 };
    let padding_len = {
        (block_size - ((5+buf.len()) % block_size))
    };
    let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };
    let mac_len = 0;

    let packet_len = 1 + buf.len() + padding_len + mac_len;
    try!(stream.write_u32::<BigEndian>(packet_len as u32));

    println!("len {:?}, padding {:?}", buf.len(), padding_len);
    try!(stream.write_u8(padding_len as u8));
    try!(stream.write_all(buf));

    let mut padding = [0;256];
    sodiumoxide::randombytes::randombytes_into(&mut padding[0..padding_len]);
    try!(stream.write_all(&padding[0..padding_len]));

    Ok(())
}

fn read_kex(buffer:&[u8]) -> Result<Names,Error> {
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
                key_algorithm = select(&buffer[(i+4)..(i+4+len)])
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

fn write_kex(buf:&mut Vec<u8>) {
    buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0;16];
    sodiumoxide::randombytes::randombytes_into(&mut cookie);

    buf.extend(&cookie); // cookie
    write_list(buf, KexAlgorithm::preferred()); // kex algo
    write_list(buf, KeyAlgorithm::preferred()); // key algo
    write_list(buf, CipherName::preferred()); // cipher client to server
    write_list(buf, CipherName::preferred()); // cipher server to client
    write_list(buf, MacName::preferred()); // mac client to server
    write_list(buf, MacName::preferred()); // mac server to client
    write_list(buf, CompressionAlgorithm::preferred()); // compress client to server
    write_list(buf, CompressionAlgorithm::preferred()); // compress server to client
    write_list(buf, &[]); // languages client to server
    write_list(buf, &[]); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0,0,0,0]); // reserved
}

fn write_list(buf:&mut Vec<u8>, list:&[&str]) {
    let len0 = buf.len();
    buf.extend(&[0,0,0,0]);
    let mut first = true;
    for i in list {
        if !first {
            buf.push(b',')
        } else {
            first = false;
        }
        buf.extend(i.as_bytes())
    }
    let len = (buf.len() - len0 - 4) as u32;
    BigEndian::write_u32(&mut buf[len0..], len);
}




impl Session {
    pub fn new<T:AsRef<[u8]>>(server_pubkey:Option<&T>) -> Session {
        Session::Init(Exchange::new(server_pubkey))
    }
    pub fn read<R:Read>(self, stream:&mut R, buffer:&mut Vec<u8>) -> Result<Session, Error> {
        match self {
            Session::Init(mut exchange) => {

                let mut client_id = [0;255];
                let read = stream.read(&mut client_id).unwrap();
                if read < 8 {
                    Ok(Session::Init(exchange))
                } else {
                    if &client_id[0..8] == b"SSH-2.0-" {
                        println!("read = {:?}", read);
                        let mut i = 0;
                        while i < read {
                            if client_id[i] == b'\n' || client_id[i] == b'\r' {
                                break
                            }
                            i += 1
                        }
                        if i < read {
                            exchange.client_id = Some((&client_id[0..i]).to_vec());
                            Ok(Session::VersionOk(exchange))
                        } else {
                            Err(Error::Version)
                        }
                    } else {
                        Err(Error::Version)
                    }
                }
            },
            Session::KexInit { mut exchange, algo, sent } => {
                let algo = if algo.is_none() {

                    let mut kex_init = Vec::new();
                    let read = read_packet(stream, &mut kex_init).unwrap();
                    let kex = read_kex(&kex_init[0..read]).unwrap();
                    kex_init.truncate(read);
                    exchange.client_kex_init = Some(kex_init);
                    println!("kex = {:?}", kex);
                    Some(kex)

                } else {
                    algo
                };

                if !sent {
                    Ok(Session::KexInit {
                        exchange: exchange,
                        algo:algo,
                        sent:sent
                    })
                } else {
                    if let Some((kex,key,cipher,mac,follows)) = algo {
                        Ok(Session::KexDh {
                            exchange:exchange,
                            kex:kex, key:key, cipher:cipher, mac:mac, follows:follows
                        })
                    } else {
                        Err(Error::Kex)
                    }
                }
            },
            Session::KexDh { mut exchange, mut kex, key, cipher, mac, follows } => {

                let mut client_ephemeral = Vec::new();
                let read = try!(read_packet(stream, &mut client_ephemeral));
                client_ephemeral.truncate(read);
                try!(kex.dh(&mut exchange, &client_ephemeral));

                exchange.client_ephemeral = Some(client_ephemeral);

                Ok(Session::KexDh {
                    exchange:exchange,
                    kex:kex, key:key, cipher:cipher, mac:mac, follows:follows
                })
            },
            session => {
                Ok(session)
            }
        }
    }

    pub fn write<W:Write>(self, stream:&mut W, buffer:&mut Vec<u8>) -> Result<Session, Error> {
        match self {
            Session::VersionOk(mut exchange) => {
                debug!("writing");
                let mut server_id = b"SSH-2.0-SSH.rs_0.1\r\n".to_vec();
                try!(stream.write_all(&mut server_id));
                let len = server_id.len();
                server_id.truncate(len - 2); // Drop CRLF.
                exchange.server_id = Some(server_id);

                try!(stream.flush());
                Ok(Session::KexInit {
                    exchange:exchange,
                    algo:None, sent:false
                })
            },
            Session::KexInit { mut exchange, algo, sent } => {
                if !sent {
                    let mut server_kex = Vec::new();
                    write_kex(&mut server_kex);
                    try!(write_packet(stream, &server_kex, None));
                    exchange.server_kex_init = Some(server_kex);
                    try!(stream.flush());
                }
                if let Some((kex,key,cipher,mac,follows)) = algo {
                    Ok(Session::KexDh {
                        exchange:exchange,
                        kex:kex, key:key, cipher:cipher, mac:mac, follows:follows
                    })
                } else {
                    Ok(Session::KexInit {
                        exchange:exchange,
                        algo:algo, sent:true
                    })
                }
            },
            Session::KexDh { mut exchange, kex, key, cipher, mac, follows } => {
                try!(kex.exchange_hash(&exchange, buffer));
                unimplemented!()
            }
            session => Ok(session)
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
