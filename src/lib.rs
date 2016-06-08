extern crate sodiumoxide;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate regex;
extern crate rustc_serialize;

use rustc_serialize::hex::ToHex;

use byteorder::{ByteOrder,BigEndian,WriteBytesExt};

use std::io::{ Read, Write, BufRead };

use std::sync::{Once, ONCE_INIT};

pub mod config;
use sodiumoxide::crypto::hash::sha256::Digest;

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

use sodiumoxide::crypto::sign::ed25519::{PublicKey,SecretKey,SIGNATUREBYTES};

#[derive(Debug)]
pub struct Exchange {
    client_id:Option<Vec<u8>>,
    server_id:Option<Vec<u8>>,
    client_kex_init:Option<Vec<u8>>,
    server_kex_init:Option<Vec<u8>>,
    client_ephemeral:Option<Vec<u8>>,
    server_ephemeral:Option<Vec<u8>>
}

impl Exchange {
    fn new() -> Self {
        Exchange { client_id: None,
                   server_id: None,
                   client_kex_init: None,
                   server_kex_init: None,
                   client_ephemeral: None,
                   server_ephemeral: None }
    }
}

#[derive(Debug)]
pub struct ServerSession<'a> {
    public_host_key: &'a PublicKey,
    secret_host_key: &'a SecretKey,
    state: Option<ServerState>
}

#[derive(Debug)]
pub enum ServerState {
    VersionOk(Exchange), // Version number received.
    KexInit { // Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively.
        algo: Option<Names>,
        exchange: Exchange,
        session_id: Option<Digest>,
        sent: bool
    },
    KexDh { // Algorithms have been determined, the DH algorithm should run.
        exchange: Exchange,
        kex: KexAlgorithm,
        key: KeyAlgorithm,
        cipher: CipherName,
        mac: MacName,
        session_id: Option<Digest>,
        follows: bool
    },
    NewKeys { // The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side.
        kex: KexAlgorithm,
        key: KeyAlgorithm,
        cipher: CipherName,
        mac: MacName,
        session_id: Digest,
        exchange_hash: sodiumoxide::crypto::hash::sha256::Digest
    },
    Encrypted { // Session is now encrypted.
        kex: KexAlgorithm,
        key: KeyAlgorithm,
        cipher: CipherName,
        mac: MacName,
        session_id: Digest,
    },
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

trait SSHString:Write {
    fn write_ssh_string(&mut self, s:&[u8]) -> Result<(), std::io::Error> {
        try!(self.write_u32::<BigEndian>(s.len() as u32));
        try!(self.write(s));
        Ok(())
    }
    fn write_ssh_mpint(&mut self, s:&[u8]) -> Result<(), std::io::Error> {
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i+=1
        }
        if s[i] & 0x80 != 0 {
            try!(self.write_u32::<BigEndian>((s.len() - i + 1) as u32));
            try!(self.write_u8(0));
        } else {
            try!(self.write_u32::<BigEndian>((s.len() - i) as u32));
        }
        try!(self.write(&s[i..]));
        Ok(())
    }
}
impl<T:Write> SSHString for T {}

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
    println!("buf len :{:?}", buf.len());
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
    println!("write_list: {:?}", &buf[len0..len0+4]);
}

pub fn hexdump(x:&[u8]) {
    let mut buf = Vec::new();
    let mut i = 0;
    while i < x.len() {
        if i%16 == 0 {
            print!("{:04}: ", i)
        }
        print!("{:02x} ", x[i]);
        if x[i] >= 0x20 && x[i]<= 0x7e {
            buf.push(x[i]);
        } else {
            buf.push(b'.');
        }
        if i % 16 == 15 || i == x.len() -1 {
            while i%16 != 15 {
                print!("   ");
                i += 1
            }
            println!(" {}", std::str::from_utf8(&buf).unwrap());
            buf.clear();
        }
        i += 1
    }
}


impl<'a> ServerSession<'a> {

    pub fn new(server_pubkey: &'a PublicKey, server_secret: &'a SecretKey) -> Self {
        SODIUM_INIT.call_once(|| { sodiumoxide::init(); });
        ServerSession {
            public_host_key: server_pubkey,
            secret_host_key: server_secret,
            state: None
        }
    }

    pub fn read<R:Read>(&mut self, stream:&mut R, buffer:&mut Vec<u8>, buffer2:&mut Vec<u8>) -> Result<(), Error> {
        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {

                let mut client_id = [0;255];
                let read = stream.read(&mut client_id).unwrap();
                if read < 8 {
                    Ok(())
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
                            let mut exchange = Exchange::new();
                            exchange.client_id = Some((&client_id[0..i]).to_vec());
                            self.state = Some(ServerState::VersionOk(exchange));
                            Ok(())
                        } else {
                            Err(Error::Version)
                        }
                    } else {
                        Err(Error::Version)
                    }
                }
            },
            Some(ServerState::KexInit { mut exchange, algo, sent, session_id }) => {
                let algo = if algo.is_none() {

                    let mut kex_init = Vec::new();
                    let read = read_packet(stream, &mut kex_init).unwrap();
                    kex_init.truncate(read);
                    let kex = read_kex(&kex_init).unwrap();
                    // println!("kex = {:?}", kex_init);
                    exchange.client_kex_init = Some(kex_init);
                    Some(kex)

                } else {
                    algo
                };

                if !sent {
                    self.state = Some(ServerState::KexInit {
                        exchange: exchange,
                        algo:algo,
                        sent:sent,
                        session_id: session_id
                    });
                    Ok(())
                } else {
                    if let Some((kex,key,cipher,mac,follows)) = algo {
                        self.state = Some(
                            ServerState::KexDh {
                                exchange:exchange,
                                kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                                session_id: session_id
                            });
                        Ok(())
                    } else {
                        Err(Error::Kex)
                    }
                }
            },
            Some(ServerState::KexDh { mut exchange, mut kex, key, cipher, mac, follows, session_id }) => {

                buffer.clear();
                let read = try!(read_packet(stream, buffer));
                buffer.truncate(read);

                assert!(buffer[0] == msg::KEX_ECDH_INIT);

                try!(kex.dh(&mut exchange, &buffer));

                exchange.client_ephemeral = Some((&buffer[5..]).to_vec());
                self.state = Some(
                    ServerState::KexDh {
                        exchange:exchange,
                        kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                        session_id: session_id
                    });
                Ok(())
            },
            Some(ServerState::NewKeys { kex, key, cipher, mac, exchange_hash, session_id }) => {

                // We are waiting for the NEWKEYS packet.
                buffer.clear();
                let read = try!(read_packet(stream, buffer));
                if read > 0 && buffer[0] == msg::NEWKEYS {
                    self.state = Some(
                        ServerState::Encrypted { kex:kex, key:key,
                                                 cipher:cipher, mac:mac,
                                                 session_id: session_id
                        }
                    );
                    Ok(())
                } else {
                    Ok(())
                }
            },
            _ => {
                println!("read: unhandled");
                Ok(())
            }
        }
    }

    pub fn write<W:Write>(&mut self, stream:&mut W, buffer:&mut Vec<u8>, buffer2:&mut Vec<u8>) -> Result<(), Error> {

        let state = std::mem::replace(&mut self.state, None);

        match state {
            Some(ServerState::VersionOk(mut exchange)) => {
                debug!("writing");
                let mut server_id = b"SSH-2.0-SSH.rs_0.1\r\n".to_vec();
                try!(stream.write_all(&mut server_id));
                let len = server_id.len();
                server_id.truncate(len - 2); // Drop CRLF.
                exchange.server_id = Some(server_id);

                try!(stream.flush());
                self.state = Some(
                    ServerState::KexInit {
                        exchange:exchange,
                        algo:None, sent:false,
                        session_id: None
                    }
                );
                Ok(())
            },
            Some(ServerState::KexInit { mut exchange, algo, sent, session_id }) => {
                if !sent {
                    let mut server_kex = Vec::new();
                    write_kex(&mut server_kex);
                    try!(write_packet(stream, &server_kex, None));
                    exchange.server_kex_init = Some(server_kex);
                    try!(stream.flush());
                }
                if let Some((kex,key,cipher,mac,follows)) = algo {

                    self.state = Some(
                        ServerState::KexDh {
                        exchange:exchange,
                        kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                        session_id: session_id
                    });
                    Ok(())
                } else {
                    self.state = Some(
                        ServerState::KexInit {
                            exchange:exchange,
                            algo:algo, sent:true,
                            session_id: session_id
                        }
                    );
                    Ok(())
                }
            },
            Some(ServerState::KexDh { exchange, kex, key, cipher, mac, follows, session_id }) => {

                let hash = try!(kex.compute_exchange_hash(&self.public_host_key, &exchange, buffer));

                let mut ok = false;
                if let Some(ref server_ephemeral) = exchange.server_ephemeral {

                    buffer.clear();

                    // ECDH Key exchange.
                    // http://tools.ietf.org/html/rfc5656#section-4

                    buffer.push(msg::KEX_ECDH_REPLY);

                    try!(buffer.write_u32::<BigEndian>(
                        (KEY_ED25519.len()
                         + self.public_host_key.0.len()
                         + 8) as u32
                    ));
                    try!(buffer.write_ssh_string(KEY_ED25519.as_bytes()));
                    try!(buffer.write_ssh_string(&self.public_host_key.0));

                    // Server ephemeral
                    try!(buffer.write_ssh_string(server_ephemeral));

                    // Hash signature
                    let sign = sodiumoxide::crypto::sign::ed25519::sign_detached(&hash.0, self.secret_host_key);

                    try!(buffer.write_u32::<BigEndian>(
                        (KEY_ED25519.len()
                         + sign.0.len()
                         + 8) as u32
                    ));
                    try!(buffer.write_ssh_string(KEY_ED25519.as_bytes()));
                    try!(buffer.write_ssh_string(&sign.0));
                    //
                    try!(write_packet(stream, &buffer, None));
                    
                    // Sending the NEWKEYS packet.
                    // https://tools.ietf.org/html/rfc4253#section-7.3
                    buffer.clear();
                    buffer.push(msg::NEWKEYS);
                    try!(write_packet(stream, &buffer, None));
                    try!(stream.flush());

                    let session_id = if let Some(session_id) = session_id {
                        session_id
                    } else {
                        hash.clone()
                    };
                    // Now computing keys.
                    let keys = kex.compute_keys(&session_id, &hash, buffer, buffer2).unwrap();
                    keys.dump(); //println!("keys: {:?}", keys);
                    //
                    self.state = Some(
                        ServerState::NewKeys {
                            kex:kex, key:key,
                            cipher:cipher, mac:mac,
                            exchange_hash: hash,
                            session_id: session_id
                        }
                    );
                    Ok(())
                } else {
                    Ok(()) // Is it ok, really?
                }
            },
            session => {
                println!("write: unhandled");
                Ok(())
            }
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
