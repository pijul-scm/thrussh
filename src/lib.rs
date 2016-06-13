extern crate libc;
extern crate libsodium_sys;
extern crate rand;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate regex; // for config.
extern crate time;


pub mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;
use std::sync::{Once, ONCE_INIT};
use std::io::BufRead;


use byteorder::{ByteOrder, BigEndian};
use regex::Regex;
use rustc_serialize::base64::{FromBase64};
use std::path::Path;
use std::fs::File;
use std::io::{Read,BufReader};
use std::collections::HashMap;

static SODIUM_INIT: Once = ONCE_INIT;

#[derive(Debug)]
pub enum Error {
    CouldNotReadKey,
    KexInit,
    Version,
    Kex,
    DH,
    PacketAuth,
    NewKeys,
    Inconsistent,
    IO(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}

mod negociation;
use negociation::*;
mod msg;
mod kex;

mod cipher;
pub mod key;

mod mac;
use mac::*;


mod compression;

mod encoding;

pub mod server;
pub mod client;

#[derive(Debug)]
struct SSHBuffers {
    recv_seqn: usize,
    sent_seqn: usize,

    read_buffer: CryptoBuf,
    read_len: usize, // next packet length.
    write_buffer: CryptoBuf,
    write_position: usize, // first position of non-written suffix.

    read_bytes: usize,
    written_bytes: usize,
    last_rekey_s: f64,
}

impl SSHBuffers {
    fn new() -> Self {
        SSHBuffers {
            recv_seqn: 0,
            sent_seqn: 0,

            read_len: 0,
            read_buffer: CryptoBuf::new(),
            write_buffer: CryptoBuf::new(),
            write_position: 0,

            read_bytes: 0,
            written_bytes: 0,
            last_rekey_s: time::precise_time_s(),
        }
    }
    // Returns true iff the write buffer has been completely written.
    pub fn write_all<W: std::io::Write>(&mut self, stream: &mut W) -> Result<bool, Error> {
        // println!("write_all");
        while self.write_position < self.write_buffer.len() {
            match self.write_buffer.write_all_from(self.write_position, stream) {
                Ok(s) => {
                    self.write_position += s;
                    self.written_bytes += s;
                    try!(stream.flush());
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(false); // need more bytes
                    } else {
                        return Err(Error::IO(e));
                    }
                }
            }
        }
        // println!("flushed");
        Ok(true)
    }
}

#[derive(Debug)]
pub struct Exchange {
    client_id: Vec<u8>,
    server_id: Vec<u8>,
    client_kex_init: Vec<u8>,
    server_kex_init: Vec<u8>,
    client_ephemeral: Vec<u8>,
    server_ephemeral: Vec<u8>,
}

impl Exchange {
    fn new() -> Self {
        Exchange {
            client_id: Vec::new(),
            server_id: Vec::new(),
            client_kex_init: Vec::new(),
            server_kex_init: Vec::new(),
            client_ephemeral: Vec::new(),
            server_ephemeral: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Kex {
    KexInit(KexInit), /* Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively. */
    KexDh(KexDh), // Algorithms have been determined, the DH algorithm should run.
    KexDhDone(KexDhDone), // The kex has run.
    NewKeys(NewKeys), /* The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side. */
}

#[derive(Debug)]
pub struct KexInit {
    pub algo: Option<negociation::Names>,
    pub exchange: Exchange,
    pub session_id: Option<kex::Digest>,
    pub sent: bool
}

impl KexInit {
    pub fn kexinit(self) -> Result<Kex, Error> {
        if !self.sent {
            Ok(Kex::KexInit(self))
        } else {
            if let Some((kex,key,cipher,mac,follows)) = self.algo {

                Ok(Kex::KexDh(KexDh {
                    exchange:self.exchange,
                    kex:kex, key:key,
                    cipher:cipher, mac:mac, follows:follows,
                    session_id: self.session_id
                }))
            } else {
                Err(Error::Kex)
            }
        }
    }
}

#[derive(Debug)]
pub struct KexDh {
    exchange: Exchange,
    kex: kex::Name,
    key: key::Algorithm,
    cipher: cipher::Name,
    mac: Mac,
    session_id: Option<kex::Digest>,
    follows: bool,
}

#[derive(Debug)]
pub struct KexDhDone {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Name,
    mac: Mac,
    session_id: Option<kex::Digest>,
    follows: bool,
}

impl KexDhDone {
    fn compute_keys(mut self,
                    hash: kex::Digest,
                    buffer: &mut CryptoBuf,
                    buffer2: &mut CryptoBuf)
                    -> NewKeys {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = self.kex.compute_keys(&session_id, &hash, buffer, buffer2, &mut self.cipher);
        NewKeys {
            exchange: self.exchange,
            kex: self.kex,
            key: self.key,
            cipher: c,
            mac: self.mac,
            session_id: session_id,
        }
    }
}

#[derive(Debug)]
pub struct NewKeys {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
}

impl NewKeys {
    fn encrypted<T, EncryptedState>(self, state:EncryptedState) -> Encrypted<T, EncryptedState> {
        Encrypted {
            exchange: Some(self.exchange),
            kex: self.kex,
            key: self.key,
            cipher: self.cipher,
            mac: self.mac,
            session_id: self.session_id,
            state: Some(state),
            rekey: None,
            channels: HashMap::new(),
        }
    }
}


pub struct Encrypted<T,EncryptedState> {
    exchange: Option<Exchange>, // It's always Some, except when we std::mem::replace it temporarily.
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
    state: Option<EncryptedState>,
    rekey: Option<Kex>,
    channels: HashMap<u32, Channel<T>>,
}
#[derive(Debug)]
pub struct ChannelParameters {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

pub struct Channel<S> {
    pub parameters: ChannelParameters,
    pub stdout: CryptoBuf,
    pub stderr: CryptoBuf,
    pub server: S,
}


/// Fills the read buffer, and returns whether a complete message has been read.
///
/// It would be tempting to return either a slice of `stream`, or a
/// slice of `read_buffer`, but except for a very small number of
/// messages, we need double buffering anyway to decrypt in place on
/// `read_buffer`.
fn read<R: BufRead>(stream: &mut R,
                    read_buffer: &mut CryptoBuf,
                    read_len: usize,
                    bytes_read: &mut usize)
                    -> Result<bool, Error> {
    // This loop consumes something or returns, it cannot loop forever.
    loop {
        let consumed_len = match stream.fill_buf() {
            Ok(buf) => {
                // println!("read {:?}", buf);
                if read_buffer.len() + buf.len() < read_len + 4 {

                    read_buffer.extend(buf);
                    buf.len()

                } else {
                    let consumed_len = read_len + 4 - read_buffer.len();
                    read_buffer.extend(&buf[0..consumed_len]);
                    consumed_len
                }
            }
            Err(e) => {
                // println!("error :{:?}", e);
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // println!("would block");
                    return Ok(false);
                } else {
                    return Err(Error::IO(e));
                }
            }
        };
        stream.consume(consumed_len);
        *bytes_read += consumed_len;
        if read_buffer.len() >= 4 + read_len {
            return Ok(true);
        }
    }
}


const KEYTYPE_ED25519:&'static [u8] = b"ssh-ed25519";

pub fn read_public_key<P:AsRef<Path>>(p:P) -> Result<sodium::ed25519::PublicKey, Error> {

    let pubkey_regex = Regex::new(r"ssh-\S*\s*(?P<key>\S+)\s*").unwrap();
    let mut pubkey = String::new();
    let mut file = File::open(p.as_ref()).unwrap();
    file.read_to_string(&mut pubkey).unwrap();
    let p = pubkey_regex.captures(&pubkey).unwrap().name("key").unwrap().from_base64().unwrap();

    let mut pos = Position { s:&p,position:0 };
    if pos.read_string() == b"ssh-ed25519" {
        let pubkey = pos.read_string();
        Ok(sodium::ed25519::PublicKey::copy_from_slice(pubkey))
    } else {
        Err(Error::CouldNotReadKey)
    }
}

pub fn read_secret_key<P:AsRef<Path>>(p:P) -> Result<sodium::ed25519::SecretKey, Error> {

    let file = File::open(p.as_ref()).unwrap();
    let file = BufReader::new(file);

    let mut secret = String::new();
    let mut started = false;

    for l in file.lines() {
        let l = try!(l);
        if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
            started = true
        } else if l == "-----END OPENSSH PRIVATE KEY-----" {
            break
        } else if started {
            secret.push_str(&l)
        }
    }
    let secret = secret.from_base64().unwrap();
    //println!("secret: {:?} {:?}", secret, secret.len());
    //println!("secret: {:?}", std::str::from_utf8(&secret[0..62]));

    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = Position { s:&secret, position:15 };

        let ciphername = position.read_string();
        let kdfname = position.read_string();
        let kdfoptions = position.read_string();
        info!("ciphername: {:?}", std::str::from_utf8(ciphername));
        debug!("kdf: {:?} {:?}",
                 std::str::from_utf8(kdfname),
                 std::str::from_utf8(kdfoptions));

        let nkeys = position.read_u32();
        
        for _ in 0..nkeys {
            let public_string = position.read_string();
            let mut pos = Position { s:public_string, position:0 };
            if pos.read_string() == KEYTYPE_ED25519 {
                // println!("{:?} {:?}", secret, secret.len());
                let public = sodium::ed25519::PublicKey::copy_from_slice(pos.read_string());
                info!("public: {:?}", public);
            }
        }
        info!("there are {} keys in this file", nkeys);
        let secret = position.read_string();
        if kdfname == b"none" {
            let mut position = Position { s: secret, position: 0 };
            let check0 = position.read_u32();
            let check1 = position.read_u32();
            debug!("check0: {:?}", check0);
            debug!("check1: {:?}", check1);
            for _ in 0..nkeys {

                let key_type = position.read_string();
                if key_type == KEYTYPE_ED25519 {
                    let pubkey = position.read_string();
                    debug!("pubkey = {:?}", pubkey);
                    let seckey = position.read_string();
                    let comment = position.read_string();
                    debug!("comment = {:?}", comment);
                    let secret = sodium::ed25519::SecretKey::copy_from_slice(seckey);
                    return Ok(secret)
                } else {
                    info!("unsupported key type {:?}", std::str::from_utf8(key_type));
                }
            }
            Err(Error::CouldNotReadKey)
        } else {
            info!("unsupported secret key cipher: {:?}", std::str::from_utf8(kdfname));
            Err(Error::CouldNotReadKey)
        }
    } else {
        Err(Error::CouldNotReadKey)
    }
}

struct Position<'a> { s:&'a[u8], position: usize }
impl<'a> Position<'a> {
    fn read_string(&mut self) -> &'a[u8] {

        let len = BigEndian::read_u32(&self.s[self.position..]) as usize;
        let result = &self.s[(self.position+4)..(self.position+4+len)];
        self.position += 4+len;
        result
    }
    fn read_u32(&mut self) -> u32 {

        let u = BigEndian::read_u32(&self.s[self.position..]);
        self.position += 4;
        u
    }
}
