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
use std::io::{Read, Write, BufRead, BufReader};


use byteorder::{ByteOrder, BigEndian};
use regex::Regex;
use rustc_serialize::base64::{FromBase64};
use std::path::Path;
use std::fs::File;
use std::collections::{HashMap, HashSet};

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

pub mod auth;

pub mod server;
pub mod client;

#[derive(Debug)]
pub struct SSHBuffers {
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

    pub fn read_ssh_id<'a, R: BufRead>(&'a mut self, stream: &'a mut R) -> Result<Option<&'a [u8]>, Error> {
        let i = {
            let buf = try!(stream.fill_buf());
            let mut i = 0;
            while i < buf.len() - 1 {
                if &buf[i..i + 2] == b"\r\n" {
                    break;
                }
                i += 1
            }
            if buf.len() <= 8 || i >= buf.len() - 1 {
                // Not enough bytes. Don't consume, wait until we have more bytes. The buffer is larger than 255 anyway.
                return Ok(None);
            }
            if &buf[0..8] == b"SSH-2.0-" {
                self.read_buffer.clear();
                self.read_bytes += i+2;
                self.read_buffer.extend(&buf[0..i+2]);
                i

            } else {
                return Err(Error::Version)
            }
        };
        stream.consume(i+2);
        Ok(Some(&self.read_buffer.as_slice()[0..i]))
    }
    pub fn send_ssh_id<W:std::io::Write>(&mut self, stream:&mut W, id:&[u8]) -> Result<(), Error> {
        self.write_buffer.extend(id);
        self.write_buffer.push(b'\r');
        self.write_buffer.push(b'\n');
        try!(self.write_all(stream));
        Ok(())
    }
    pub fn cleartext_write_kex_init<S,W: Write>(&mut self,
                                                keys: &[key::Algorithm],
                                                is_server: bool,
                                                mut kexinit: KexInit,
                                                stream: &mut W)
                                                -> Result<ServerState<S>, Error> {
        if !kexinit.sent {
            // println!("kexinit");
            self.write_buffer.extend(b"\0\0\0\0\0");
            negociation::write_kex(&keys, &mut self.write_buffer);

            {
                let buf = self.write_buffer.as_slice();
                if is_server {
                    kexinit.exchange.server_kex_init.extend(&buf[5..]);
                } else {
                    kexinit.exchange.client_kex_init.extend(&buf[5..]);
                }
            }

            complete_packet(&mut self.write_buffer, 0);
            self.sent_seqn += 1;
            try!(self.write_all(stream));
            kexinit.sent = true;
        }
        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
            Ok(ServerState::Kex(Kex::KexDh(KexDh {
                exchange: kexinit.exchange,
                kex: kex,
                key: key,
                cipher: cipher,
                mac: mac,
                follows: follows,
                session_id: kexinit.session_id,
            })))
        } else {
            Ok(ServerState::Kex(Kex::KexInit(kexinit)))
        }

    }
    fn set_clear_len<R: BufRead>(&mut self, stream: &mut R) -> Result<(), Error> {
        debug_assert!(self.read_len == 0);
        // Packet lengths are always multiples of 8, so is a StreamBuf.
        // Therefore, this can never block.
        self.read_buffer.clear();
        try!(self.read_buffer.read(4, stream));

        self.read_len = self.read_buffer.read_u32_be(0) as usize;
        // println!("clear_len: {:?}", self.read_len);
        Ok(())
    }

    fn get_current_payload<'b>(&'b mut self) -> &'b [u8] {
        let packet_length = self.read_buffer.read_u32_be(0) as usize;
        let padding_length = self.read_buffer[4] as usize;

        let buf = self.read_buffer.as_slice();
        let payload = {
            &buf[5..(4 + packet_length - padding_length)]
        };
        // println!("payload : {:?} {:?} {:?}", payload.len(), padding_length, packet_length);
        payload
    }

    /// Fills the read buffer, and returns whether a complete message has been read.
    ///
    /// It would be tempting to return either a slice of `stream`, or a
    /// slice of `read_buffer`, but except for a very small number of
    /// messages, we need double buffering anyway to decrypt in place on
    /// `read_buffer`.
    fn read<R: BufRead>(&mut self, stream: &mut R) -> Result<bool, Error> {
        // This loop consumes something or returns, it cannot loop forever.
        loop {
            let consumed_len = match stream.fill_buf() {
                Ok(buf) => {
                    // println!("read {:?}", buf);
                    if self.read_buffer.len() + buf.len() < self.read_len + 4 {

                        self.read_buffer.extend(buf);
                        buf.len()

                    } else {
                        let consumed_len = self.read_len + 4 - self.read_buffer.len();
                        self.read_buffer.extend(&buf[0..consumed_len]);
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
            self.read_bytes += consumed_len;
            if self.read_buffer.len() >= 4 + self.read_len {
                return Ok(true);
            }
        }
    }

}

fn complete_packet(buf: &mut CryptoBuf, off: usize) {

    let block_size = 8; // no MAC yet.
    let padding_len = {
        (block_size - ((buf.len() - off) % block_size))
    };
    let padding_len = if padding_len < 4 {
        padding_len + block_size
    } else {
        padding_len
    };
    let mac_len = 0;

    let packet_len = buf.len() - off - 4 + padding_len + mac_len;
    {
        let buf = buf.as_mut_slice();
        BigEndian::write_u32(&mut buf[off..], packet_len as u32);
        buf[off + 4] = padding_len as u8;
    }


    let mut padding = [0; 256];
    sodium::randombytes::into(&mut padding[0..padding_len]);

    buf.extend(&padding[0..padding_len]);

}


pub enum ServerState<T> {
    VersionOk(Exchange),
    Kex(Kex),
    Encrypted(Encrypted<T, EncryptedState>), // Session is now encrypted.
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest,
    ServiceRequest,
    WaitingAuthRequest(auth::AuthRequest),
    RejectAuthRequest(auth::AuthRequest),
    WaitingSignature(auth::AuthRequest),
    AuthRequestSuccess(auth::AuthRequest),
    WaitingChannelOpen,
    ChannelOpenConfirmation(ChannelParameters),
    ChannelOpened(u32) // (HashSet<u32>),
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
            received: false,
            sent: false
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
    received:bool,
    sent:bool
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
    pub engine: S, // might be client or server
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

pub fn load_public_key<P:AsRef<Path>>(p:P) -> Result<key::PublicKey, Error> {

    let pubkey_regex = Regex::new(r"ssh-\S*\s*(?P<key>\S+)\s*").unwrap();
    let mut pubkey = String::new();
    let mut file = File::open(p.as_ref()).unwrap();
    file.read_to_string(&mut pubkey).unwrap();
    let p = pubkey_regex.captures(&pubkey).unwrap().name("key").unwrap().from_base64().unwrap();
    read_public_key(&p)
}

pub fn read_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
    let mut pos = Position { s:p,position:0 };
    if pos.read_string() == b"ssh-ed25519" {
        let pubkey = pos.read_string();
        Ok(key::PublicKey::Ed25519(sodium::ed25519::PublicKey::copy_from_slice(pubkey)))
    } else {
        Err(Error::CouldNotReadKey)
    }
}

pub fn load_secret_key<P:AsRef<Path>>(p:P) -> Result<key::SecretKey, Error> {

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
                    return Ok(key::SecretKey::Ed25519(secret))
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
