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
use std::collections::{HashMap};


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
    HUP,
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
use encoding::*;

pub mod auth;

pub mod server;
pub mod client;

#[derive(Debug)]
pub struct SSHBuffers {
    read: SSHBuffer,
    write: SSHBuffer,
    last_rekey_s: f64,
}

#[derive(Debug)]
pub struct SSHBuffer {
    buffer: CryptoBuf,
    len: usize, // next packet length.
    bytes: usize,
    seqn: usize,
}
impl SSHBuffer {
    fn new() -> Self {
        SSHBuffer {
            buffer:CryptoBuf::new(),
            len:0,
            bytes:0,
            seqn:0
        }
    }
    fn clear(&mut self) {
        self.len = 0;
        self.buffer.clear();
    }
    fn clear_incr(&mut self) {
        self.len = 0;
        self.buffer.clear();
        self.seqn += 1
    }
}
impl SSHBuffers {
    fn new() -> Self {
        SSHBuffers {
            read: SSHBuffer::new(),
            write: SSHBuffer::new(),
            last_rekey_s: time::precise_time_s(),
        }
    }
    // Returns true iff the write buffer has been completely written.
    pub fn write_all<W: std::io::Write>(&mut self, stream: &mut W) -> Result<bool, Error> {
        // println!("write_all");
        while self.write.len < self.write.buffer.len() {
            match self.write.buffer.write_all_from(self.write.len, stream) {
                Ok(s) => {
                    self.write.len += s;
                    self.write.bytes += s;
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
                self.read.buffer.clear();
                self.read.bytes += i+2;
                self.read.buffer.extend(&buf[0..i+2]);
                i

            } else {
                return Err(Error::Version)
            }
        };
        stream.consume(i+2);
        Ok(Some(&self.read.buffer.as_slice()[0..i]))
    }
    pub fn send_ssh_id<W:std::io::Write>(&mut self, stream:&mut W, id:&[u8]) -> Result<(), Error> {
        self.write.buffer.extend(id);
        self.write.buffer.push(b'\r');
        self.write.buffer.push(b'\n');
        try!(self.write_all(stream));
        Ok(())
    }
    pub fn cleartext_write_kex_init<W: Write>(
        &mut self,
        keys: &[key::Algorithm],
        is_server: bool,
        mut kexinit: KexInit,
        stream: &mut W)
        -> Result<ServerState, Error> {

        if !kexinit.sent {
            // println!("kexinit");
            self.write.buffer.extend(b"\0\0\0\0\0");
            negociation::write_kex(&keys, &mut self.write.buffer);

            {
                let buf = self.write.buffer.as_slice();
                if is_server {
                    kexinit.exchange.server_kex_init.extend(&buf[5..]);
                } else {
                    kexinit.exchange.client_kex_init.extend(&buf[5..]);
                }
            }

            complete_packet(&mut self.write.buffer, 0);
            self.write.seqn += 1;
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
        debug_assert!(self.read.len == 0);
        // Packet lengths are always multiples of 8, so is a StreamBuf.
        // Therefore, this can never block.
        self.read.buffer.clear();
        try!(self.read.buffer.read(4, stream));

        self.read.len = self.read.buffer.read_u32_be(0) as usize;
        // println!("clear_len: {:?}", self.read_len);
        Ok(())
    }

    fn get_current_payload<'b>(&'b mut self) -> &'b [u8] {
        let packet_length = self.read.buffer.read_u32_be(0) as usize;
        let padding_length = self.read.buffer[4] as usize;

        let buf = self.read.buffer.as_slice();
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
                    if self.read.buffer.len() + buf.len() < self.read.len + 4 {

                        self.read.buffer.extend(buf);
                        buf.len()

                    } else {
                        let consumed_len = self.read.len + 4 - self.read.buffer.len();
                        self.read.buffer.extend(&buf[0..consumed_len]);
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
            self.read.bytes += consumed_len;
            if self.read.buffer.len() >= 4 + self.read.len {
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


pub enum ServerState {
    VersionOk(Exchange),
    Kex(Kex),
    Encrypted(Encrypted), // Session is now encrypted.
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

    pub fn rekey(ex:Exchange, algo:Names, session_id:&kex::Digest) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: Some(algo),
            sent: false,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
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

    fn client_compute_exchange_hash(&mut self, payload:&[u8], buffer:&mut CryptoBuf) -> Result<kex::Digest, Error> {
        assert!(payload[0] == msg::KEX_ECDH_REPLY);
        let mut reader = payload.reader(1);

        let pubkey = reader.read_string().unwrap();
        let server_ephemeral = reader.read_string().unwrap();
        self.exchange.server_ephemeral.extend(server_ephemeral);
        let signature = reader.read_string().unwrap();

        try!(self.kex.compute_shared_secret(&self.exchange.server_ephemeral));

        let pubkey = try!(read_public_key(pubkey));
        let hash = try!(self.kex.compute_exchange_hash(&pubkey,
                                                       &self.exchange,
                                                       buffer));

        let signature = {
            let mut sig_reader = signature.reader(0);
            let sig_type = sig_reader.read_string().unwrap();
            assert_eq!(sig_type, b"ssh-ed25519");
            let signature = sig_reader.read_string().unwrap();
            sodium::ed25519::Signature::copy_from_slice(signature)
        };

        match pubkey {
            key::PublicKey::Ed25519(ref pubkey) => {

                assert!(sodium::ed25519::verify_detached(&signature, hash.as_bytes(), pubkey))

            }
        };
        println!("signature = {:?}", signature);
        println!("exchange = {:?}", self.exchange);
        Ok(hash)
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
    fn encrypted(self, state:EncryptedState) -> Encrypted {
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


pub struct Encrypted {
    exchange: Option<Exchange>, // It's always Some, except when we std::mem::replace it temporarily.
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
    state: Option<EncryptedState>,
    rekey: Option<Kex>,
    channels: HashMap<u32, ChannelParameters>,
}

impl Encrypted {

    fn server_read_rekey(&mut self, buf:&[u8], keys:&[key::Algorithm]) -> Result<bool, Error> {
        if buf[0] == msg::KEXINIT {
            match std::mem::replace(&mut self.rekey, None) {
                Some(Kex::KexInit(mut kexinit)) => {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::read_kex(buf, keys)));
                    }
                    kexinit.exchange.client_kex_init.extend(buf);
                    self.rekey = Some(try!(kexinit.kexinit()));
                    Ok(true)
                },
                None => {
                    // start a rekeying
                    let mut kexinit = KexInit::rekey(
                        std::mem::replace(&mut self.exchange, None).unwrap(),
                        try!(negociation::read_kex(buf, &keys)),
                        &self.session_id
                    );
                    kexinit.exchange.client_kex_init.extend(buf);
                    self.rekey = Some(try!(kexinit.kexinit()));
                    Ok(true)
                },
                _ => {
                    // Error, maybe?
                    // unimplemented!()
                    Ok(true)
                }
            }
        } else {

            let packet_matches = match self.rekey {
                Some(Kex::KexDh(_)) if buf[0] == msg::KEX_ECDH_INIT => true,
                Some(Kex::NewKeys(_)) if buf[0] == msg::NEWKEYS => true,
                _ => false
            };
            debug!("packet_matches: {:?}", packet_matches);
            if packet_matches {
                let rekey = std::mem::replace(&mut self.rekey, None);
                match rekey {
                    Some(Kex::KexDh(mut kexdh)) => {
                        debug!("KexDH");
                        let kex = {
                            kexdh.exchange.client_ephemeral.extend(&buf[5..]);
                            try!(kexdh.kex.server_dh(&mut kexdh.exchange, buf))
                        };
                        self.rekey = Some(Kex::KexDhDone(KexDhDone {
                            exchange: kexdh.exchange,
                            kex: kex,
                            key: kexdh.key,
                            cipher: kexdh.cipher,
                            mac: kexdh.mac,
                            follows: kexdh.follows,
                            session_id: kexdh.session_id,
                        }));
                        Ok(true)
                    },
                    Some(Kex::NewKeys(kexinit)) => {
                        debug!("NewKeys");
                        if buf[0] == msg::NEWKEYS {
                            self.exchange = Some(kexinit.exchange);
                            self.kex = kexinit.kex;
                            self.key = kexinit.key;
                            self.cipher = kexinit.cipher;
                            self.mac = kexinit.mac;
                        } else {
                            self.rekey = Some(Kex::NewKeys(kexinit))
                        }
                        Ok(true)
                    },
                    _ => {
                        Ok(true)
                    }
                }
            } else {
                Ok(false)
            }
        }
    }


    fn server_write_rekey<W:Write>(&mut self, stream:&mut W, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf, buffers:&mut SSHBuffers, keys:&[key::Algorithm], rekey: Kex) -> Result<(),Error> {
        match rekey {
            Kex::KexInit(mut kexinit) => {
                if !kexinit.sent {
                    debug!("sending kexinit");
                    buffer.clear();
                    negociation::write_kex(keys, buffer);
                    kexinit.exchange.server_kex_init.extend(buffer.as_slice());

                    self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                    buffers.write.seqn += 1;
                    try!(buffers.write_all(stream));
                    kexinit.sent = true;
                }
                if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                    debug!("rekey ok");
                    self.rekey = Some(Kex::KexDh(KexDh {
                        exchange: kexinit.exchange,
                        kex: kex,
                        key: key,
                        cipher: cipher,
                        mac: mac,
                        follows: follows,
                        session_id: kexinit.session_id,
                    }))
                } else {
                    debug!("still kexinit");
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            },
            Kex::KexDh(kexinit) => {
                // Nothing to do here.
                self.rekey = Some(Kex::KexDh(kexinit))
            },
            Kex::KexDhDone(kexdhdone) => {

                debug!("kexdhdone: {:?}", kexdhdone);

                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                    &kexdhdone.exchange,
                                                                    buffer));

                // http://tools.ietf.org/html/rfc5656#section-4
                buffer.clear();
                buffer.push(msg::KEX_ECDH_REPLY);
                kexdhdone.key.public_host_key.extend_pubkey(buffer);
                // Server ephemeral
                buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                // Hash signature
                kexdhdone.key.add_signature(buffer, hash.as_bytes());
                //
                self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                buffers.write.seqn += 1;

                
                buffer.clear();
                buffer.push(msg::NEWKEYS);
                self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                buffers.write.seqn += 1;

                try!(buffers.write_all(stream));
                debug!("new keys");
                let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                self.rekey = Some(Kex::NewKeys(new_keys));

            },
            Kex::NewKeys(n) => {
                self.rekey = Some(Kex::NewKeys(n));
            }
        }
        Ok(())
    }
}


#[derive(Debug)]
pub struct ChannelParameters {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
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
    let mut pos = p.reader(0);
    if pos.read_string() == Some(b"ssh-ed25519") {
        if let Some(pubkey) = pos.read_string() {
            return Ok(key::PublicKey::Ed25519(sodium::ed25519::PublicKey::copy_from_slice(pubkey)))
        }
    }
    Err(Error::CouldNotReadKey)
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
        let mut position = secret.reader(15);

        let ciphername = position.read_string().unwrap();
        let kdfname = position.read_string().unwrap();
        let kdfoptions = position.read_string().unwrap();
        info!("ciphername: {:?}", std::str::from_utf8(ciphername));
        debug!("kdf: {:?} {:?}",
                 std::str::from_utf8(kdfname),
                 std::str::from_utf8(kdfoptions));

        let nkeys = position.read_u32().unwrap();
        
        for _ in 0..nkeys {
            let public_string = position.read_string().unwrap();
            let mut pos = public_string.reader(0);
            if pos.read_string() == Some(KEYTYPE_ED25519) {
                // println!("{:?} {:?}", secret, secret.len());
                if let Some(pubkey) = pos.read_string() {
                    let public = sodium::ed25519::PublicKey::copy_from_slice(pubkey);
                    info!("public: {:?}", public);
                } else {
                    info!("warning: no public key");
                }
            }
        }
        info!("there are {} keys in this file", nkeys);
        let secret = position.read_string().unwrap();
        if kdfname == b"none" {
            let mut position = secret.reader(0);
            let check0 = position.read_u32().unwrap();
            let check1 = position.read_u32().unwrap();
            debug!("check0: {:?}", check0);
            debug!("check1: {:?}", check1);
            for _ in 0..nkeys {

                let key_type = position.read_string().unwrap();
                if key_type == KEYTYPE_ED25519 {
                    let pubkey = position.read_string().unwrap();
                    debug!("pubkey = {:?}", pubkey);
                    let seckey = position.read_string().unwrap();
                    let comment = position.read_string().unwrap();
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
