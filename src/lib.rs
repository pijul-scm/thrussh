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
    Regex(regex::Error),
    Base64(rustc_serialize::base64::FromBase64Error),
    KexInit,
    Version,
    Kex,
    DH,
    PacketAuth,
    NewKeys,
    Inconsistent,
    HUP,
    IndexOutOfBounds,
    Utf8(std::str::Utf8Error),
    UnknownKey,
    IO(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}
impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf8(e)
    }
}
impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Error {
        Error::Regex(e)
    }
}
impl From<rustc_serialize::base64::FromBase64Error> for Error {
    fn from(e: rustc_serialize::base64::FromBase64Error) -> Error {
        Error::Base64(e)
    }
}

mod negociation;
use negociation::*;
mod msg;
mod kex;

mod cipher;
use cipher::CipherT;
pub mod key;

mod mac;
use mac::*;


mod compression;

mod encoding;
use encoding::*;

pub mod auth;

pub mod server;
pub mod client;

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

pub struct SignalName<'a> {
    name:&'a str
}
pub const SIGABRT:SignalName<'static> = SignalName { name:"ABRT" };
pub const SIGALRM:SignalName<'static> = SignalName { name:"ALRM" };
pub const SIGFPE:SignalName<'static> = SignalName { name:"FPE" };
pub const SIGHUP:SignalName<'static> = SignalName { name:"HUP" };
pub const SIGILL:SignalName<'static> = SignalName { name:"ILL" };
pub const SIGINT:SignalName<'static> = SignalName { name:"INT" };
pub const SIGKILL:SignalName<'static> = SignalName { name:"KILL" };
pub const SIGPIPE:SignalName<'static> = SignalName { name:"PIPE" };
pub const SIGQUIT:SignalName<'static> = SignalName { name:"QUIT" };
pub const SIGSEGV:SignalName<'static> = SignalName { name:"SEGV" };
pub const SIGTERM:SignalName<'static> = SignalName { name:"TERM" };
pub const SIGUSR1:SignalName<'static> = SignalName { name:"USR1" };

impl<'a> SignalName<'a> {
    pub fn other(name:&'a str) -> SignalName<'a> {
        SignalName { name:name }
    }
}

pub struct ChannelBuf<'a> {
    buffer:&'a mut CryptoBuf,
    channel: &'a mut ChannelParameters,
    write_buffer: &'a mut SSHBuffer,
    cipher: &'a mut cipher::CipherPair,
    wants_reply: bool
}
impl<'a> ChannelBuf<'a> {

    fn output(&mut self, extended:Option<u32>, buf:&[u8]) -> usize {
        println!("output {:?} {:?}", self.channel, buf);
        let mut buf =
            if buf.len() as u32 > self.channel.recipient_window_size {
                &buf[0..self.channel.recipient_window_size as usize]
            } else {
                buf
            };
        let buf_len = buf.len();

        while buf.len() > 0 && self.channel.recipient_window_size > 0 {

            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(), self.channel.recipient_maximum_packet_size as usize);
            let off = std::cmp::min(off, self.channel.recipient_window_size as usize);

            //
            self.buffer.clear();

            if let Some(ext) = extended {
                self.buffer.push(msg::CHANNEL_EXTENDED_DATA);
                self.buffer.push_u32_be(self.channel.recipient_channel);
                self.buffer.push_u32_be(ext);
            } else {
                self.buffer.push(msg::CHANNEL_DATA);
                self.buffer.push_u32_be(self.channel.recipient_channel);
            }
            self.buffer.extend_ssh_string(&buf [ .. off ]);
            println!("buffer = {:?}", self.buffer.as_slice());
            self.cipher.write(self.write_buffer.seqn,
                              self.buffer.as_slice(),
                              &mut self.write_buffer.buffer);

            self.channel.recipient_window_size -= off as u32;
            self.write_buffer.seqn += 1;

            buf = &buf[off..]
        }
        buf_len
    }
    pub fn stdout(&mut self, stdout:&[u8]) -> usize {
        self.output(None, stdout)
    }
    pub fn stderr(&mut self, stderr:&[u8]) -> usize {
        self.output(Some(SSH_EXTENDED_DATA_STDERR), stderr)
    }

    fn reply(&mut self, msg:u8) {
        self.buffer.clear();
        self.buffer.push(msg);
        self.buffer.push_u32_be(self.channel.recipient_channel);
        println!("reply {:?}", self.buffer.as_slice());
        self.cipher.write(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }
    pub fn success(&mut self) {
        if self.wants_reply {
            self.reply(msg::CHANNEL_SUCCESS);
            self.wants_reply = false
        }
    }
    pub fn failure(&mut self) {
        if self.wants_reply {
            self.reply(msg::CHANNEL_FAILURE);
            self.wants_reply = false
        }
    }
    pub fn eof(&mut self) {
        self.reply(msg::CHANNEL_EOF);
    }
    pub fn close(mut self) {
        self.reply(msg::CHANNEL_CLOSE);
    }
    
    pub fn exit_status(&mut self, exit_status: u32) {
        // https://tools.ietf.org/html/rfc4254#section-6.10
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_REQUEST);
        self.buffer.push_u32_be(self.channel.recipient_channel);
        self.buffer.extend_ssh_string(b"exit-status");
        self.buffer.push(0);
        self.buffer.push_u32_be(exit_status);
        self.cipher.write(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }

    pub fn exit_signal(&mut self, signal_name:SignalName, core_dumped: bool, error_message:&str, language_tag: &str) {
        // https://tools.ietf.org/html/rfc4254#section-6.10
        // Windows compatibility: we can't use Unix signal names here.
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_REQUEST);
        self.buffer.push_u32_be(self.channel.recipient_channel);
        self.buffer.extend_ssh_string(b"exit-signal");
        self.buffer.push(0);

        self.buffer.extend_ssh_string(signal_name.name.as_bytes());
        self.buffer.push(if core_dumped { 1 } else { 0 });
        self.buffer.extend_ssh_string(error_message.as_bytes());
        self.buffer.extend_ssh_string(language_tag.as_bytes());

        self.cipher.write(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }
}

pub trait Server {
    fn new_channel(&mut self, channel: &ChannelParameters);
    fn data(&mut self, _: &[u8], _: ChannelBuf) -> Result<(), Error> {
        Ok(())
    }
    fn exec(&mut self, _:&[u8], _: ChannelBuf) -> Result<(),Error> {
        Ok(())
    }
}
pub trait Client {
    fn auth_banner(&mut self, _:&str) { }
    fn new_channel(&mut self, _: &ChannelParameters) { }
    fn data(&mut self, _:Option<u32>, _: &[u8], _: ChannelBuf) -> Result<(), Error> {
        Ok(())
    }
}

pub trait ValidateKey {
    fn check_server_key(&self, key:&key::PublicKey) -> bool {
        false
    }
}

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
                self.buffer.clear();
                self.bytes += i+2;
                self.buffer.extend(&buf[0..i+2]);
                i

            } else {
                return Err(Error::Version)
            }
        };
        stream.consume(i+2);
        Ok(Some(&self.buffer.as_slice()[0..i]))
    }
    pub fn send_ssh_id(&mut self, id:&[u8]) {
        self.buffer.extend(id);
        self.buffer.push(b'\r');
        self.buffer.push(b'\n');
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
        println!("write_all, self = {:?}", self.write.buffer.as_slice());
        while self.write.len < self.write.buffer.len() {
            match self.write.buffer.write_all_from(self.write.len, stream) {
                Ok(s) => {
                    println!("written {:?} bytes", s);
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
        self.write.clear();
        self.write.len = 0;
        Ok(true)
    }

    pub fn cleartext_write_kex_init(
        &mut self,
        keys: &[key::Algorithm],
        is_server: bool,
        mut kexinit: KexInit) -> ServerState {

        if !kexinit.sent {
            // println!("kexinit");
            let pos = self.write.buffer.len();
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

            complete_packet(&mut self.write.buffer, pos);
            self.write.seqn += 1;
            kexinit.sent = true;
        }
        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
            ServerState::Kex(Kex::KexDh(KexDh {
                exchange: kexinit.exchange,
                kex: kex,
                key: key,
                cipher: cipher,
                mac: mac,
                follows: follows,
                session_id: kexinit.session_id,
            }))
        } else {
            ServerState::Kex(Kex::KexInit(kexinit))
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

#[derive(Debug)]
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
    ChannelOpened(Option<u32>) // (HashSet<u32>),
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
                    buffer2: &mut CryptoBuf,
                    is_server:bool)
                    -> NewKeys {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = self.kex.compute_keys(&session_id, &hash, buffer, buffer2, &mut self.cipher, is_server);
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

    fn client_compute_exchange_hash<C:ValidateKey>(&mut self, client:&C, payload:&[u8], buffer:&mut CryptoBuf) -> Result<kex::Digest, Error> {
        assert!(payload[0] == msg::KEX_ECDH_REPLY);
        let mut reader = payload.reader(1);

        let pubkey = try!(reader.read_string()); // server public key.
        let pubkey = try!(read_public_key(pubkey));
        if ! client.check_server_key(&pubkey) {
            return Err(Error::UnknownKey)
        }
        let server_ephemeral = try!(reader.read_string());
        self.exchange.server_ephemeral.extend(server_ephemeral);
        let signature = try!(reader.read_string());

        try!(self.kex.compute_shared_secret(&self.exchange.server_ephemeral));

        let hash = try!(self.kex.compute_exchange_hash(&pubkey,
                                                       &self.exchange,
                                                       buffer));

        let signature = {
            let mut sig_reader = signature.reader(0);
            let sig_type = try!(sig_reader.read_string());
            assert_eq!(sig_type, b"ssh-ed25519");
            let signature = try!(sig_reader.read_string());
            sodium::ed25519::Signature::copy_from_slice(signature)
        };

        match pubkey {
            key::PublicKey::Ed25519(ref pubkey) => {

                assert!(sodium::ed25519::verify_detached(&signature, hash.as_bytes(), pubkey))

            }
        };
        debug!("signature = {:?}", signature);
        debug!("exchange = {:?}", self.exchange);
        Ok(hash)
    }

}

#[derive(Debug)]
pub struct NewKeys {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::CipherPair,
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

#[derive(Debug)]
pub struct Encrypted {
    exchange: Option<Exchange>, // It's always Some, except when we std::mem::replace it temporarily.
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::CipherPair,
    mac: Mac,
    session_id: kex::Digest,
    state: Option<EncryptedState>,
    rekey: Option<Kex>,
    channels: HashMap<u32, ChannelParameters>,
}

#[derive(Debug)]
pub struct ChannelParameters {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub recipient_window_size: u32,
    pub sender_window_size: u32,
    pub recipient_maximum_packet_size: u32,
    pub sender_maximum_packet_size: u32,
}
fn adjust_window_size(write_buffer:&mut SSHBuffer, cipher:&mut cipher::CipherPair, target:u32, buffer:&mut CryptoBuf, channel:&mut ChannelParameters) {
    buffer.clear();
    buffer.push(msg::CHANNEL_WINDOW_ADJUST);
    buffer.push_u32_be(channel.recipient_channel);
    buffer.push_u32_be(target - channel.sender_window_size);
    cipher.write(write_buffer.seqn,
                 buffer.as_slice(),
                 &mut write_buffer.buffer);
    write_buffer.seqn += 1;
    channel.sender_window_size = target;
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

    let pubkey_regex = try!(Regex::new(r"ssh-\S*\s*(?P<key>\S+)\s*"));
    let mut pubkey = String::new();
    let mut file = try!(File::open(p.as_ref()));
    try!(file.read_to_string(&mut pubkey));
    if let Some(p) = pubkey_regex.captures(&pubkey).and_then(|cap| cap.name("key")).and_then(|base| base.from_base64().ok()) {
        read_public_key(&p)
    } else {
        Err(Error::CouldNotReadKey)
    }
}

pub fn read_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
    let mut pos = p.reader(0);
    if try!(pos.read_string()) == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            return Ok(key::PublicKey::Ed25519(sodium::ed25519::PublicKey::copy_from_slice(pubkey)))
        }
    }
    Err(Error::CouldNotReadKey)
}

pub fn load_secret_key<P:AsRef<Path>>(p:P) -> Result<key::SecretKey, Error> {

    let file = try!(File::open(p.as_ref()));
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
    let secret = try!(secret.from_base64());

    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = secret.reader(15);

        let ciphername = try!(position.read_string());
        let kdfname = try!(position.read_string());
        let kdfoptions = try!(position.read_string());
        info!("ciphername: {:?}", std::str::from_utf8(ciphername));
        debug!("kdf: {:?} {:?}",
                 std::str::from_utf8(kdfname),
                 std::str::from_utf8(kdfoptions));

        let nkeys = try!(position.read_u32());
        
        for _ in 0..nkeys {
            let public_string = try!(position.read_string());
            let mut pos = public_string.reader(0);
            if try!(pos.read_string()) == KEYTYPE_ED25519 {
                // println!("{:?} {:?}", secret, secret.len());
                if let Ok(pubkey) = pos.read_string() {
                    let public = sodium::ed25519::PublicKey::copy_from_slice(pubkey);
                    info!("public: {:?}", public);
                } else {
                    info!("warning: no public key");
                }
            }
        }
        info!("there are {} keys in this file", nkeys);
        let secret = try!(position.read_string());
        if kdfname == b"none" {
            let mut position = secret.reader(0);
            let check0 = try!(position.read_u32());
            let check1 = try!(position.read_u32());
            debug!("check0: {:?}", check0);
            debug!("check1: {:?}", check1);
            for _ in 0..nkeys {

                let key_type = try!(position.read_string());
                if key_type == KEYTYPE_ED25519 {
                    let pubkey = try!(position.read_string());
                    debug!("pubkey = {:?}", pubkey);
                    let seckey = try!(position.read_string());
                    let comment = try!(position.read_string());
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
