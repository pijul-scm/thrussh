// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Server and client SSH library. See the two example crates
//! [thrussh_client](https://crates.io/crates/thrussh_server) and
//! [thrussh_client](https://crates.io/crates/thrussh_client) on
//! crates.io.
//!
//! The source code for this crates and the examples is available
//! online, just follow [the instructions](https://pijul.org/thrussh).
//!
//! This library will never do much more than handling the SSH
//! protocol.  In particular, it does not run a main loop, does not
//! call external processes, and does not do its own crypto.
//!
//! If you want to implement an SSH server, create a type that
//! implements the `Server` trait, create a `server::Config`, and then for each
//! new connection, create a server session using `let s =
//! ServerSession::new()`. Then, every time new packets are available,
//! read as many packets as possible using `ServerSession::read(..)`,
//! and then write the answer using `ServerSession::write(..)`.
//!
//! Clients work almost in the same way, except if you want to provide
//! a command line interface, which needs its own event loop. See the
//! [thrussh_client](https://pijul.org) crate for an example.


extern crate libc;
extern crate libsodium_sys;
extern crate rand;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate time;

mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;

mod sshbuffer;
use sshbuffer::{SSHBuffer};

use std::sync::{Once, ONCE_INIT};
use std::io::{Read, BufRead, BufReader};


use byteorder::{ByteOrder, BigEndian};
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;


static SODIUM_INIT: Once = ONCE_INIT;
mod state;

#[derive(Debug)]
pub enum Error {
    CouldNotReadKey,
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
    WrongState,
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
impl From<rustc_serialize::base64::FromBase64Error> for Error {
    fn from(e: rustc_serialize::base64::FromBase64Error) -> Error {
        Error::Base64(e)
    }
}

mod negociation;
pub mod pty;
pub mod channel_request;
pub mod global_request;
mod msg;
pub mod key;
mod kex;

mod cipher;
use cipher::CipherT;

// mod mac;
// use mac::*;
// mod compression;

mod encoding;
use encoding::*;

pub mod auth;
macro_rules! transport {
    ( $x:expr ) => {
        {
            match $x[0] {
                msg::DISCONNECT => return Ok(ReturnCode::Disconnect),
                msg::IGNORE => return Ok(ReturnCode::Ok),
                msg::UNIMPLEMENTED => return Ok(ReturnCode::Ok),
                msg::DEBUG => return Ok(ReturnCode::Ok),
                _ => {}
            }
        }
    };
}
pub enum ReturnCode {
    Ok,
    NotEnoughBytes,
    Disconnect,
    WrongPacket,
}

pub mod server;
pub mod client;

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

pub enum ChannelRequest<'a> {
    Pty(channel_request::Pty<'a>),
    X11(channel_request::X11<'a>),
    Env(channel_request::Env<'a>),
    Shell(channel_request::Shell),
    Exec(channel_request::Exec<'a>),
    Subsystem(channel_request::Subsystem<'a>),
    WindowChange(channel_request::WindowChange),
    XonXoff(channel_request::XonXoff),
    ExitStatus(channel_request::ExitStatus),
}


pub enum ChannelType<'a> {
    Session,
    X11 { originator_address: &'a str, originator_port: u32 },
    ForwardedTcpip { connected_address: &'a str, connected_port: u32, originator_address: &'a str, originator_port: u32 },
    DirectTcpip { host_to_connect: &'a str, port_to_connect: u32, originator_address: &'a str, originator_port: u32 }
}



pub struct ChannelBuf<'a> {
    buffer: &'a mut CryptoBuf,
    channel: &'a mut ChannelParameters,
    write_buffer: &'a mut SSHBuffer,
    cipher: &'a mut cipher::CipherPair,
    wants_reply: bool,
}
impl<'a> ChannelBuf<'a> {

    fn output(&mut self, extended: Option<u32>, buf: &[u8]) -> usize {
        debug!("output {:?} {:?}", self.channel, buf);
        let mut buf = if buf.len() as u32 > self.channel.recipient_window_size {
            &buf[0..self.channel.recipient_window_size as usize]
        } else {
            buf
        };
        let buf_len = buf.len();

        while buf.len() > 0 && self.channel.recipient_window_size > 0 {

            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(),
                                    self.channel.recipient_maximum_packet_size as usize);
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
            self.buffer.extend_ssh_string(&buf[..off]);
            debug!("buffer = {:?}", self.buffer.as_slice());
            self.cipher.write(self.buffer.as_slice(), self.write_buffer);

            self.channel.recipient_window_size -= off as u32;

            buf = &buf[off..]
        }
        buf_len
    }
    pub fn stdout(&mut self, stdout: &[u8]) -> usize {
        self.output(None, stdout)
    }
    pub fn stderr(&mut self, stderr: &[u8]) -> usize {
        self.output(Some(SSH_EXTENDED_DATA_STDERR), stderr)
    }

    fn reply(&mut self, msg: u8) {
        self.buffer.clear();
        self.buffer.push(msg);
        self.buffer.push_u32_be(self.channel.recipient_channel);
        debug!("reply {:?}", self.buffer.as_slice());
        self.cipher.write(self.buffer.as_slice(), self.write_buffer);
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
}

pub trait Server {
    /// Called when a new channel is created.
    fn new_channel(&mut self, channel: u32) {}
    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    fn data(&mut self, channel:u32, data: &[u8], response: ChannelBuf) -> Result<(), Error> {
        Ok(())
    }
    fn exec(&mut self, channel:u32, data: &[u8], response: ChannelBuf) -> Result<(), Error> {
        Ok(())
    }

    fn auth(&self, methods: auth::Methods, method: &auth::Method<key::PublicKey>) -> auth::Auth {
        auth::Auth::Reject {
            remaining_methods: methods - method,
            partial_success: false,
        }
    }
}

pub trait Client {
    fn auth_banner(&mut self, _: &str) {}
    fn channel_confirmed(&self, channel:u32) {}
    fn data(&mut self, _: Option<u32>, _: &[u8], _: ChannelBuf) -> Result<(), Error> {
        Ok(())
    }
    fn check_server_key(&self, _: &key::PublicKey) -> bool {
        false
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
#[doc(hidden)]
pub struct ChannelParameters {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub recipient_window_size: u32,
    pub sender_window_size: u32,
    pub recipient_maximum_packet_size: u32,
    pub sender_maximum_packet_size: u32,
    pub confirmed: bool
}
fn adjust_window_size(write_buffer: &mut SSHBuffer,
                      cipher: &mut cipher::CipherPair,
                      target: u32,
                      buffer: &mut CryptoBuf,
                      channel: &mut ChannelParameters) {
    buffer.clear();
    buffer.push(msg::CHANNEL_WINDOW_ADJUST);
    buffer.push_u32_be(channel.recipient_channel);
    buffer.push_u32_be(target - channel.sender_window_size);
    cipher.write(buffer.as_slice(), write_buffer);
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
                if e.kind() == std::io::ErrorKind::WouldBlock {
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


const KEYTYPE_ED25519: &'static [u8] = b"ssh-ed25519";

pub fn load_public_key<P: AsRef<Path>>(p: P) -> Result<key::PublicKey, Error> {

    let mut pubkey = String::new();
    let mut file = try!(File::open(p.as_ref()));
    try!(file.read_to_string(&mut pubkey));

    let mut split = pubkey.split_whitespace();

    match (split.next(), split.next()) {
        (Some(ssh_), Some(key)) if ssh_.starts_with("ssh-") => {
            let base = try!(key.from_base64());
            read_public_key(&base)
        }
        _ => Err(Error::CouldNotReadKey),
    }
}

pub fn read_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
    let mut pos = p.reader(0);
    if try!(pos.read_string()) == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            return Ok(key::PublicKey::Ed25519(sodium::ed25519::PublicKey::copy_from_slice(pubkey)));
        }
    }
    Err(Error::CouldNotReadKey)
}

pub fn load_secret_key<P: AsRef<Path>>(p: P) -> Result<key::Algorithm, Error> {

    let file = try!(File::open(p.as_ref()));
    let file = BufReader::new(file);

    let mut secret = String::new();
    let mut started = false;

    for l in file.lines() {
        let l = try!(l);
        if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
            started = true
        } else if l == "-----END OPENSSH PRIVATE KEY-----" {
            break;
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
                    let public = sodium::ed25519::PublicKey::copy_from_slice(pubkey);
                    let secret = sodium::ed25519::SecretKey::copy_from_slice(seckey);
                    return Ok(key::Algorithm::Ed25519 { public: public, secret:secret });
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

#[cfg(test)]
mod test {
    use super::*;
    use std::io::BufReader;
    extern crate env_logger;

    #[test]
    fn test_session() {
        env_logger::init().unwrap_or(());


        
        struct S {}
        impl Server for S {
            fn auth(&self, _:auth::Methods, _:&auth::Method<key::PublicKey>) -> auth::Auth {
                auth::Auth::Success
            }
        }

        struct C {}
        impl Client for C {
            fn check_server_key(&self, _:&key::PublicKey) -> bool {
                true
            }
        }
        // Initialize the server
        let server_config = {
            let mut config:server::Config = Default::default();
            // Generate keys
            let (pk,sk) = super::sodium::ed25519::generate_keypair().unwrap();
            config.keys.push(
                key::Algorithm::Ed25519 {
                    public: pk, secret: sk
                }
            );
            config
        };
        let client_config = Default::default();

        let mut server_read:Vec<u8> = Vec::new();
        let mut server_write:Vec<u8> = Vec::new();
        
        let mut server = S{};
        let mut server_session = server::Session::new();

        let mut client = C{};
        let mut client_session = client::Session::new();

        let mut s_buffer0 = CryptoBuf::new();
        let mut s_buffer1 = CryptoBuf::new();
        let mut c_buffer0 = CryptoBuf::new();
        let mut c_buffer1 = CryptoBuf::new();


        let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
        client_session.set_method(auth::Method::PublicKey { user:"pe",
                                                            pubkey: client_keypair });

        let mut run_loop = |client_session:&mut client::Session| {
            {
                let mut swrite = &server_write[..];
                while swrite.len() > 0 {
                    client_session.read(&client_config, &mut client, &mut swrite, &mut c_buffer0, &mut c_buffer1).unwrap();
                }
            }
            server_write.clear();
            client_session.write(&client_config, &mut server_read, &mut c_buffer0).unwrap();

            {
                let mut sread = &server_read[..];
                while sread.len() > 0 {
                    server_session.read(&mut server, &server_config, &mut sread, &mut s_buffer0, &mut s_buffer1).unwrap();
                }
            }
            server_read.clear();
            server_session.write(&mut server_write).unwrap();
        };
        
        while !client_session.is_authenticated() {
            run_loop(&mut client_session)
        }

        let mut c_buffer0 = CryptoBuf::new();
        let channel = client_session.open_channel(ChannelType::Session, &client_config, &mut c_buffer0).unwrap();

        loop {
            if let Some(chan) = client_session.channels().and_then(|x| x.get(&channel)) {
                if chan.confirmed {
                    break
                }
            }
            run_loop(&mut client_session);
        }
    
        
    }
}
