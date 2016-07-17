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
extern crate enum_primitive;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate time;

mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;

mod sshbuffer;

use std::sync::{Once, ONCE_INIT};
use std::io::{Read, BufRead, BufReader};


use byteorder::{ByteOrder};
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;


static SODIUM_INIT: Once = ONCE_INIT;

macro_rules! push_packet {
    ( $buffer:expr, $x:expr ) => {
        {
            use byteorder::{BigEndian, ByteOrder};
            let i0 = $buffer.len();
            $buffer.extend(b"\0\0\0\0");
            let x = $x;
            let i1 = $buffer.len();
            let buf = $buffer.as_mut_slice();
            BigEndian::write_u32(&mut buf[i0..], (i1-i0-4) as u32);
            x
        }
    };
}

mod session;

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
    WrongChannel,
    UnknownChannelType,
    UnknownSignal,
    IO(std::io::Error),
    Disconnect
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
mod msg;
pub mod key;
mod kex;

mod cipher;

// mod mac;
// use mac::*;
// mod compression;

mod encoding;
use encoding::*;

pub mod auth;

#[derive(Debug,Clone)]
pub struct Limits {
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
}

pub mod server;
pub mod client;

#[derive(Debug)]
pub enum ChannelType<'a> {
    Session,
    X11 { originator_address: &'a str, originator_port: u32 },
    ForwardedTcpip { connected_address: &'a str, connected_port: u32, originator_address: &'a str, originator_port: u32 },
    DirectTcpip { host_to_connect: &'a str, port_to_connect: u32, originator_address: &'a str, originator_port: u32 }
}


#[derive(Debug, Clone, Copy)]
pub enum Sig {
    ABRT = libc::SIGABRT as isize,
    ALRM = libc::SIGALRM as isize,
    FPE = libc::SIGFPE as isize,
    HUP = libc::SIGHUP as isize,
    ILL = libc::SIGILL as isize,
    INT = libc::SIGINT as isize,
    KILL = libc::SIGKILL as isize,
    PIPE = libc::SIGPIPE as isize,
    QUIT = libc::SIGQUIT as isize,
    SEGV = libc::SIGSEGV as isize,
    TERM = libc::SIGTERM as isize,
    USR1 = libc::SIGUSR1 as isize,
}

impl Sig {
    fn name(&self) -> &'static str {
        match *self {
            Sig::ABRT => "ABRT",
            Sig::ALRM => "ALRM",
            Sig::FPE => "FPE",
            Sig::HUP => "HUP",
            Sig::ILL => "ILL",
            Sig::INT => "INT",
            Sig::KILL => "KILL",
            Sig::PIPE => "PIPE",
            Sig::QUIT => "QUIT",
            Sig::SEGV => "SEGV",
            Sig::TERM => "TERM",
            Sig::USR1 => "USR1"
        }
    }
    fn from_name(name: &[u8]) -> Option<Sig> {
        match name {
            b"ABRT" => Some(Sig::ABRT),
            b"ALRM" => Some(Sig::ALRM),
            b"FPE" => Some(Sig::FPE),
            b"HUP" => Some(Sig::HUP),
            b"ILL" => Some(Sig::ILL),
            b"INT" => Some(Sig::INT),
            b"KILL" => Some(Sig::KILL),
            b"PIPE" => Some(Sig::PIPE),
            b"QUIT" => Some(Sig::QUIT),
            b"SEGV" => Some(Sig::SEGV),
            b"TERM" => Some(Sig::TERM),
            b"USR1" => Some(Sig::USR1),
            _ => None
        }
    }
}

pub trait Server {
    /// Called to check authentication requests.
    #[allow(unused_variables)]
    fn auth(&self, methods: auth::M, method: &auth::Method<key::PublicKey>) -> auth::Auth {
        auth::Auth::Reject {
            remaining_methods: methods - method.num(),
            partial_success: false,
        }
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn new_channel(&mut self, channel: u32, channel_type: ChannelType, session: &mut server::Session) {}

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    fn data(&mut self, channel:u32, data: &[u8], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    fn extended_data(&mut self, channel:u32, code:u32, data: &[u8], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn pty_request(&mut self, channel:u32, term:&str, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, modes:&[(pty::Option, u32)], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn x11_request(&mut self, channel:u32, single_connection:bool, x11_auth_protocol:&str, x11_auth_cookie:&str, x11_screen_number:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn env_request(&mut self, channel:u32, variable_name:&str, variable_value:&str, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn shell_request(&mut self, channel:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn exec_request(&mut self, channel:u32, data: &[u8], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn subsystem_request(&mut self, channel:u32, name: &str, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn window_change_request(&mut self, channel:u32, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn tcpip_forward(&mut self, address:&str, port: u32) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn cancel_tcpip_forward(&mut self, address:&str, port: u32) -> Result<(), Error> {
        Ok(())
    }

}


pub trait Client {

    #[allow(unused_variables)]
    fn auth_banner(&mut self, banner: &str) {}

    #[allow(unused_variables)]
    fn check_server_key(&self, server_public_key: &key::PublicKey) -> bool {
        false
    }

    #[allow(unused_variables)]
    fn channel_open_confirmation(&self, channel:u32, session: &mut client::Session) {}

    #[allow(unused_variables)]
    fn channel_open_failure(&self, channel:u32, reason: ChannelOpen, description:&str, language:&str, session: &mut client::Session) {}

    #[allow(unused_variables)]
    fn data(&mut self, channel: Option<u32>, data: &[u8], session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn xon_xoff(&mut self, channel: u32, client_can_do: bool, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn exit_status(&mut self, channel: u32, exit_status: u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn exit_signal(&mut self, channel: u32, signal_name: Sig, core_dumped: bool, error_message:&str, lang_tag:&str, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

}

enum_from_primitive! {
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub enum ChannelOpen {
        AdministrativelyProhibited = 1,
        ConnectFailed = 2,
        UnknownChannelType = 3,
        ResourceShortage = 4,
        
    }
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
    pub confirmed: bool,
    pub wants_reply: bool
}

const KEYTYPE_ED25519: &'static [u8] = b"ssh-ed25519";

/// Load a public key from a file. Only ed25519 keys are currently supported.
pub fn load_public_key<P: AsRef<Path>>(p: P) -> Result<key::PublicKey, Error> {

    let mut pubkey = String::new();
    let mut file = try!(File::open(p.as_ref()));
    try!(file.read_to_string(&mut pubkey));

    let mut split = pubkey.split_whitespace();

    match (split.next(), split.next()) {
        (Some(_), Some(key)) => {
            let base = try!(key.from_base64());
            read_public_key(&base)
        }
        _ => Err(Error::CouldNotReadKey),
    }
}

fn read_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
    let mut pos = p.reader(0);
    if try!(pos.read_string()) == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            return Ok(key::PublicKey::Ed25519(sodium::ed25519::PublicKey::copy_from_slice(pubkey)));
        }
    }
    Err(Error::CouldNotReadKey)
}

/// Load a secret key from a file. Only ed25519 keys are currently supported.
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
    extern crate env_logger;
    use std::sync::Arc;
    
    #[test]
    fn test_session() {
        env_logger::init().unwrap_or(());


        
        struct S {}
        impl Server for S {
            fn auth(&self, _:auth::M, _:&auth::Method<key::PublicKey>) -> auth::Auth {
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
                    public: pk.clone(), secret: sk
                }
            );
            Arc::new(config)
        };
        let client_config = Arc::new(Default::default());

        let mut server_read:Vec<u8> = Vec::new();
        let mut server_write:Vec<u8> = Vec::new();
        
        let mut server = S{};
        let mut server_session = server::Connection::new(server_config.clone());

        let mut client = C{};
        let mut client_session = client::Connection::new(client_config);

        let mut s_buffer0 = CryptoBuf::new();
        let mut s_buffer1 = CryptoBuf::new();
        let mut c_buffer0 = CryptoBuf::new();
        let mut c_buffer1 = CryptoBuf::new();


        let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
        client_session.authenticate(auth::Method::PublicKey { user:"pe",
                                                              pubkey: client_keypair });

        let mut run_loop = |client_session:&mut client::Connection| {
            {
                let mut swrite = &server_write[..];
                debug!("client read");
                client_session.read(&mut client, &mut swrite, &mut c_buffer0, &mut c_buffer1).unwrap();
            }
            server_write.clear();
            client_session.write(&mut server_read).unwrap();

            {
                let mut sread = &server_read[..];
                debug!("server read");
                server_session.read(&mut server, &mut sread, &mut s_buffer0, &mut s_buffer1).unwrap();
            }
            server_read.clear();
            server_session.write(&mut server_write).unwrap();
        };
        
        while !client_session.is_authenticated() {
            debug!("client_session: {:?}", client_session);
            run_loop(&mut client_session)
        }
        /*
        let channel = client_session.session.channel_open(ChannelType::Session).unwrap();
        client_session.flush();

        loop {
            if let Some(chan) = client_session.session.channels().and_then(|x| x.get(&channel)) {
                if chan.confirmed {
                    break
                }
            }
            run_loop(&mut client_session);
        }
        */
    }
}
