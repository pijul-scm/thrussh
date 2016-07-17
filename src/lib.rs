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
//! crates.io. More information [here](https://pijul.org/thrussh).
//!
//! Here is an example, using `Vec`s as instances of `Read` and `Write`, instead of network sockets.
//!
//!```
//! use thrussh::key;
//! use thrussh::auth;
//! use thrussh::server;
//! use thrussh::client;
//! use std::sync::Arc;
//! use thrussh::{Client,Server,CryptoBuf};
//! let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//! let server_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//!
//! // Server instance
//!
//! struct S<'p> {
//!     client_pubkey: &'p key::PublicKey
//! }
//! impl<'p> Server for S<'p> {
//!     fn auth(&self, _:auth::M, method:&auth::Method<key::PublicKey>) -> auth::Auth {
//!         match *method {
//!             auth::Method::PublicKey { ref user, ref public_key }
//!               if *user == "pe" && public_key == self.client_pubkey=> {
//!                 // If the user and public key match, accept the public key.
//!                 auth::Auth::Success
//!             },
//!             _ =>
//!                 // Else, reject and provide no other methods.
//!                 auth::Auth::Reject {
//!                     partial_success:false, remaining_methods:
//!                     auth::M::empty()
//!                 }
//!         }
//!     }
//! }
//!
//! // Client instance
//!
//! struct C<'p> {
//!     server_pk: &'p key::PublicKey
//! }
//! impl<'p> Client for C<'p> {
//!     fn check_server_key(&self, server_pk:&key::PublicKey) -> bool {
//!
//!         // This is an important part of the protocol: check the
//!         // server's public key against the known one, to help prevent
//!         // man-in-the-middle attacks.
//!
//!         self.server_pk == server_pk
//!     }
//! }
//!
//! 
//! // Initialize the server
//! 
//! let server_config = {
//!     let mut config:server::Config = Default::default();
//!     config.keys.push(server_keypair.clone());
//!     Arc::new(config)
//! };

//! let mut server = S{
//!     client_pubkey: &client_keypair.public_key()
//! };
//! let mut server_session = server::Connection::new(server_config.clone());
//!
//!
//! // Initialize the client
//! 
//! let client_config = Arc::new(Default::default());

//! let mut client = C{
//!     server_pk: &server_keypair.public_key()
//! };
//! let mut client_session = client::Connection::new(client_config);
//! client_session.authenticate(
//!     auth::Method::PublicKey { user:"pe", public_key: client_keypair }
//! );
//!
//!
//! // Now, run the protocol (it is obviously more useful when the
//! // instances of Read and Write are networks sockets instead of Vec).
//!
//!
//! // Fake sockets.
//! let mut server_read:Vec<u8> = Vec::new();
//! let mut server_write:Vec<u8> = Vec::new();
//!
//! // The server and client need extra workspace, we allocate these here.
//! let mut buffer0 = CryptoBuf::new();
//! let mut buffer1 = CryptoBuf::new();
//!
//! let mut run_protocol = |client_session:&mut client::Connection| {
//!     {
//!         let mut swrite = &server_write[..];
//!         client_session.read(&mut client, &mut swrite, &mut buffer0, &mut buffer1).unwrap();
//!     }
//!     server_write.clear();
//!     client_session.write(&mut server_read).unwrap();
//!     {
//!         let mut sread = &server_read[..];
//!         server_session.read(&mut server, &mut sread, &mut buffer0, &mut buffer1).unwrap();
//!     }
//!     server_read.clear();
//!     server_session.write(&mut server_write).unwrap();
//! };
//!
//! // Run the protocol until authentication is complete.
//! while !client_session.is_authenticated() {
//!     run_protocol(&mut client_session)
//! }
//!
//! // From the client, ask the server to open a channel (prepare buffers to do so).
//! let channel = client_session.session.channel_open_session().unwrap();
//!
//!
//! // Then run the protocol again, until our channel is confirmed.
//! loop {
//!     if let Some(chan) = client_session.session.channels().and_then(|x| x.get(&channel)) {
//!         if chan.confirmed {
//!             break
//!         }
//!     }
//!     run_protocol(&mut client_session);
//! }
//!
//!```


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

/// The number of bytes read/written, and the number of seconds before a key re-exchange is requested.
#[derive(Debug,Clone)]
pub struct Limits {
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
}

pub mod server;
pub mod client;

/// The type of signals that can be sent to a remote process. If you plan to use custom signals, read [the RFC](https://tools.ietf.org/html/rfc4254#section-6.10) to understand the encoding.
#[derive(Debug, Clone, Copy)]
pub enum Sig<'a> {
    ABRT,
    ALRM,
    FPE,
    HUP,
    ILL,
    INT,
    KILL,
    PIPE,
    QUIT,
    SEGV,
    TERM,
    USR1,
    Custom(&'a str)
}

impl<'a> Sig<'a> {
    fn name(&self) -> &'a str {
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
            Sig::USR1 => "USR1",
            Sig::Custom(c) => c
        }
    }
    fn from_name(name: &'a [u8]) -> Result<Sig, Error> {
        match name {
            b"ABRT" => Ok(Sig::ABRT),
            b"ALRM" => Ok(Sig::ALRM),
            b"FPE" => Ok(Sig::FPE),
            b"HUP" => Ok(Sig::HUP),
            b"ILL" => Ok(Sig::ILL),
            b"INT" => Ok(Sig::INT),
            b"KILL" => Ok(Sig::KILL),
            b"PIPE" => Ok(Sig::PIPE),
            b"QUIT" => Ok(Sig::QUIT),
            b"SEGV" => Ok(Sig::SEGV),
            b"TERM" => Ok(Sig::TERM),
            b"USR1" => Ok(Sig::USR1),
            x => Ok(Sig::Custom(try!(std::str::from_utf8(x))))
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
    fn channel_open_session(&mut self, channel: u32, session: &mut server::Session) {}

    /// Called when a new X11 channel is created.
    #[allow(unused_variables)]
    fn channel_open_x11(&mut self, channel: u32, originator_address:&str, originator_port:u32, session: &mut server::Session) {}

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(&mut self, channel: u32, connected_address:&str, connected_port:u32, originator_address:&str, originator_port:u32, session: &mut server::Session) {}

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_direct_tcpip(&mut self, channel: u32, host_to_connect:&str, port_to_connect:u32, originator_address:&str, originator_port:u32, session: &mut server::Session) {}

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

    /// The client requests a pseudo-terminal with the given specifications.
    #[allow(unused_variables)]
    fn pty_request(&mut self, channel:u32, term:&str, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, modes:&[(pty::Option, u32)], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client requests an X11 connection.
    #[allow(unused_variables)]
    fn x11_request(&mut self, channel:u32, single_connection:bool, x11_auth_protocol:&str, x11_auth_cookie:&str, x11_screen_number:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    #[allow(unused_variables)]
    fn env_request(&mut self, channel:u32, variable_name:&str, variable_value:&str, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    fn shell_request(&mut self, channel:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client sends a command to execute, to be passed to a shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    fn exec_request(&mut self, channel:u32, data: &[u8], session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client asks to start the subsystem with the given name (such as sftp).
    #[allow(unused_variables)]
    fn subsystem_request(&mut self, channel:u32, name: &str, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    fn window_change_request(&mut self, channel:u32, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client is sending a signal (usually to pass to the currently running process).
    #[allow(unused_variables)]
    fn signal(&mut self, channel: u32, signal_name: Sig, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Used for reverse-forwarding ports, see [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn tcpip_forward(&mut self, address:&str, port: u32) -> Result<(), Error> {
        Ok(())
    }

    /// Used to stop the reverse-forwarding of a port, see [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(&mut self, address:&str, port: u32) -> Result<(), Error> {
        Ok(())
    }

}


pub trait Client {

    /// Called when the server sends us an authentication banner. This is usually meant to be shown to the user, see [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for more details.
    #[allow(unused_variables)]
    fn auth_banner(&mut self, banner: &str) {}

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    fn check_server_key(&self, server_public_key: &key::PublicKey) -> bool {
        false
    }

    /// Called when the server confirmed our request to open a channel. A channel can only be written to after receiving this message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(&self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(&self, channel:u32, reason: ChannelOpenFailure, description:&str, language:&str, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server sends us data. The `extended_code` parameter is a stream identifier, `None` is usually the standard output, and `Some(1)` is the standard error. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(&mut self, channel:u32, extended_code: Option<u32>, data: &[u8], session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The server informs this client that the client may perform control-S/control-Q flow control. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(&mut self, channel: u32, client_can_do: bool, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(&mut self, channel: u32, exit_status: u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(&mut self, channel: u32, signal_name: Sig, core_dumped: bool, error_message:&str, lang_tag:&str, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `client::Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

}

/// Reason for not being able to open a channel.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ChannelOpenFailure {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

impl ChannelOpenFailure {
    fn from_u32(x:u32) -> Option<ChannelOpenFailure> {
        match x {
            1 => Some(ChannelOpenFailure::AdministrativelyProhibited),
            2 => Some(ChannelOpenFailure::ConnectFailed),
            3 => Some(ChannelOpenFailure::UnknownChannelType),
            4 => Some(ChannelOpenFailure::ResourceShortage),
            _ => None
        }
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
/*
#[cfg(test)]
mod test {
    use super::*;
    extern crate env_logger;
    use std::sync::Arc;
    
    #[test]
    fn test_session() {

        let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
        let (server_pk,server_sk) = super::sodium::ed25519::generate_keypair().unwrap();

        struct S<'p> {
            client_pubkey: &'p key::PublicKey
        }
        impl<'p> Server for S<'p> {
            fn auth(&self, _:auth::M, method:&auth::Method<key::PublicKey>) -> auth::Auth {
                match *method {
                    auth::Method::PublicKey { ref user, ref public_key } if *user == "pe" && public_key == self.client_pubkey=> {
                        auth::Auth::Success
                    },
                    _ => auth::Auth::Reject { partial_success:false, remaining_methods: auth::M::empty() }
                }
            }
        }

        struct C<'p> {
            server_pk: &'p key::PublicKey
        }
        impl<'p> Client for C<'p> {
            fn check_server_key(&self, server_pk:&key::PublicKey) -> bool {
                self.server_pk == server_pk
            }
        }
        // Initialize the server
        let server_config = {
            let mut config:server::Config = Default::default();
            // Generate keys
            config.keys.push(
                key::Algorithm::Ed25519 {
                    public: server_pk.clone(), secret: server_sk
                }
            );
            Arc::new(config)
        };

        let mut server = S{
            client_pubkey: &client_keypair.public_key()
        };
        let mut server_session = server::Connection::new(server_config.clone());

        // Initialize the client
        let client_config = Arc::new(Default::default());

        let server_pk = super::key::PublicKey::Ed25519(server_pk);
        let mut client = C{
            server_pk: &server_pk
        };
        let mut client_session = client::Connection::new(client_config);

        //

        let mut server_read:Vec<u8> = Vec::new();
        let mut server_write:Vec<u8> = Vec::new();

        let mut buffer0 = CryptoBuf::new();
        let mut buffer1 = CryptoBuf::new();

        client_session.authenticate(auth::Method::PublicKey { user:"pe", public_key: client_keypair });

        let mut run_protocol = |client_session:&mut client::Connection| {
            {
                let mut swrite = &server_write[..];
                client_session.read(&mut client, &mut swrite, &mut buffer0, &mut buffer1).unwrap();
            }
            server_write.clear();
            client_session.write(&mut server_read).unwrap();

            {
                let mut sread = &server_read[..];
                server_session.read(&mut server, &mut sread, &mut buffer0, &mut buffer1).unwrap();
            }
            server_read.clear();
            server_session.write(&mut server_write).unwrap();
        };
        
        while !client_session.is_authenticated() {
            run_protocol(&mut client_session)
        }
        let channel = client_session.session.channel_open_session().unwrap();
        client_session.flush();

        loop {
            if let Some(chan) = client_session.session.channels().and_then(|x| x.get(&channel)) {
                if chan.confirmed {
                    break
                }
            }
            run_protocol(&mut client_session);
        }
    }
}
*/
