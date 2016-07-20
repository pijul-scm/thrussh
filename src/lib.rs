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
//! use std::sync::Arc;
//! use thrussh::{key, server, client, Server, Client, CryptoBuf, Error};
//! let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//! let server_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//!
//! // Server instance
//!
//! struct S {
//!     client_pubkey: key::PublicKey
//! }
//! impl Server for S {
//!     fn auth_publickey(&mut self, user:&str, publickey:&key::PublicKey) -> bool {
//!         user == "pe" && publickey == &self.client_pubkey
//!     }
//! }
//!
//! // Client instance
//!
//! struct C {
//!     server_pk: key::PublicKey,
//!     channel_confirmed: Option<u32>
//! }
//! impl Client for C {
//!     fn check_server_key(&mut self, server_pk:&key::PublicKey) -> Result<bool, Error> {
//!
//!         // This is an important part of the protocol: check the
//!         // server's public key against the known one, to help prevent
//!         // man-in-the-middle attacks.
//!
//!         Ok(&self.server_pk == server_pk)
//!     }
//!     fn channel_open_confirmation(&mut self, channel:u32, _:&mut client::Session) -> Result<(), Error> {
//!         self.channel_confirmed = Some(channel);
//!         Ok(())
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
//!     client_pubkey: client_keypair.clone_public_key()
//! };
//! let mut server_connection = server::Connection::new(server_config.clone());
//!
//!
//! // Initialize the client
//! 
//! let client_config = Arc::new(Default::default());
//!
//! let mut client = C{
//!     server_pk: server_keypair.clone_public_key(),
//!     channel_confirmed: None
//! };
//! let mut client_connection = client::Connection::new(client_config);
//! client_connection.session.set_auth_public_key("pe".to_string(), client_keypair);
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
//! let mut run_protocol = |client_connection:&mut client::Connection, client:&mut C| {
//!     {
//!         let mut swrite = &server_write[..];
//!         client_connection.read(client, &mut swrite, &mut buffer0, &mut buffer1).unwrap();
//!     }
//!     server_write.clear();
//!     client_connection.write(&mut server_read).unwrap();
//!     {
//!         let mut sread = &server_read[..];
//!         server_connection.read(&mut server, &mut sread, &mut buffer0, &mut buffer1).unwrap();
//!     }
//!     server_read.clear();
//!     server_connection.write(&mut server_write).unwrap();
//! };
//!
//! // Run the protocol until authentication is complete.
//! while !client_connection.session.is_authenticated() {
//!     run_protocol(&mut client_connection, &mut client)
//! }
//!
//! // From the client, ask the server to open a channel (prepare buffers to do so).
//! let channel = client_connection.session.channel_open_session().unwrap();
//!
//!
//! // Then run the protocol again, until our channel is confirmed.
//! loop {
//!     if client.channel_confirmed == Some(channel) { break };
//!     run_protocol(&mut client_connection, &mut client);
//! }
//!
//!```


extern crate libc;
extern crate libsodium_sys;
extern crate rand;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate time;

use std::sync::{Once, ONCE_INIT};
use std::io::{Read, BufRead, BufReader};
use byteorder::{ByteOrder};
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;
use std::borrow::Cow;

mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;

mod sshbuffer;

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
    PacketAuth,
    NewKeys,
    Inconsistent,
    IndexOutOfBounds,
    Utf8(std::str::Utf8Error),
    UnknownKey,
    WrongChannel,
    UnknownChannelType,
    UnknownSignal,
    IO(std::io::Error),
    Disconnect,
    NoHomeDir,
    KeyChanged
}

use std::error::Error as StdError;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Base64(ref e) => e.description(),
            Error::Utf8(ref e) => e.description(),
            Error::IO(ref e) => e.description(),
            Error::CouldNotReadKey => "Could not read key",
            Error::KexInit => "No common algorithms were found",
            Error::Kex => "Received invalid key exchange packet",
            Error::Version => "Invalid version string from the remote side",
            Error::PacketAuth => "Incorrect packet authentication code",
            Error::NewKeys => "No NEWKEYS packet received",
            Error::Inconsistent => "Unexpected packet",
            Error::IndexOutOfBounds => "Index out of bounds in a packet",
            Error::UnknownKey => "Unknown host key",
            Error::WrongChannel => "Inexistent channel",
            Error::UnknownChannelType => "Unknown channel type",
            Error::UnknownSignal => "Unknown signal",
            Error::Disconnect => "Disconnected",
            Error::NoHomeDir => "Home directory not found",
            Error::KeyChanged => "Server key changed"
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::Base64(ref e) => Some(e),
            Error::Utf8(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            _ => None
        }
    }
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
pub use negociation::Preferred;
mod pty;
pub use pty::Pty;
mod msg;
/// Key generation and use.
pub mod key;
mod kex;

mod cipher;

// mod mac;
// use mac::*;
// mod compression;

mod encoding;
use encoding::*;

mod auth;

/// The number of bytes read/written, and the number of seconds before a key re-exchange is requested.
#[derive(Debug,Clone)]
pub struct Limits {
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
}

pub mod server;
pub mod client;


/// A reason for disconnection.
pub enum Disconnect {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnectionss = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

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

    #[allow(unused_variables)]
    fn auth_none(&mut self, user: &str) -> bool {
        false
    }

    #[allow(unused_variables)]
    fn auth_password(&mut self, user: &str, password:&str) -> bool {
        false
    }

    #[allow(unused_variables)]
    fn auth_publickey(&mut self, user: &str, public_key:&key::PublicKey) -> bool {
        false
    }


    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    fn channel_close(&mut self, channel:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(&mut self, channel:u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when a new session channel is created.
    #[allow(unused_variables)]
    fn channel_open_session(&mut self, channel: u32, session: &mut server::Session) {}

    /// Called when a new X11 channel is created.
    #[allow(unused_variables)]
    fn channel_open_x11(&mut self, channel: u32, originator_address:&str, originator_port:u32, session: &mut server::Session) {}

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
    fn pty_request(&mut self, channel:u32, term:&str, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, modes:&[(Pty, u32)], session: &mut server::Session) -> Result<(), Error> {
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
    fn tcpip_forward(&mut self, address:&str, port: u32, session: &mut server::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Used to stop the reverse-forwarding of a port, see [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(&mut self, address:&str, port: u32, session: &mut server::Session) -> Result<(), Error> {
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
    #[allow(unused_variables)]
    fn check_server_key(&mut self, server_public_key: &key::PublicKey) -> Result<bool, Error> {
        Ok(false)
    }

    /// Called when the server confirmed our request to open a channel. A channel can only be written to after receiving this message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(&mut self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(&mut self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(&mut self, channel:u32, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(&mut self, channel:u32, reason: ChannelOpenFailure, description:&str, language:&str, session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(&mut self, channel: u32, connected_address:&str, connected_port:u32, originator_address:&str, originator_port:u32, session: &mut client::Session) {}

    /// Called when the server sends us data. The `extended_code` parameter is a stream identifier, `None` is usually the standard output, and `Some(1)` is the standard error. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(&mut self, channel:u32, extended_code: Option<u32>, data: &[u8], session: &mut client::Session) -> Result<(), Error> {
        Ok(())
    }

    /// The server informs this client of whether the client may perform control-S/control-Q flow control. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
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

/// The parameters of a channel.
#[derive(Debug)]
#[doc(hidden)]
pub struct Channel {
    recipient_channel: u32,
    sender_channel: u32,
    recipient_window_size: u32,
    sender_window_size: u32,
    recipient_maximum_packet_size: u32,
    sender_maximum_packet_size: u32,
    /// Has the other side confirmed the channel?
    pub confirmed: bool,
    wants_reply: bool
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
            parse_public_key_base64(key)
        }
        _ => Err(Error::CouldNotReadKey),
    }
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// thrussh::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key:&str) -> Result<key::PublicKey, Error> {
    let base = try!(key.from_base64());
    parse_public_key(&base)
}

pub fn parse_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
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

#[cfg(target_os = "windows")]
pub fn check_known_hosts(host:&str, port:u16, pubkey: &key::PublicKey) -> Result<bool,Error> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_known_hosts(host:&str, port:u16, pubkey: &key::PublicKey) -> Result<bool,Error> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        debug!("known_hosts file = {:?}", known_host_file);
        check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}


pub fn check_known_hosts_path<P:AsRef<Path>>(host:&str, port:u16, pubkey:&key::PublicKey, path:P) -> Result<bool, Error> {
    let mut f = BufReader::new(try!(File::open(path)));
    let mut buffer = String::new();

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{}]:{}", host, port))
    };
    while f.read_line(&mut buffer).unwrap() > 0 {
        {
            if buffer.as_bytes()[0] == b'#' {
                buffer.clear();
                continue
            }
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            match (hosts, key) {
                (Some(h), Some(k)) => {
                    let host_matches = h.split(',').any(|x| {
                        x == host_port
                    });
                    if host_matches {
                        if &try!(parse_public_key_base64(k)) == pubkey {
                            return Ok(true)
                        } else {
                            return Err(Error::KeyChanged)
                        }
                    }
                    
                },
                _ => {}
            }
        }
        buffer.clear();
    }
    Ok(false)
}


#[cfg(test)]
mod test {
    extern crate tempdir;
    use std::fs::File;
    use std::io::Write;
    use super::*;
    #[test]
    fn test_check_known_hosts() {
        let dir = tempdir::TempDir::new("thrussh").unwrap();
        let path = dir.path().join("known_hosts");
        {
            let mut f = File::create(&path).unwrap();
            f.write(b"[localhost]:13265 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n#pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\npijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
        }

        // Valid key, non-standard port.
        let host = "localhost";
        let port = 13265;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").unwrap();
        assert!(check_known_hosts_path(host,port,&hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X").unwrap();
        assert!(check_known_hosts_path(host,port,&hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X").unwrap();
        assert!(check_known_hosts_path(host,port,&hostkey, &path).is_err());
    }
}
