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
//! ```
//! use std::sync::Arc;
//! use thrussh::{key, server, client, CryptoBuf, Error};
//! let client_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//! let server_keypair = key::Algorithm::generate_keypair(key::ED25519).unwrap();
//!
//! // Server instance
//!
//! struct S {
//!     client_pubkey: key::PublicKey
//! }
//! impl server::Handler for S {
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
//! impl client::Handler for C {
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
//! client_connection.set_auth_user("pe");
//! client_connection.set_auth_public_key(client_keypair);
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
//! ```


extern crate libc;
extern crate rand;
extern crate ring;
extern crate time;
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate untrusted;

use std::io::{Read, BufRead, BufReader, Seek, SeekFrom, Write};
use byteorder::{BigEndian, WriteBytesExt};
use ring::signature;
use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};
use std::path::Path;
use std::fs::File;
use std::ops::Deref;
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::sync::Arc;

mod cryptobuf;
pub use cryptobuf::CryptoBuf;

mod sshbuffer;

macro_rules! push_packet {
    ( $buffer:expr, $x:expr ) => {
        {
            use byteorder::{BigEndian, ByteOrder};
            let i0 = $buffer.len();
            $buffer.extend(b"\0\0\0\0");
            let x = $x;
            let i1 = $buffer.len();
            use std::ops::DerefMut;
            let buf = $buffer.deref_mut();
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
    KeyChanged,
    HUP,
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
            Error::KeyChanged => "Server key changed",
            Error::HUP => "Connection closed by the remote side",
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::Base64(ref e) => Some(e),
            Error::Utf8(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            _ => None,
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
use negociation::Named;
pub use negociation::Preferred;
mod pty;
pub use pty::Pty;
mod msg;
/// Key generation and use.
pub mod key;
pub mod kex;

pub mod cipher;

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
    pub rekey_time_limit: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        // Following the recommendations of
        // https://tools.ietf.org/html/rfc4253#section-9
        Limits {
            rekey_write_limit: 1 << 30, // 1 Gb
            rekey_read_limit: 1 << 30, // 1 Gb
            rekey_time_limit: std::time::Duration::from_secs(3600),
        }
    }
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
    Custom(&'a str),
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
            Sig::Custom(c) => c,
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
            x => Ok(Sig::Custom(try!(std::str::from_utf8(x)))),
        }
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
    fn from_u32(x: u32) -> Option<ChannelOpenFailure> {
        match x {
            1 => Some(ChannelOpenFailure::AdministrativelyProhibited),
            2 => Some(ChannelOpenFailure::ConnectFailed),
            3 => Some(ChannelOpenFailure::UnknownChannelType),
            4 => Some(ChannelOpenFailure::ResourceShortage),
            _ => None,
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
    wants_reply: bool,
}

const KEYTYPE_ED25519: &'static [u8] = b"ssh-ed25519";

/// Load a public key from a file. Only ed25519 keys are currently supported.
pub fn load_public_key<P: AsRef<Path>>(p: P) -> Result<key::PublicKey, Error> {

    let mut pubkey = String::new();
    let mut file = try!(File::open(p.as_ref()));
    try!(file.read_to_string(&mut pubkey));

    let mut split = pubkey.split_whitespace();

    match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key),
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
pub fn parse_public_key_base64(key: &str) -> Result<key::PublicKey, Error> {
    let base = try!(key.from_base64());
    parse_public_key(&base)
}

pub fn parse_public_key(p: &[u8]) -> Result<key::PublicKey, Error> {
    let mut pos = p.reader(0);
    if try!(pos.read_string()) == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            return Ok(key::PublicKey::Ed25519(Vec::from(pubkey)));
        }
    }
    Err(Error::CouldNotReadKey)
}

pub fn write_public_key_base64<W:std::io::Write>(mut w:W, publickey:&key::PublicKey) -> Result<(), Error> {
    try!(w.write_all(publickey.name().as_bytes()));
    try!(w.write_all(b" "));
    let mut s = Vec::new();
    let name = publickey.name().as_bytes();
    s.write_u32::<BigEndian>(name.len() as u32).unwrap();
    s.extend(name);
    s.write_u32::<BigEndian>(publickey.len() as u32).unwrap();
    s.extend(publickey.deref());
    try!(w.write_all(s.to_base64(STANDARD).as_bytes()));
    Ok(())
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
                    info!("public: ED25519:{:?}", pubkey);
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
                    return signature::Ed25519KeyPair::from_bytes(seckey, pubkey)
                            .map(|key_pair| key::Algorithm::Ed25519(Arc::new(key_pair)))
                            .map_err(|_| Error::CouldNotReadKey)
                } else {
                    info!("unsupported key type {:?}", std::str::from_utf8(key_type));
                }
            }
            Err(Error::CouldNotReadKey)
        } else {
            info!("unsupported secret key cipher: {:?}",
                  std::str::from_utf8(kdfname));
            Err(Error::CouldNotReadKey)
        }
    } else {
        Err(Error::CouldNotReadKey)
    }
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P:AsRef<Path>>(host:&str, port:u16, pubkey:&key::PublicKey, path:P) -> Result<(), Error> {


    let mut file = try!(OpenOptions::new()
                        .read(true)
                        .append(true)
                        .create(true)
                        .open(path));

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0;1];
    try!(file.seek(SeekFrom::End(-1)));
    try!(file.read_exact(&mut buf));
    let ends_in_newline = buf[0] == b'\n';

    // Write the key.
    try!(file.seek(SeekFrom::Start(0)));
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        try!(write!(file, "\n"));
    }
    if port != 22 {
        try!(write!(file, "[{}]:{} ", host, port))
    } else {
        try!(write!(file, "{} ", host))
    }
    try!(write_public_key_base64(&mut file, pubkey));
    try!(write!(file, "\n"));
    Ok(())
}


pub fn check_known_hosts_path<P: AsRef<Path>>(host: &str,
                                              port: u16,
                                              pubkey: &key::PublicKey,
                                              path: P)
                                              -> Result<bool, Error> {
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
                continue;
            }
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            match (hosts, key) {
                (Some(h), Some(k)) => {
                    let host_matches = h.split(',').any(|x| x == host_port);
                    if host_matches {
                        if &try!(parse_public_key_base64(k)) == pubkey {
                            return Ok(true);
                        } else {
                            return Err(Error::KeyChanged);
                        }
                    }

                }
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
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1e\
                                               bz9/cu7/QEXn9OIeZJ")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQ\
                                               lj2P+jpNSOEWD9OJ3X")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQ\
                                               lj2P+jpNSOEWD9OJ3X")
            .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).is_err());
    }
}
