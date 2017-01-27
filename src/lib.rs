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
#![deny(missing_docs,
        trivial_casts,
        unstable_features,
        unused_import_braces)]
//! Server and client SSH library, based on *ring* for its crypto, and
//! tokio/futures for its network management. More information at
//! [pijul.org/thrussh](https://pijul.org/thrussh).
//!
//! Here is an example client and server:
//!
//! ```
//!extern crate thrussh;
//!extern crate futures;
//!extern crate tokio_core;
//!extern crate env_logger;
//!use std::sync::Arc;
//!use thrussh::*;
//!
//!#[derive(Clone)]
//!struct H{}
//!
//!impl server::Handler for H {
//!    type Error = ();
//!    type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
//!    type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
//!    type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;
//!
//!    fn auth_publickey(mut self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
//!        futures::finished((self, server::Auth::Accept))
//!    }
//!    fn data(mut self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
//!        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
//!        session.data(channel, None, data).unwrap();
//!        futures::finished((self, session))
//!    }
//!}
//!
//!
//!use std::net::ToSocketAddrs;
//!use futures::Future;
//!use tokio_core::net::TcpStream;
//!use tokio_core::reactor::Core;
//!
//!
//!struct Client { }
//!
//!impl client::Handler for Client {
//!    type Error = ();
//!    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
//!    type FutureUnit = futures::Finished<Self, Self::Error>;
//!    type SessionUnit = futures::Finished<(Self, client::Session), Self::Error>;
//!    fn check_server_key(mut self, server_public_key: &key::PublicKey) -> Self::FutureBool {
//!        println!("check_server_key: {:?}", server_public_key);
//!        futures::finished((self, true))
//!    }
//!    fn channel_open_confirmation(mut self, channel: ChannelId, session: client::Session) -> Self::SessionUnit {
//!        println!("channel_open_confirmation: {:?}", channel);
//!        futures::finished((self, session))
//!    }
//!    fn data(mut self, channel: ChannelId, ext: Option<u32>, data: &[u8], session: client::Session) -> Self::SessionUnit {
//!        println!("data on channel {:?} {:?}: {:?}", ext, channel, std::str::from_utf8(data));
//!        futures::finished((self, session))
//!    }
//!}
//!
//!impl Client {
//!    fn run(self, config: Arc<client::Config>, addr: &str) {
//!
//!        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
//!        let mut l = Core::new().unwrap();
//!        let handle = l.handle();
//!        let done =
//!            TcpStream::connect(&addr, &handle).map_err(|err| HandlerError::Error(thrussh::Error::IO(err))).and_then(|socket| {
//!
//!                println!("connected");
//!                let mut connection = client::Connection::new(
//!                    config.clone(),
//!                    socket,
//!                    self,
//!                    None
//!                ).unwrap();
//!
//!                let key = thrussh::load_secret_key("/home/pe/.ssh/id_ed25519").unwrap();
//!                connection.authenticate_key("pe", key).and_then(|connection| {
//!
//!                    connection.channel_open_session().and_then(|(mut connection, chan)| {
//!
//!                        connection.data(chan, None, b"First test").unwrap();
//!                        connection.data(chan, None, b"Second test").unwrap();
//!                        connection.disconnect(Disconnect::ByApplication, "Ciao", "");
//!                        connection
//!
//!                    })
//!                })
//!            });
//!        l.run(done).unwrap();
//!    }
//!
//!}
//!
//!fn main() {
//!    env_logger::init().unwrap();
//!    // Starting the server thread.
//!    let t = std::thread::spawn(|| {
//!        let mut config = thrussh::server::Config::default();
//!        config.connection_timeout = Some(std::time::Duration::from_secs(600));
//!        config.auth_rejection_time = std::time::Duration::from_secs(3);
//!        config.keys.push(thrussh::key::Algorithm::generate_keypair(thrussh::key::ED25519).unwrap());
//!        let config = Arc::new(config);
//!        let sh = H{};
//!        thrussh::server::run(config, "0.0.0.0:2222", sh);
//!    });
//!
//!    std::thread::sleep(std::time::Duration::from_secs(1));
//!    let mut config = thrussh::client::Config::default();
//!    config.connection_timeout = Some(std::time::Duration::from_secs(600));
//!    let config = Arc::new(config);
//!    let sh = Client {};
//!    sh.run(config, "127.0.0.1:2222");
//!
//!    // Kill the server thread after the client has ended.
//!    std::mem::forget(t)
//!}
//! ```


#[macro_use]
extern crate arrayref;
extern crate libc;
extern crate mio;
extern crate ring;
extern crate time;
#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // Reading keys in base64.
extern crate untrusted;
extern crate regex;
extern crate cryptovec;

#[macro_use]
extern crate tokio_core;
#[macro_use]
extern crate futures;

use std::io::{Read, BufRead, BufReader, Seek, SeekFrom, Write};
use byteorder::{BigEndian, WriteBytesExt};
use ring::signature;
use rustc_serialize::base64::{FromBase64, ToBase64, STANDARD};
use std::path::Path;
use std::fs::File;
use std::ops::Deref;
use std::borrow::Cow;
use std::fs::OpenOptions;

pub use cryptovec::CryptoVec;

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

/// Since handlers are large, their associated future types must implement this trait to provide reasonable default implementations (basically, rejecting all requests).
pub trait FromFinished<T, E>:futures::Future<Item=T, Error=E> {
    /// Turns type `T` into `Self`, a future yielding `T`.
    fn finished(t: T) -> Self;
}

impl<T, E> FromFinished<T, E> for futures::Finished<T, E> {
    fn finished(t: T) -> Self {
        futures::finished(t)
    }
}



#[derive(Debug)]
/// Errors.
pub enum Error {
    /// The key file could not be parsed.
    CouldNotReadKey,
    /// Base 64 decoding error.
    Base64(rustc_serialize::base64::FromBase64Error),

    /// Could not find common algorithms.
    KexInit,

    /// Invalid SSH version string.
    Version,

    /// Error during key exchange.
    Kex,

    /// Invalid packet authentication code.
    PacketAuth,

    /// The protocol is in an inconsistent state.
    Inconsistent,

    /// Index out of bounds.
    IndexOutOfBounds,

    /// UTF-8 decoding error (most probably ASCII error).
    Utf8(std::str::Utf8Error),

    /// Unknown server key.
    UnknownKey,

    /// Message received/sent on unopened channel.
    WrongChannel,

    /// I/O error.
    IO(std::io::Error),

    /// Disconnected
    Disconnect,

    /// No home directory found when trying to learn new host key.
    NoHomeDir,

    /// Remote key changed, this could mean a man-in-the-middle attack
    /// is being performed on the connection.
    KeyChanged(usize),

    /// Connection closed by the remote side.
    HUP,

    /// Error from the cryptography layer (*ring*).
    Ring(ring::error::Unspecified),

    /// Connection timeout.
    ConnectionTimeout,

    /// Missing authentication method.
    NoAuthMethod,
}

/// Errors including those coming from handler. These are not included
/// in this crate's "main" error type to allow for a simpler API (the
/// "handler error" type cannot be inferred by the compiler in some
/// functions).
#[derive(Debug)]
pub enum HandlerError<E> {
    /// Standard errors
    Error(Error),
    /// From handler
    Handler(E)
}
impl Error {
    fn kind(&self) -> std::io::ErrorKind {
        match *self {
            Error::IO(ref e) => e.kind(),
            _ => std::io::ErrorKind::Other
        }
    }
}
impl<E> HandlerError<E> {
    fn kind(&self) -> std::io::ErrorKind {
        match *self {
            HandlerError::Error(ref e) => e.kind(),
            _ => std::io::ErrorKind::Other
        }
    }
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
            Error::Inconsistent => "Unexpected packet",
            Error::IndexOutOfBounds => "Index out of bounds in a packet",
            Error::UnknownKey => "Unknown host key",
            Error::WrongChannel => "Inexistent channel",
            Error::Disconnect => "Disconnected",
            Error::NoHomeDir => "Home directory not found",
            Error::KeyChanged(_) => "Server key changed",
            Error::HUP => "Connection closed by the remote side",
            Error::Ring(ref e) => e.description(),
            Error::ConnectionTimeout => "Connection timout",
            Error::NoAuthMethod => "No more authentication method available",
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::Base64(ref e) => Some(e),
            Error::Utf8(ref e) => Some(e),
            Error::IO(ref e) => Some(e),
            Error::Ring(ref e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}
impl From<ring::error::Unspecified> for Error {
    fn from(e: ring::error::Unspecified) -> Error {
        Error::Ring(e)
    }
}
impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf8(e)
    }
}
impl From<rustc_serialize::base64::FromBase64Error> for Error {
    fn from(e: rustc_serialize::base64::FromBase64Error) -> Error{
        Error::Base64(e)
    }
}

impl<E> From<Error> for HandlerError<E> {
    fn from(e: Error) -> HandlerError<E> {
        HandlerError::Error(e)
    }
}
impl<E> From<std::io::Error> for HandlerError<E> {
    fn from(e: std::io::Error) -> HandlerError<E> {
        HandlerError::Error(Error::IO(e))
    }
}
impl<E> From<ring::error::Unspecified> for HandlerError<E> {
    fn from(e: ring::error::Unspecified) -> HandlerError<E> {
        HandlerError::Error(Error::Ring(e))
    }
}
impl<E> From<std::str::Utf8Error> for HandlerError<E> {
    fn from(e: std::str::Utf8Error) -> HandlerError<E> {
        HandlerError::Error(Error::Utf8(e))
    }
}
impl<E> From<rustc_serialize::base64::FromBase64Error> for HandlerError<E> {
    fn from(e: rustc_serialize::base64::FromBase64Error) -> HandlerError<E> {
        HandlerError::Error(Error::Base64(e))
    }
}


mod negotiation;
use negotiation::Named;
pub use negotiation::Preferred;
mod pty;
pub use pty::Pty;
mod msg;
/// Key generation and use.
pub mod key;
pub use key::parse_public_key;

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
    rekey_write_limit: usize,
    rekey_read_limit: usize,
    rekey_time_limit: std::time::Duration,
}

impl Limits {
    /// Create a new `Limits`, checking that the given bounds cannot lead to nonce reuse.
    pub fn new(write_limit: usize, read_limit: usize, time_limit: std::time::Duration) -> Limits {
        assert!(write_limit <= 1<<30 && read_limit <= 1<<30);
        Limits {
            rekey_write_limit: write_limit,
            rekey_read_limit: read_limit,
            rekey_time_limit: time_limit
        }
    }
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

/// Server side of this library.
pub mod server;

/// Client side of this library.
pub mod client;

/// A reason for disconnection.
#[allow(missing_docs)] // This should be relatively self-explanatory.
pub enum Disconnect {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    #[doc(hidden)]
    Reserved = 4,
    MACError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

/// The type of signals that can be sent to a remote process. If you
/// plan to use custom signals, read [the
/// RFC](https://tools.ietf.org/html/rfc4254#section-6.10) to
/// understand the encoding.
#[allow(missing_docs)] // This should be relatively self-explanatory.
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
#[allow(missing_docs)]
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


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ChannelId(u32);

/// The parameters of a channel.
#[derive(Debug)]
#[doc(hidden)]
pub struct Channel {
    recipient_channel: u32,
    sender_channel: ChannelId,
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
pub fn load_public_key<E, P: AsRef<Path>>(p: P) -> Result<key::PublicKey, Error> {

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


/// Write a public key onto the provided `Write`, encoded in base-64.
pub fn write_public_key_base64<W:Write>(mut w:W, publickey:&key::PublicKey) -> Result<(), Error> {
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
                    let (a,b) = seckey.split_at(32);
                    assert_eq!(pubkey, b);
                    let keypair = try!(signature::Ed25519KeyPair::from_bytes(a, pubkey));
                    let keypair = key::Algorithm::Ed25519(keypair);
                    return Ok(keypair)
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

/// Check that a server key matches the one recorded in file `path`.
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
    let mut line = 1;
    while f.read_line(&mut buffer).unwrap() > 0 {
        debug!("check_known_hosts_path: {:?}", buffer);
        {
            if buffer.as_bytes()[0] == b'#' {
                buffer.clear();
                continue;
            }
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            debug!("{:?} {:?}", hosts, key);
            match (hosts, key) {
                (Some(h), Some(k)) => {
                    let host_matches = h.split(',').any(|x| x == host_port);
                    debug!("host matches: {:?}", host_matches);
                    debug!("{:?} {:?}", parse_public_key_base64(k), pubkey);
                    if host_matches {
                        if &try!(parse_public_key_base64(k)) == pubkey {
                            return Ok(true);
                        } else {
                            return Err(Error::KeyChanged(line));
                        }
                    }

                }
                _ => {}
            }
        }
        buffer.clear();
        line += 1;
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
