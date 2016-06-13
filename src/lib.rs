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

use byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write, BufRead};
use std::sync::{Once, ONCE_INIT};
use std::collections::{HashSet, HashMap};
use rand::Rng;

pub mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;

pub mod config;

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
pub mod auth;
use auth::AuthRequest;

mod encoding;

use std::marker::PhantomData;

pub struct ServerSession<T, S> {
    recv_seqn: usize,
    sent_seqn: usize,

    read_buffer: CryptoBuf,
    read_len: usize, // next packet length.
    write_buffer: CryptoBuf,
    write_position: usize, // first position of non-written suffix.

    read_bytes: usize,
    written_bytes: usize,
    last_kex_time: u64,

    state: Option<ServerState<S>>,
    marker: PhantomData<T>,
}

pub enum ServerState<T> {
    VersionOk(Exchange), // Version number received.
    KexInit(kex::KexInit), /* Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively. */
    KexDh(KexDh), // Algorithms have been determined, the DH algorithm should run.
    KexDhDone(KexDhDone), // The kex has run.
    NewKeys(NewKeys), /* The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side. */
    Encrypted(Encrypted<T>), // Session is now encrypted.
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
    fn encrypted<T>(self) -> Encrypted<T> {
        Encrypted {
            exchange: self.exchange,
            kex: self.kex,
            key: self.key,
            cipher: self.cipher,
            mac: self.mac,
            session_id: self.session_id,
            state: Some(EncryptedState::WaitingServiceRequest),
            channels: HashMap::new(),
        }
    }
}


pub struct Encrypted<T> {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
    state: Option<EncryptedState>,
    channels: HashMap<u32, Channel<T>>,
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest,
    ServiceRequest,
    WaitingAuthRequest(AuthRequest),
    RejectAuthRequest(AuthRequest),
    WaitingSignature(AuthRequest),
    AuthRequestSuccess,
    WaitingChannelOpen,
    ChannelOpenConfirmation(ChannelParameters),
    ChannelOpened(HashSet<u32>),
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

#[derive(Debug)]
pub struct Exchange {
    client_id: Option<Vec<u8>>,
    server_id: Option<Vec<u8>>,
    client_kex_init: Option<Vec<u8>>,
    server_kex_init: Option<Vec<u8>>,
    client_ephemeral: Option<Vec<u8>>,
    server_ephemeral: Option<Vec<u8>>,
}

impl Exchange {
    fn new() -> Self {
        Exchange {
            client_id: None,
            server_id: None,
            client_kex_init: None,
            server_kex_init: None,
            client_ephemeral: None,
            server_ephemeral: None,
        }
    }
}




pub use auth::Authenticate;
pub trait Serve<S> {
    fn init(&S, channel: &ChannelParameters) -> Self;
    fn data(&mut self, _: &[u8], _: &mut CryptoBuf, _: &mut CryptoBuf) -> Result<(), Error> {
        Ok(())
    }
}

pub fn hexdump(x: &CryptoBuf) {
    let x = x.as_slice();
    let mut buf = Vec::new();
    let mut i = 0;
    while i < x.len() {
        if i % 16 == 0 {
            print!("{:04}: ", i)
        }
        print!("{:02x} ", x[i]);
        if x[i] >= 0x20 && x[i] <= 0x7e {
            buf.push(x[i]);
        } else {
            buf.push(b'.');
        }
        if i % 16 == 15 || i == x.len() - 1 {
            while i % 16 != 15 {
                print!("   ");
                i += 1
            }
            println!(" {}", std::str::from_utf8(&buf).unwrap());
            buf.clear();
        }
        i += 1
    }
}


/// Fills the read buffer, and returns whether a complete message has been read.
///
/// It would be tempting to return either a slice of `stream`, or a
/// slice of `read_buffer`, but except for a very small number of
/// messages, we need double buffering anyway to decrypt in place on
/// `read_buffer`.
fn read<R: BufRead>(stream: &mut R,
                    read_buffer: &mut CryptoBuf,
                    read_len: usize)
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
        if read_buffer.len() >= 4 + read_len {
            return Ok(true);
        }
    }
}

mod read;
mod write;

impl<T, S: Serve<T>> ServerSession<T, S> {
    pub fn new() -> Self {
        SODIUM_INIT.call_once(|| {
            sodium::init();
        });
        ServerSession {
            recv_seqn: 0,
            sent_seqn: 0,
            read_len: 0,
            read_buffer: CryptoBuf::new(),
            write_buffer: CryptoBuf::new(),

            read_bytes: 0,
            written_bytes: 0,
            last_kex_time: time::precise_time_ns(),

            write_position: 0,
            state: None,
            marker: PhantomData,
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


    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, A: Authenticate>(&mut self,
                                             config: &config::Config<A>,
                                             stream: &mut R,
                                             buffer: &mut CryptoBuf)
                                             -> Result<bool, Error> {

        let state = std::mem::replace(&mut self.state, None);
        // println!("state: {:?}", state);
        match state {
            None => self.read_client_id(stream),

            Some(ServerState::KexInit(kexinit)) => self.read_cleartext_kexinit(stream, kexinit, &config.keys),

            Some(ServerState::KexDh(mut kexdh)) => {


                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }

                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    let kex = {
                        let payload = self.get_current_payload();
                        println!("payload = {:?}", payload);
                        assert!(payload[0] == msg::KEX_ECDH_INIT);
                        kexdh.exchange.client_ephemeral = Some((&payload[5..]).to_vec());
                        try!(kexdh.kex.dh(&mut kexdh.exchange, payload))
                    };
                    self.recv_seqn += 1;
                    self.read_buffer.clear();
                    self.read_len = 0;
                    self.state = Some(ServerState::KexDhDone(KexDhDone {
                        exchange: kexdh.exchange,
                        kex: kex,
                        key: kexdh.key,
                        cipher: kexdh.cipher,
                        mac: kexdh.mac,
                        follows: kexdh.follows,
                        session_id: kexdh.session_id,
                    }));

                    Ok(true)

                } else {
                    // not enough bytes.
                    self.state = Some(ServerState::KexDh(kexdh));
                    Ok(false)
                }
            }
            Some(ServerState::NewKeys(newkeys)) => {

                // We are waiting for the NEWKEYS packet. Is it this one?
                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }
                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    let payload_is_newkeys = self.get_current_payload()[0] == msg::NEWKEYS;
                    if payload_is_newkeys {
                        // Ok, NEWKEYS received, now encrypted.
                        self.state = Some(ServerState::Encrypted(newkeys.encrypted()));
                        self.recv_seqn += 1;
                        self.read_buffer.clear();
                        self.read_len = 0;
                        Ok(true)
                    } else {
                        Err(Error::NewKeys)
                    }
                } else {
                    // Not enough bytes
                    self.state = Some(ServerState::NewKeys(newkeys));
                    Ok(false)
                }
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?}", enc.state);

                let buf_is_some =
                    if let Some(buf) = try!(enc.cipher.read_client_packet(self.recv_seqn,
                                                                          stream,
                                                                          &mut self.read_len,
                                                                          &mut self.read_buffer)) {

                        let enc_state = read::read_encrypted(&config.auth, &mut enc, buf, buffer);
                        enc.state = Some(enc_state);
                        true
                    } else {
                        false
                    };
                if buf_is_some {
                    self.recv_seqn += 1;
                    self.read_buffer.clear();
                    self.read_len = 0;
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(buf_is_some)
            }
            _ => {
                // println!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    // Returns whether the connexion is still alive.

    pub fn write<W: Write, A: Authenticate>(&mut self,
                                            config: &config::Config<A>,
                                            server: &T,
                                            stream: &mut W,
                                            buffer: &mut CryptoBuf,
                                            buffer2: &mut CryptoBuf)
                                            -> Result<bool, Error> {

        // println!("writing");
        // Finish pending writes, if any.
        if !try!(self.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        self.write_buffer.clear();
        self.write_position = 0;

        let state = std::mem::replace(&mut self.state, None);

        match state {
            Some(ServerState::VersionOk(mut exchange)) => {

                self.write_buffer.extend(config.server_id.as_bytes());
                self.write_buffer.push(b'\r');
                self.write_buffer.push(b'\n');
                try!(self.write_all(stream));

                exchange.server_id = Some(config.server_id.as_bytes().to_vec());

                self.state = Some(ServerState::KexInit(kex::KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                }));
                Ok(true)
            }
            Some(ServerState::KexInit(kexinit)) => {

                self.state = Some(try!(self.cleartext_write_kex_init(&config.keys,
                                                                     kexinit,
                                                                     stream)));
                Ok(true)
            }
            Some(ServerState::KexDhDone(kexdhdone)) => {

                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key,
                                                                    &kexdhdone.exchange,
                                                                    buffer));
                try!(self.cleartext_kex_ecdh_reply(&kexdhdone, &hash));
                self.cleartext_send_newkeys();
                try!(self.write_all(stream));

                self.state = Some(ServerState::NewKeys(kexdhdone.compute_keys(hash,
                                                                              buffer,
                                                                              buffer2)));
                Ok(true)
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?}", enc.state);
                let state = std::mem::replace(&mut enc.state, None);
                match state {

                    Some(EncryptedState::ServiceRequest) => {
                        let auth_request = self.accept_service(config.auth_banner,
                                                               config.methods,
                                                               &mut enc,
                                                               buffer);
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        try!(self.write_all(stream));
                    }

                    Some(EncryptedState::RejectAuthRequest(auth_request)) => {

                        self.reject_auth_request(&mut enc, buffer, &auth_request);
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        try!(self.write_all(stream));
                    }

                    Some(EncryptedState::WaitingSignature(mut auth_request)) => {

                        self.send_pk_ok(&mut enc, buffer, &mut auth_request);
                        enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                        try!(self.write_all(stream));
                    }

                    Some(EncryptedState::AuthRequestSuccess) => {
                        buffer.clear();
                        buffer.push(msg::USERAUTH_SUCCESS);
                        enc.cipher.write_server_packet(self.sent_seqn,
                                                       buffer.as_slice(),
                                                       &mut self.write_buffer);
                        self.sent_seqn += 1;
                        enc.state = Some(EncryptedState::WaitingChannelOpen);
                        try!(self.write_all(stream));
                    }

                    Some(EncryptedState::ChannelOpenConfirmation(channel)) => {

                        let server = S::init(server, &channel);
                        self.confirm_channel_open(&mut enc, buffer, channel, server);
                        enc.state = Some(EncryptedState::ChannelOpened(HashSet::new()));
                        try!(self.write_all(stream));
                    }
                    Some(EncryptedState::ChannelOpened(mut channels)) => {

                        self.flush_channels(&mut enc, &mut channels, buffer);
                        try!(self.write_all(stream));
                        enc.state = Some(EncryptedState::ChannelOpened(channels))
                    }
                    state => enc.state = state,
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
            session => {
                // println!("write: unhandled {:?}", session);
                self.state = session;
                Ok(true)
            }
        }
    }
}
