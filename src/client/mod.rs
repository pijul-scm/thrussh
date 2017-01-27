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

use std::sync::Arc;
use std::io::{Write, BufReader};
use std;
use futures::{Poll, Async};
use futures::future::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Timeout;
use ring;
use {Disconnect, Error, Limits, Sig, ChannelOpenFailure, parse_public_key, ChannelId,
     FromFinished, HandlerError};
use encoding::Reader;
use key;
use msg;
use auth;
use cipher::CipherPair;
use negotiation;
use cryptovec::CryptoVec;
use negotiation::Select;
use session::*;
use sshbuffer::*;
use cipher;
use kex;
use ring::signature;
use pty::Pty;
use untrusted;
use encoding::Encoding;
mod encrypted;

/// The configuration of clients.
#[derive(Debug)]
pub struct Config {
    /// The client ID string sent at the beginning of the protocol.
    pub client_id: String,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Lists of preferred algorithms.
    pub preferred: negotiation::Preferred,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!("SSH-2.0-{}_{}",
                               env!("CARGO_PKG_NAME"),
                               env!("CARGO_PKG_VERSION")),
            limits: Limits::default(),
            window_size: 200000,
            maximum_packet_size: 200000,
            preferred: Default::default(),
            connection_timeout: None,
        }
    }
}


/// Client connection.
pub struct Connection<H: Handler> {
    read_buffer: SSHBuffer,
    /// Session of this connection.
    pub session: Option<Session>,
    stream: BufReader<TcpStream>,
    state: Option<ConnectionState>,
    pending_future: Option<PendingFuture<H>>,
    buffer: CryptoVec,
    buffer2: CryptoVec,
    /// Handler for this connection.
    handler: Option<H>,
    timeout: Option<Timeout>,
}

impl<H: Handler> std::ops::Deref for Connection<H> {
    type Target = Session;
    fn deref(&self) -> &Self::Target {
        self.session.as_ref().unwrap()
    }
}

impl<H: Handler> std::ops::DerefMut for Connection<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.session.as_mut().unwrap()
    }
}


#[derive(Debug)]
enum ConnectionState {
    ReadSshId { sshid: ReadSshId },
    WriteSshId,
    Read,
    Write,
    Flush,
}

/// The type of a client session.
pub struct Session(CommonSession<Config>);

/// A client handler. Note that messages can be received from the
/// server at any time during a session.
pub trait Handler:Sized {

    /// Error type returned by the futures.
    type Error: std::fmt::Debug;

    /// A future ultimately resolving into a boolean, which can be
    /// returned by some parts of this handler.
    type FutureBool: Future<Item = (Self, bool), Error = Self::Error> + FromFinished<(Self, bool), Self::Error>;

    /// A future ultimately resolving into a boolean, which can be
    /// returned by some parts of this handler.
    type FutureUnit: Future<Item = Self, Error = Self::Error> + FromFinished<Self, Self::Error>;

    /// A future ultimately resolving into unit, which can be returned
    /// by some parts of this handler.
    type SessionUnit: Future<Item = (Self, Session), Error = Self::Error> + FromFinished<(Self, Session), Self::Error>;

    /// Called when the server sends us an authentication banner. This
    /// is usually meant to be shown to the user, see
    /// [RFC4252](https://tools.ietf.org/html/rfc4252#section-5.4) for
    /// more details.
    #[allow(unused_variables)]
    fn auth_banner(self, banner: &str) -> Self::FutureUnit {
        Self::FutureUnit::finished(self)
    }

    /// Called to check the server's public key. This is a very important
    /// step to help prevent man-in-the-middle attacks. The default
    /// implementation rejects all keys.
    #[allow(unused_variables)]
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        Self::FutureBool::finished((self, false))
    }

    /// Called when the server confirmed our request to open a
    /// channel. A channel can only be written to after receiving this
    /// message (this library panics otherwise).
    #[allow(unused_variables)]
    fn channel_open_confirmation(self,
                                 channel: ChannelId,
                                 session: Session)
                                 -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(self,
                            channel: ChannelId,
                            reason: ChannelOpenFailure,
                            description: &str,
                            language: &str,
                            session: Session)
                            -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(self,
                                    channel: ChannelId,
                                    connected_address: &str,
                                    connected_port: u32,
                                    originator_address: &str,
                                    originator_port: u32,
                                    session: Session)
                                    -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the server sends us data. The `extended_code`
    /// parameter is a stream identifier, `None` is usually the
    /// standard output, and `Some(1)` is the standard error. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(self,
            channel: ChannelId,
            extended_code: Option<u32>,
            data: &[u8],
            session: Session)
            -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The server informs this client of whether the client may
    /// perform control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(self,
                channel: ChannelId,
                client_can_do: bool,
                session: Session)
                -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(self,
                   channel: ChannelId,
                   exit_status: u32,
                   session: Session)
                   -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(self,
                   channel: ChannelId,
                   signal_name: Sig,
                   core_dumped: bool,
                   error_message: &str,
                   lang_tag: &str,
                   session: Session)
                   -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(self, channel: ChannelId, session: Session) -> Self::SessionUnit {
        Self::SessionUnit::finished((self, session))
    }
}









impl KexInit {
    pub fn client_parse(mut self,
                        rng: &ring::rand::SecureRandom,
                        config: &Config,
                        cipher: &mut CipherPair,
                        buf: &[u8],
                        write_buffer: &mut SSHBuffer)
                        -> Result<KexDhDone, Error> {

        let algo = if self.algo.is_none() {
            // read algorithms from packet.
            self.exchange.server_kex_init.extend(buf);
            try!(super::negotiation::Client::read_kex(buf, &config.preferred))
        } else {
            return Err(Error::Kex);
        };
        if !self.sent {
            try!(self.client_write(rng, config, cipher, write_buffer))
        }

        // This function is called from the public API.
        //
        // In order to simplify the public API, we reuse the
        // self.exchange.client_kex buffer to send an extra packet,
        // then truncate that buffer. Without that, we would need an
        // extra buffer.
        let i0 = self.exchange.client_kex_init.len();
        let kex = try!(kex::Algorithm::client_dh(algo.kex,
                                                 &mut self.exchange.client_ephemeral,
                                                 &mut self.exchange.client_kex_init));

        cipher.write(&self.exchange.client_kex_init[i0..], write_buffer);
        self.exchange.client_kex_init.resize(i0);


        Ok(KexDhDone {
            exchange: self.exchange,
            names: algo,
            kex: kex,
            key: 0,
            session_id: self.session_id,
        })
    }

    pub fn client_write(&mut self,
                        rng: &ring::rand::SecureRandom,
                        config: &Config,
                        cipher: &mut CipherPair,
                        write_buffer: &mut SSHBuffer)
                        -> Result<(), Error> {
        self.exchange.client_kex_init.clear();
        try!(negotiation::write_kex(rng, &config.preferred, &mut self.exchange.client_kex_init));
        self.sent = true;
        cipher.write(&self.exchange.client_kex_init, write_buffer);
        Ok(())
    }
}



impl<H: Handler> Connection<H> {
    /// Create a new client connection.
    pub fn new(config: Arc<Config>,
               stream: TcpStream,
               handler: H,
               timeout: Option<Timeout>)
               -> Result<Self, Error> {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().client_id.as_bytes());
        let mut connection = Connection {
            read_buffer: SSHBuffer::new(),
            timeout: timeout,
            session: Some(Session(CommonSession {
                write_buffer: write_buffer,
                kex: None,
                auth_user: String::new(),
                auth_method: None, // Client only.
                cipher: cipher::CLEAR_PAIR,
                encrypted: None,
                config: config,
                wants_reply: false,
                disconnected: false,
                rng: ring::rand::SystemRandom::new(),
            })),
            stream: BufReader::new(stream),
            state: Some(ConnectionState::WriteSshId),
            pending_future: None,
            handler: Some(handler),
            buffer: CryptoVec::new(),
            buffer2: CryptoVec::new(),
        };
        if let Some(ref mut s) = connection.session {
            try!(s.flush())
        }
        Ok(connection)
    }
}


impl<H: Handler> Future for Connection<H> {
    type Item = ();
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // If timeout, shutdown the socket.
        try_ready!(self.poll_timeout());
        loop {
            debug!("client polling");
            if !try_ready!(self.atomic_poll()) {
                return Ok(Async::Ready(()));
            }
        }
    }
}

#[doc(hidden)]
pub enum PendingFuture<H: Handler> {
    ServerKeyCheck {
        check: H::FutureBool,
        kexdhdone: KexDhDone,
        buf_len: usize,
    },
    SessionUnit(H::SessionUnit),
    Done(H, Session)
}


impl<H: Handler> Connection<H> {
    fn poll_timeout(&mut self) -> Poll<(), HandlerError<H::Error>> {
        if let Some(ref mut timeout) = self.timeout {
            if let Async::Ready(()) = try!(timeout.poll()) {
                debug!("Timeout, shutdown");
                try_nb!(self.stream.get_mut().shutdown(std::net::Shutdown::Both));
                if let Some(ref mut s) = self.session {
                    s.0.disconnected = true;
                }
                return Err(HandlerError::Error(Error::ConnectionTimeout))
            }
        }
        Ok(Async::Ready(()))
    }

    fn pending_poll(&mut self) -> Poll<(), HandlerError<H::Error>> {

        match self.pending_future.take() {

            Some(PendingFuture::SessionUnit(mut f)) => {
                if let Async::Ready((h, session)) = try!(f.poll().map_err(HandlerError::Handler)) {
                    self.session = Some(session);
                    self.handler = Some(h);
                    Ok(Async::Ready(()))
                } else {
                    self.pending_future = Some(PendingFuture::SessionUnit(f));
                    Ok(Async::NotReady)
                }
            }
            Some(PendingFuture::Done(h, session)) => {
                self.session = Some(session);
                self.handler = Some(h);
                Ok(Async::Ready(()))
            }
            Some(PendingFuture::ServerKeyCheck { mut check, mut kexdhdone, buf_len }) => {

                match try!(check.poll().map_err(HandlerError::Handler)) {
                    Async::Ready((h, false)) => {
                        self.handler = Some(h);
                        Err(HandlerError::Error(Error::UnknownKey))
                    },
                    Async::NotReady => {
                        self.pending_future = Some(PendingFuture::ServerKeyCheck {
                            check: check,
                            kexdhdone: kexdhdone,
                            buf_len: buf_len,
                        });
                        Ok(Async::NotReady)
                    }
                    Async::Ready((h, true)) => {
                        self.handler = Some(h);
                        let buf = &self.read_buffer.buffer[5..5 + buf_len];
                        let hash = {
                            let mut reader = buf.reader(1);
                            let pubkey = try!(reader.read_string()); // server public key.
                            let pubkey = try!(parse_public_key(pubkey));
                            let server_ephemeral = try!(reader.read_string());
                            kexdhdone.exchange.server_ephemeral.extend(server_ephemeral);
                            let signature = try!(reader.read_string());

                            try!(kexdhdone.kex
                                .compute_shared_secret(&kexdhdone.exchange.server_ephemeral));

                            let hash = try!(kexdhdone.kex
                                .compute_exchange_hash(&pubkey,
                                                       &kexdhdone.exchange,
                                                       &mut self.buffer));

                            let signature = {
                                let mut sig_reader = signature.reader(0);
                                let sig_type = try!(sig_reader.read_string());
                                assert_eq!(sig_type, b"ssh-ed25519");
                                try!(sig_reader.read_string())
                            };

                            match pubkey {
                                key::PublicKey::Ed25519(ref pubkey) => {
                                    assert!(signature::verify(&signature::ED25519,
                                                              untrusted::Input::from(&pubkey[..]),
                                                              untrusted::Input::from(hash.as_ref()),
                                                              untrusted::Input::from(signature))
                                            .is_ok());
                                }
                            };
                            hash
                        };
                        let mut newkeys = try!(kexdhdone.compute_keys(
                            hash, &mut self.buffer, &mut self.buffer2, false));
                        if let Some(ref mut s) = self.session {
                            s.0.cipher.write(&[msg::NEWKEYS], &mut s.0.write_buffer);
                            s.0.kex = Some(Kex::NewKeys(newkeys));
                        }
                        newkeys.sent = true;
                        Ok(Async::Ready(()))
                    }
                }
            }
            None => Ok(Async::Ready(())),
        }
    }

    /// Process all packets available in the buffer, and returns
    /// whether at least one complete packet was read.  `buffer` and
    /// `buffer2` are work spaces mostly used to compute keys. They
    /// are cleared before using, hence nothing is expected from them.
    fn atomic_poll(&mut self) -> Poll<bool, HandlerError<H::Error>> {

        try_ready!(self.pending_poll());

        // Special case for the beginning.
        match self.state.take() {
            None => {
                if let Some(ref mut s) = self.session {
                    if s.0.disconnected {
                        Ok(Async::Ready(false))
                    } else {
                        try_nb!(self.stream.get_mut().shutdown(std::net::Shutdown::Both));
                        s.0.disconnected = true;
                        Ok(Async::Ready(false))
                    }
                } else {
                    unreachable!()
                }
            }
            Some(ConnectionState::WriteSshId) => {
                self.state = Some(ConnectionState::ReadSshId { sshid: read_ssh_id() });
                Ok(Async::Ready(true))
            }
            Some(ConnectionState::ReadSshId { mut sshid }) => {

                match sshid.poll(&mut self.stream) {
                    Ok(Async::NotReady) => {
                        self.state = Some(ConnectionState::ReadSshId { sshid: sshid });
                        Ok(Async::NotReady)
                    }
                    Err(Error::IO(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        self.state = Some(ConnectionState::ReadSshId { sshid: sshid });
                        Ok(Async::NotReady)
                    }
                    Err(e) => Err(HandlerError::Error(e)),
                    Ok(Async::Ready(())) => {
                        self.read_buffer.bytes += sshid.id_len + 2;
                        let mut exchange = Exchange::new();
                        exchange.server_id.extend(sshid.id());
                        // Preparing the response
                        if let Some(ref mut s) = self.session {
                            exchange.client_id.extend(s.0.config.as_ref().client_id.as_bytes());
                            let mut kexinit = KexInit {
                                exchange: exchange,
                                algo: None,
                                sent: false,
                                session_id: None,
                            };
                            try!(kexinit.client_write(&s.0.rng,
                                                      s.0.config.as_ref(),
                                                      &mut s.0.cipher,
                                                      &mut s.0.write_buffer));
                            s.0.kex = Some(Kex::KexInit(kexinit));
                            self.state = Some(ConnectionState::Write);
                        } else {
                            unreachable!()
                        }
                        Ok(Async::Ready(true))
                    }
                }
            }
            Some(ConnectionState::Write) => {
                debug!("writing");
                self.state = Some(ConnectionState::Write);
                if let Some(ref mut s) = self.session {
                    try!(s.flush());
                    try_nb!(s.0.write_buffer.write_all(self.stream.get_mut()));
                }
                self.state = Some(ConnectionState::Flush);
                Ok(Async::Ready(true))
            }
            Some(ConnectionState::Flush) => {
                debug!("flushing");
                self.state = Some(ConnectionState::Flush);
                try_nb!(self.stream.get_mut().flush());
                self.state = Some(ConnectionState::Read);
                Ok(Async::Ready(true))
            }
            Some(ConnectionState::Read) => {
                debug!("reading");
                let buf = if let Some(ref mut s) = self.session {

                    self.state = Some(ConnectionState::Read);
                    // In all other cases:
                    let buf = try_nb!(s.0.cipher.read(&mut self.stream, &mut self.read_buffer));

                    // Handle the transport layer.
                    if buf.len() == 0 || buf[0] == msg::DISCONNECT {
                        // transport
                        return Ok(Async::Ready(false));
                    }
                    // If we don't disconnect, keep the state.
                    self.state = Some(ConnectionState::Write);

                    // Handle transport layer packets.
                    if buf[0] <= 4 {
                        return Ok(Async::Ready(true));
                    }

                    // Handle key exchange/re-exchange.
                    match s.0.kex.take() {
                        Some(Kex::KexInit(kexinit)) => {
                            if kexinit.algo.is_some() || buf[0] == msg::KEXINIT || s.0.encrypted.is_none() {
                                let kexdhdone = kexinit.client_parse(&s.0.rng,
                                                                     s.0.config.as_ref(),
                                                                     &mut s.0.cipher,
                                                                     buf,
                                                                     &mut s.0.write_buffer);
                                match kexdhdone {
                                    Ok(kexdhdone) => {
                                        s.0.kex = Some(Kex::KexDhDone(kexdhdone));
                                        return Ok(Async::Ready(true))
                                    }
                                    Err(e) => return Err(HandlerError::Error(e)),
                                }
                            } else {
                                unreachable!()
                            }
                        }
                        Some(Kex::KexDhDone(mut kexdhdone)) => {
                            if kexdhdone.names.ignore_guessed {
                                kexdhdone.names.ignore_guessed = false;
                                s.0.kex = Some(Kex::KexDhDone(kexdhdone));
                                return Ok(Async::Ready(true))
                            } else {
                                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                                if buf[0] == msg::KEX_ECDH_REPLY {
                                    let mut reader = buf.reader(1);
                                    let pubkey = try!(reader.read_string()); // server public key.
                                    let pubkey = try!(parse_public_key(pubkey));
                                    self.pending_future = Some(PendingFuture::ServerKeyCheck {
                                        check: self.handler.take().unwrap().check_server_key(&pubkey),
                                        kexdhdone: kexdhdone,
                                        buf_len: buf.len(),
                                    });
                                    return Ok(Async::Ready(true))
                                } else {
                                    return Err(HandlerError::Error(Error::Inconsistent))
                                }
                            }
                        }
                        Some(Kex::NewKeys(newkeys)) => {
                            if buf[0] != msg::NEWKEYS {
                                return Err(HandlerError::Error(Error::Kex));
                            }
                            s.0.encrypted(EncryptedState::WaitingServiceRequest, newkeys);
                            // Ok, NEWKEYS received, now encrypted.
                            let p = b"\x05\0\0\0\x0Cssh-userauth";
                            s.0.cipher.write(p, &mut s.0.write_buffer);
                            return Ok(Async::Ready(true))
                        }
                        Some(kex) => {
                            s.0.kex = Some(kex);
                            return Ok(Async::Ready(true))
                        },
                        None => buf
                    }
                } else {
                    unreachable!()
                };

                if let (Some(s), Some(h)) = (self.session.take(), self.handler.take()) {
                    self.pending_future = Some(try_nb!(s.client_read_encrypted(h, buf, &mut self.buffer)));
                } else {
                    unreachable!()
                }
                Ok(Async::Ready(true))
            }
        }
    }

    /// Try to authenticate this client using a password.
    pub fn authenticate_password(mut self, user: &str, password: String) -> Authenticate<H> {
        if let Some(ref mut s) = self.session {
            s.set_auth_user(user);
            s.set_auth_password(password);
        }
        Authenticate(Some(self))
    }

    /// Try to authenticate this client using a key pair.
    pub fn authenticate_key(mut self, user: &str, key: key::Algorithm) -> Authenticate<H> {
        if let Some(ref mut s) = self.session {
            s.set_auth_user(user);
            s.set_auth_public_key(key);
        }
        Authenticate(Some(self))
    }

    /// Ask the server to open a session channel.
    pub fn channel_open_session(mut self) -> ChannelOpen<H, SessionChannel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_session().unwrap()
        } else {
            unreachable!()
        };
        self.state = Some(ConnectionState::Write);
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
        }
    }

    /// Ask the server to open an X11 forwarding channel.
    pub fn channel_open_x11(mut self,
                            originator_address: &str,
                            originator_port: u32)
                            -> ChannelOpen<H, X11Channel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_x11(originator_address, originator_port).unwrap()
        } else {
            unreachable!()
        };
        self.state = Some(ConnectionState::Write);
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
        }
    }

    /// Ask the server to open a direct TCP/IP forwarding channel.
    pub fn channel_open_direct_tcpip(mut self,
                                     host_to_connect: &str,
                                     port_to_connect: u32,
                                     originator_address: &str,
                                     originator_port: u32)
                                     -> ChannelOpen<H, DirectTcpIpChannel> {
        let num = if let Some(ref mut s) = self.session {
            s.channel_open_direct_tcpip(host_to_connect,
                                        port_to_connect,
                                        originator_address,
                                        originator_port)
                .unwrap()
        } else {
            unreachable!()
        };
        self.state = Some(ConnectionState::Write);
        ChannelOpen {
            connection: Some(self),
            channel: num,
            channel_type: PhantomData,
        }
    }

    /// Ask the server to close a channel, finishing any pending write and read.
    pub fn channel_close(mut self, channel: ChannelId) {
        if let Some(ref mut s) = self.session {
            s.0.byte(channel, msg::CHANNEL_CLOSE);
        }
        self.state = Some(ConnectionState::Write);
    }

    /// Wait until a condition is met on the connection.
    pub fn wait<F: Fn(&Connection<H>) -> bool>(mut self, f: F) -> Wait<H, F> {
        self.state = Some(ConnectionState::Write);
        Wait {
            connection: Some(self),
            condition: f,
        }
    }

    /// Flush the session, sending any pending message.
    pub fn flush(mut self) -> Flush<H> {
        self.state = Some(ConnectionState::Write);
        Flush { connection: Some(self) }
    }

    /// Gets a borrow to the connection's handler.
    pub fn handler(&self) -> &H {
        self.handler.as_ref().unwrap()
    }

    /// Gets a mutable borrow to the connection's handler.
    pub fn handler_mut(&mut self) -> &mut H {
        self.handler.as_mut().unwrap()
    }
}

/// An authenticating future, ultimately resolving into an authenticated connection.
pub struct Authenticate<H: Handler>(Option<Connection<H>>);

impl<H: Handler> Future for Authenticate<H> {
    type Item = Connection<H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref mut c) = self.0 {
            try_ready!(c.poll_timeout());
        }
        loop {
            debug!("authenticated loop");
            let is_authenticated = if let Some(ref c) = self.0 {
                if let Some(ref s) = c.session {
                    s.is_authenticated()
                } else {
                    false
                }
            } else {
                false
            };
            if is_authenticated {
                return Ok(Async::Ready(self.0.take().unwrap()))
            }
            let disconnected = if let Some(ref mut c) = self.0 {
                !try_ready!(c.atomic_poll())
            } else {
                unreachable!()
            };
            if disconnected {
                return Ok(Async::Ready(self.0.take().unwrap()))
            }
        }
    }
}

use std::marker::PhantomData;

#[doc(hidden)]
pub enum X11Channel {}
#[doc(hidden)]
pub enum SessionChannel {}
#[doc(hidden)]
pub enum DirectTcpIpChannel {}

/// A future resolving into an open channel number of type
/// `ChannelType`, which can be either `SessionChannel`, `X11Channel`
/// or `DirectTcpIdChannel`.
pub struct ChannelOpen<H: Handler, ChannelType> {
    connection: Option<Connection<H>>,
    channel: ChannelId,
    channel_type: PhantomData<ChannelType>,
}

/// A future waiting for a channel to be closed.
pub struct Wait<H: Handler, F> {
    connection: Option<Connection<H>>,
    condition: F,
}

/// A future waiting for a flush request to complete.
pub struct Flush<H: Handler> {
    connection: Option<Connection<H>>,
}

impl<H: Handler, ChannelType> Future for ChannelOpen<H, ChannelType> {
    type Item = (Connection<H>, ChannelId);
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref mut c) = self.connection {
            try_ready!(c.poll_timeout());
        }

        loop {
            debug!("channelopen loop");
            let is_open = if let Some(ref c) = self.connection {
                if let Some(ref s) = c.session {
                    s.channel_is_open(self.channel)
                } else {
                    false
                }
            } else {
                false
            };
            if is_open {
                return Ok(Async::Ready((self.connection.take().unwrap(), self.channel)));
            }

            let is_disconnected = if let Some(ref mut c) = self.connection {
                !try_ready!(c.atomic_poll())
            } else {
                unreachable!()
            };

            if is_disconnected {
                return Err(HandlerError::Error(Error::Disconnect))
            }
        }
    }
}


impl<H: Handler, F: Fn(&Connection<H>) -> bool> Future for Wait<H, F> {
    type Item = Connection<H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        if let Some(ref mut c) = self.connection {
            try_ready!(c.poll_timeout());
        }

        loop {
            debug!("wait loop");
            if let Some(mut connection) = self.connection.take() {
                if connection.handler.is_some() && (self.condition)(&connection) {
                    return Ok(Async::Ready(connection));
                } else {
                    match try!(connection.atomic_poll()) {
                        Async::Ready(true) => {
                            self.connection = Some(connection);
                        }
                        Async::Ready(false) => {
                            return Ok(Async::Ready(connection))
                        }
                        Async::NotReady => {
                            self.connection = Some(connection);
                            return Ok(Async::NotReady);
                        }
                    }
                }
            }
        }
    }
}



impl<H: Handler> Future for Flush<H> {
    type Item = Connection<H>;
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(ref mut c) = self.connection {
            try_ready!(c.poll_timeout());
        }

        loop {
            debug!("flush loop");
            let completely_written = if let Some(ref mut c) = self.connection {
                if let Some(ref mut s) = c.session {
                    try!(s.flush());
                    try_nb!(s.0.write_buffer.write_all(c.stream.get_mut()))
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            };
            if completely_written {
                if let Some(mut c) = self.connection.take() {
                    c.state = Some(ConnectionState::Write);
                    return Ok(Async::Ready(c));
                } else {
                    unreachable!()
                }
            }
        }
    }
}



impl Session {
    fn flush(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.0.encrypted {
            if enc.flush(&self.0.config.as_ref().limits,
                         &mut self.0.cipher,
                         &mut self.0.write_buffer) {
                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                    let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                    try!(kexinit.client_write(&self.0.rng,
                                              &self.0.config.as_ref(),
                                              &mut self.0.cipher,
                                              &mut self.0.write_buffer));
                    enc.rekey = Some(Kex::KexInit(kexinit))
                }
            }
        }
        Ok(())
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// Retrieves the current user.
    pub fn auth_user(&self) -> &str {
        &self.0.auth_user
    }

    /// Sends a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.0.disconnect(reason, description, language_tag);
    }

    /// Set the user.
    fn set_auth_user(&mut self, user: &str) {
        self.0.auth_user.clear();
        self.0.auth_user.push_str(user)
    }

    /// Set the authentication method.
    fn set_auth_public_key(&mut self, key: key::Algorithm) {
        self.0.auth_method = Some(auth::Method::PublicKey { key: key });
    }

    /// Set the authentication method.
    fn set_auth_password(&mut self, password: String) {
        self.0.auth_method = Some(auth::Method::Password { password: password });
    }

    /// Whether the client is authenticated.
    pub fn is_authenticated(&self) -> bool {
        if let Some(ref enc) = self.0.encrypted {
            if let Some(EncryptedState::Authenticated) = enc.state {
                return true;
            }
        }
        false
    }

    /// Whether the client is disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.0.disconnected
    }

    /// Check whether a channel has been confirmed.
    pub fn channel_is_open(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.0.encrypted {
            if let Some(ref channel) = enc.channels.get(&channel) {
                return channel.confirmed;
            }
        }
        false
    }

    /// Tests whether we need an authentication method (for instance
    /// if the last attempt failed).
    pub fn has_auth_method(&self) -> bool {
        self.0.auth_method.is_some()
    }

    /// Returns the set of authentication methods that can continue, or None if this is not valid.
    pub fn valid_auth_methods(&self) -> Option<auth::MethodSet> {
        if let Some(ref enc) = self.0.encrypted {
            match enc.state {
                Some(EncryptedState::WaitingAuthRequest(ref auth_request)) => {
                    Some(auth_request.methods)
                }
                _ => None,
            }
        } else {
            None
        }
    }


    /// Request a session channel (the most basic type of
    /// channel). This function returns `Some(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            match enc.state {
                Some(EncryptedState::Authenticated) => {
                    debug!("sending open request");

                    let sender_channel =
                        enc.new_channel(self.0.config.window_size,
                                        self.0.config.maximum_packet_size);
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"session");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size);

                        // max packet size.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size);
                    });
                    sender_channel
                }
                _ => return Err(Error::Inconsistent),
            }
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }


    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    fn channel_open_x11(&mut self,
                        originator_address: &str,
                        originator_port: u32)
                        -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            match enc.state {
                Some(EncryptedState::Authenticated) => {

                    let sender_channel =
                        enc.new_channel(self.0.config.window_size,
                                        self.0.config.maximum_packet_size);
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"x11");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size);

                        // max packet size.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size);

                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    sender_channel
                }
                _ => return Err(Error::Inconsistent),
            }
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    fn channel_open_direct_tcpip(&mut self,
                                 host_to_connect: &str,
                                 port_to_connect: u32,
                                 originator_address: &str,
                                 originator_port: u32)
                                 -> Result<ChannelId, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            match enc.state {
                Some(EncryptedState::Authenticated) => {

                    let sender_channel =
                        enc.new_channel(self.0.config.window_size,
                                        self.0.config.maximum_packet_size);
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"direct-tcpip");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size);

                        // max packet size.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size);

                        enc.write.extend_ssh_string(host_to_connect.as_bytes());
                        enc.write.push_u32_be(port_to_connect); // sender channel id.
                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    sender_channel
                }
                _ => return Err(Error::Inconsistent),
            }
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }

    /// Send EOF to a channel
    pub fn channel_eof(&mut self, channel: ChannelId) {
        self.0.byte(channel, msg::CHANNEL_EOF);
    }

    /// Send data or "extended data" to the given channel. Extended
    /// data can be used to multiplex different data streams into a
    /// single channel.
    pub fn data(&mut self,
                channel: ChannelId,
                extended: Option<u32>,
                data: &[u8])
                -> Result<usize, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            try!(enc.data(channel, extended, data))
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }

    /// Request a pseudo-terminal with the given characteristics.
    pub fn request_pty(&mut self,
                       channel: ChannelId,
                       want_reply: bool,
                       term: &str,
                       col_width: u32,
                       row_height: u32,
                       pix_width: u32,
                       pix_height: u32,
                       terminal_modes: &[(Pty, u32)]) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"pty-req");
                    enc.write.push(if want_reply { 1 } else { 0 });

                    enc.write.extend_ssh_string(term.as_bytes());
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);

                    enc.write.push_u32_be((5 * (1 + terminal_modes.len())) as u32);
                    for &(code, value) in terminal_modes {
                        enc.write.push(code as u8);
                        enc.write.push_u32_be(value)
                    }
                    // 0 code (to terminate the list)
                    enc.write.push(0);
                    enc.write.push_u32_be(0);
                });
            }
        }
    }

    /// Request X11 forwarding through an already opened X11
    /// channel. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.1)
    /// for security issues related to cookies.
    pub fn request_x11(&mut self,
                       channel: ChannelId,
                       want_reply: bool,
                       single_connection: bool,
                       x11_authentication_protocol: &str,
                       x11_authentication_cookie: &str,
                       x11_screen_number: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"x11-req");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.push(if single_connection { 1 } else { 0 });
                    enc.write.extend_ssh_string(x11_authentication_protocol.as_bytes());
                    enc.write.extend_ssh_string(x11_authentication_cookie.as_bytes());
                    enc.write.push_u32_be(x11_screen_number);
                });
            }
        }
    }

    /// Set a remote environment variable.
    pub fn set_env(&mut self,
                   channel: ChannelId,
                   want_reply: bool,
                   variable_name: &str,
                   variable_value: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"env");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(variable_name.as_bytes());
                    enc.write.extend_ssh_string(variable_value.as_bytes());
                });
            }
        }
    }


    /// Request a remote shell.
    pub fn request_shell(&mut self, want_reply: bool, channel: ChannelId) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"shell");
                    enc.write.push(if want_reply { 1 } else { 0 });
                });
            }
        }
    }

    /// Execute a remote program (will be passed to a shell). This can
    /// be used to implement scp (by calling a remote scp and
    /// tunneling to its standard input).
    pub fn exec(&mut self, channel: ChannelId, want_reply: bool, command: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exec");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(command.as_bytes());
                });
            }
        }
    }

    /// Signal a remote process.
    pub fn signal(&mut self, channel: ChannelId, signal: Sig) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"signal");
                    enc.write.push(0);
                    enc.write.extend_ssh_string(signal.name().as_bytes());
                });
            }
        }
    }

    /// Request the start of a subsystem with the given name.
    pub fn request_subsystem(&mut self, want_reply: bool, channel: ChannelId, name: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"subsystem");
                    enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.extend_ssh_string(name.as_bytes());
                });
            }
        }
    }

    /// Inform the server that our window size has changed.
    pub fn window_change(&mut self,
                         channel: ChannelId,
                         col_width: u32,
                         row_height: u32,
                         pix_width: u32,
                         pix_height: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"window-change");
                    enc.write.push(0); // this packet never wants reply
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);
                });
            }
        }
    }

    /// Request the forwarding of a remote port to the client. The
    /// server will then open forwarding channels (which cause the
    /// client to call `.channel_open_forwarded_tcpip()`).
    pub fn tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"tcpip-forward");
                enc.write.push(if want_reply { 1 } else { 0 });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }

    /// Cancel a previous forwarding request.
    pub fn cancel_tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"cancel-tcpip-forward");
                enc.write.push(if want_reply { 1 } else { 0 });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }
}


/// Record a host's public key into the user's known_hosts file.
#[cfg(target_os = "windows")]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<(), Error> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Record a host's public key into the user's known_hosts file.
#[cfg(not(target_os = "windows"))]
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<(), Error> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        super::learn_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(target_os = "windows")]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error<E>> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push("ssh");
        known_host_file.push("known_hosts");
        super::check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}

/// Check whether the host is known, from its standard location.
#[cfg(not(target_os = "windows"))]
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error> {
    if let Some(mut known_host_file) = std::env::home_dir() {
        known_host_file.push(".ssh");
        known_host_file.push("known_hosts");
        debug!("known_hosts file = {:?}", known_host_file);
        super::check_known_hosts_path(host, port, pubkey, &known_host_file)
    } else {
        Err(Error::NoHomeDir)
    }
}
