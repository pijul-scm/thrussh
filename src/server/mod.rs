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
use std::io::{Write, Read, BufRead};
use std;
use std::sync::Arc;
use futures;
use super::*;

use negociation::{Select, Named};
use msg;
use cipher::CipherPair;

use sshbuffer::*;
use negociation;
use key::PubKey;
use encoding::{Encoding, Reader};

use session::*;
use auth;

mod encrypted;

#[derive(Debug)]
pub struct Config {
    /// The server ID string sent at the beginning of the protocol.
    pub server_id: String,
    /// Authentication methods proposed to the client.
    pub methods: auth::MethodSet,
    /// The authentication banner, usually a warning message shown to the client.
    pub auth_banner: Option<&'static str>,
    /// Authentication rejections must happen in constant time for
    /// security reasons. Thrussh does not handle this by default.
    pub auth_rejection_time: std::time::Duration,
    /// The server's keys. The first key pair in the client's preference order will be chosen.
    pub keys: Vec<key::Algorithm>,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Lists of preferred algorithms.
    pub preferred: Preferred,
    /// Maximal number of allowed authentication attempts.
    pub max_auth_attempts: usize,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME"),
                               env!("CARGO_PKG_VERSION")),
            methods: auth::MethodSet::all(),
            auth_banner: None,
            auth_rejection_time: std::time::Duration::from_secs(1),
            keys: Vec::new(),
            window_size: 1 << 30,
            maximum_packet_size: 1 << 20,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10,
            connection_timeout: Some(std::time::Duration::from_secs(600)),
        }
    }
}

#[doc(hidden)]
pub struct Connection<R, H:Handler> {
    read_buffer: SSHBuffer,
    session: Session,
    stream: BufReader<R>,
    state: Option<ConnectionState>,
    encrypted_future: Option<encrypted::ReadEncrypted<H>>,
    buffer: CryptoVec,
    buffer2: CryptoVec,
    handler: H,
    timeout: Option<Timeout>
}


pub struct Session(CommonSession<Config>);

impl<R,H:Handler> std::ops::Deref for Connection<R, H> {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.session
    }
}

impl<R,H:Handler> std::ops::DerefMut for Connection<R,H> {
    fn deref_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

#[derive(Debug)]
pub struct Response<'a> {
    pos: super::encoding::Position<'a>,
    n: u32,
}

impl<'a> Iterator for Response<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            self.pos.read_string().ok()
        }
    }
}

pub enum Auth {
    Reject,
    Accept,
    Partial { name: String, instructions: String, prompts: Vec<(String, bool)> },
}

pub trait Handler {
    type FutureAuth: Future<Item = Auth, Error = Error>;
    type FutureUnit: Future<Item = (), Error = Error>;
    type FutureBool: Future<Item = bool, Error = Error>;

    /// Check authentication using the "none" method. Thrussh makes
    /// sure rejection happens in time `config.auth_rejection_time`,
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_none(&mut self, user: &str) -> Self::FutureBool;

    /// Check authentication using the "password" method. Thrussh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_password(&mut self, user: &str, password: &str) -> Self::FutureBool;

    /// Check authentication using the "publickey" method. Thrussh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_publickey(&mut self, user: &str, public_key: &key::PublicKey) -> Self::FutureBool;

    /// Check authentication using the "keyboard-interactive"
    /// method. Thrussh makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_keyboard_interactive(&mut self,
                                 user: &str,
                                 submethods: &str,
                                 response: Option<Response>)
                                 -> Self::FutureAuth;

    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    fn channel_close(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit;

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit;

    /// Called when a new session channel is created.
    #[allow(unused_variables)]
    fn channel_open_session(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit;

    /// Called when a new X11 channel is created.
    #[allow(unused_variables)]
    fn channel_open_x11(&mut self,
                        channel: u32,
                        originator_address: &str,
                        originator_port: u32,
                        session: &mut Session)
                        -> Self::FutureUnit;

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_direct_tcpip(&mut self,
                                 channel: u32,
                                 host_to_connect: &str,
                                 port_to_connect: u32,
                                 originator_address: &str,
                                 originator_port: u32,
                                 session: &mut Session)
                                 -> Self::FutureUnit;

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    fn data(&mut self, channel: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit;

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    fn extended_data(&mut self, channel: u32, code: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit;

    /// Called when the network window is adjusted, meaning that we can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit;

    /// The client requests a pseudo-terminal with the given specifications.
    #[allow(unused_variables)]
    fn pty_request(&mut self,
                   channel: u32,
                   term: &str,
                   col_width: u32,
                   row_height: u32,
                   pix_width: u32,
                   pix_height: u32,
                   modes: &[(Pty, u32)],
                   session: &mut Session)
                   -> Self::FutureUnit;

    /// The client requests an X11 connection.
    #[allow(unused_variables)]
    fn x11_request(&mut self,
                   channel: u32,
                   single_connection: bool,
                   x11_auth_protocol: &str,
                   x11_auth_cookie: &str,
                   x11_screen_number: u32,
                   session: &mut Session)
                   -> Self::FutureUnit;

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    #[allow(unused_variables)]
    fn env_request(&mut self,
                   channel: u32,
                   variable_name: &str,
                   variable_value: &str,
                   session: &mut Session)
                   -> Self::FutureUnit;

    /// The client requests a shell.
    #[allow(unused_variables)]
    fn shell_request(&mut self, channel: u32, session: &mut Session) -> Self::FutureUnit;

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    fn exec_request(&mut self, channel: u32, data: &[u8], session: &mut Session) -> Self::FutureUnit;

    /// The client asks to start the subsystem with the given name (such as sftp).
    #[allow(unused_variables)]
    fn subsystem_request(&mut self, channel: u32, name: &str, session: &mut Session) -> Self::FutureUnit;

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    fn window_change_request(&mut self,
                             channel: u32,
                             col_width: u32,
                             row_height: u32,
                             pix_width: u32,
                             pix_height: u32,
                             session: &mut Session)
                             -> Self::FutureUnit;

    /// The client is sending a signal (usually to pass to the currently running process).
    #[allow(unused_variables)]
    fn signal(&mut self, channel: u32, signal_name: Sig, session: &mut Session) -> Self::FutureUnit;

    /// Used for reverse-forwarding ports, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn tcpip_forward(&mut self, address: &str, port: u32, session: &mut Session) -> Self::FutureBool;

    /// Used to stop the reverse-forwarding of a port, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(&mut self, address: &str, port: u32, session: &mut Session) -> Self::FutureBool;
}

impl KexInit {
    pub fn server_parse(mut self,
                        config: &Config,
                        cipher: &mut cipher::CipherPair,
                        buf: &[u8],
                        write_buffer: &mut SSHBuffer)
                        -> Result<Kex, Error> {

        if buf[0] == msg::KEXINIT {
            debug!("server parse");
            let algo = if self.algo.is_none() {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                try!(super::negociation::Server::read_kex(buf, &config.preferred))
            } else {
                return Err(Error::Kex);
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)
            }
            let mut key = 0;
            debug!("config {:?} algo {:?}", config.keys, algo.key);
            while key < config.keys.len() && config.keys[key].name() != algo.key.as_ref() {
                key += 1
            }
            let next_kex = if key < config.keys.len() {
                Kex::KexDh(KexDh {
                    exchange: self.exchange,
                    key: key,
                    names: algo,
                    session_id: self.session_id,
                })
            } else {
                return Err(Error::UnknownKey);
            };

            Ok(next_kex)
        } else {
            Ok(Kex::KexInit(self))
        }
    }

    pub fn server_write(&mut self,
                        config: &Config,
                        cipher: &mut cipher::CipherPair,
                        write_buffer: &mut SSHBuffer) {
        self.exchange.server_kex_init.clear();
        negociation::write_kex(&config.preferred, &mut self.exchange.server_kex_init);
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer)
    }
}

impl KexDh {
    pub fn parse(mut self,
                 config: &Config,
                 buffer: &mut CryptoVec,
                 buffer2: &mut CryptoVec,
                 cipher: &mut CipherPair,
                 buf: &[u8],
                 write_buffer: &mut SSHBuffer)
                 -> Result<Kex, Error> {
        debug!("KexDh: parse");
        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            // Else, process it.
            assert!(buf[0] == msg::KEX_ECDH_INIT);
            let mut r = buf.reader(1);
            self.exchange.client_ephemeral.extend(try!(r.read_string()));
            let kex =
                try!(super::kex::Algorithm::server_dh(self.names.kex, &mut self.exchange, buf));
            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: self.exchange,
                kex: kex,
                key: self.key,
                names: self.names,
                session_id: self.session_id,
            };

            let hash = try!(kexdhdone.kex
                .compute_exchange_hash(&config.keys[kexdhdone.key], &kexdhdone.exchange, buffer));

            buffer.clear();
            buffer.push(msg::KEX_ECDH_REPLY);
            config.keys[kexdhdone.key].push_to(buffer);
            // Server ephemeral
            buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
            // Hash signature
            debug!(" >>>>>>>>>>>>>>> signing with key {:?}", kexdhdone.key);
            config.keys[kexdhdone.key].add_signature(buffer, &hash);
            cipher.write(&buffer, write_buffer);

            cipher.write(&[msg::NEWKEYS], write_buffer);

            Ok(Kex::NewKeys(try!(kexdhdone.compute_keys(hash, buffer, buffer2, true))))
        }
    }
}

#[derive(Clone, Copy)]
pub enum Status {
    Ok,
    AuthRejected,
    Disconnect
}

#[derive(Debug)]
enum ConnectionState {
    ReadSshId { sshid: ReadSshId },
    Read,
    Write
}
/*
impl<'a, H:Handler, R:BufRead> futures::Future for NextPacket<'a, H, R> {
    type Item = Status;
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            NextPacket::Done(status) => Ok(Async::Ready(status)),
            NextPacket::Transport => Ok(Async::Ready(Status::Ok)),
            NextPacket::ReadEncrypted(ref mut enc) => {
                try_ready!(enc.poll());
                // session.flush();
                Ok(Async::Ready(Status::Ok))
            },
            NextPacket::ReadSshId { ref mut sshid, ref mut connection } => {
                try_ready!(sshid.poll());
            }
        }
    }
}
struct ClientRecord<H:Handler> {
    stream: BufReader<TcpStream>,
    addr: std::net::SocketAddr,
    connection: Connection,
    buffer0: CryptoVec,
    buffer1: CryptoVec,
    handler: H,
    config: Arc<Config>,
    l: Arc<Handle>,
}

enum State<'a, H:Handler, R:BufRead+'a> {
    Read(NextPacket<'a, H, R>),
    Write,
    Timeout(Timeout),
}
*/
impl<R: Read + Write, H:Handler> Connection<R, H> {
    #[doc(hidden)]
    pub fn new(config: Arc<Config>, stream: R, handler: H, timeout: Option<Timeout>) -> Self {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().server_id.as_bytes());
        let mut connection = Connection {
            read_buffer: SSHBuffer::new(),
            timeout: timeout,
            session: Session(CommonSession {
                write_buffer: write_buffer,
                kex: None,
                auth_user: String::new(),
                auth_method: None, // Client only.
                cipher: cipher::CLEAR_PAIR,
                encrypted: None,
                config: config,
                wants_reply: false,
                disconnected: false,
            }),
            stream: BufReader::new(stream),
            state: Some(ConnectionState::ReadSshId { sshid: read_ssh_id() }),
            encrypted_future: None,
            handler: handler,
            buffer: CryptoVec::new(),
            buffer2: CryptoVec::new()
        };
        connection.session.flush();
        connection
    }
}

impl<H: Handler> Future for Connection<TcpStream, H> {

    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // If timeout, shutdown the socket.
        if let Some(ref mut timeout) = self.timeout {
            match try_nb!(timeout.poll()) {
                Async::Ready(()) => {
                    try_nb!(self.stream.get_mut().shutdown(std::net::Shutdown::Both));
                    debug!("Timeout, shutdown");
                    return Ok(Async::Ready(()));
                }
                Async::NotReady => {}
            }
        }
        loop {
            debug!("polling, state = {:?}", self.state);
            try_ready!(self.atomic_poll())
        }
    }
}

impl<H:Handler> Connection<TcpStream, H> {
    fn atomic_poll(&mut self) -> Poll<(), Error> {
        let encrypted_future_done = if let Some(ref mut read_encrypted) = self.encrypted_future {
            debug!("Running encrypted future");
            try_nb!(read_encrypted.poll(&mut self.session, &mut self.buffer));
            true
        } else {
            false
        };
        if encrypted_future_done {
            self.encrypted_future = None;
        }


        debug!("read");
        // Special case for the beginning.
        match std::mem::replace(&mut self.state, None) {
            None => {
                Ok(Async::Ready(()))
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
                    Err(e) => Err(e),
                    _ => {
                        self.read_buffer.bytes += sshid.client_id_len + 2;
                        let mut exchange = Exchange::new();
                        exchange.client_id.extend(sshid.client_id());
                        // Preparing the response
                        exchange.server_id.extend(self.session.0.config.as_ref().server_id.as_bytes());
                        let mut kexinit = KexInit {
                            exchange: exchange,
                            algo: None,
                            sent: false,
                            session_id: None,
                        };
                        kexinit.server_write(self.session.0.config.as_ref(),
                                             &mut self.session.0.cipher,
                                             &mut self.session.0.write_buffer);
                        self.session.0.kex = Some(Kex::KexInit(kexinit));
                        self.state = Some(ConnectionState::Write);
                        Ok(Async::Ready(()))
                    }
                }
            },
            Some(ConnectionState::Write) => {
                self.state = Some(ConnectionState::Write);
                self.session.flush();
                try_nb!(self.session.0.write_buffer.write_all(self.stream.get_mut()));
                self.state = Some(ConnectionState::Read);
                Ok(Async::Ready(()))
            },
            Some(ConnectionState::Read) => {
                
                self.state = Some(ConnectionState::Read);
                let buf = try_nb!(self.session.0.cipher.read(&mut self.stream, &mut self.read_buffer));
                debug!("read buf = {:?}", buf);
                // Handle the transport layer.
                if buf[0] == msg::DISCONNECT {
                    // transport
                    return Ok(Async::Ready(()));
                }
                // If we don't disconnect, keep the state.
                self.state = Some(ConnectionState::Write);

                // Handle transport layer packets.
                if buf[0] <= 4 {
                    return Ok(Async::Ready(()))
                }

                // Handle key exchange/re-exchange.
                match std::mem::replace(&mut self.session.0.kex, None) {
                    Some(Kex::KexInit(kexinit)) => {
                        if kexinit.algo.is_some() || buf[0] == msg::KEXINIT ||
                            self.session.0.encrypted.is_none() {
                                let next_kex = kexinit.server_parse(
                                    self.session.0.config.as_ref(),
                                    &mut self.session.0.cipher,
                                    buf,
                                    &mut self.session.0.write_buffer
                                );
                                match next_kex {
                                    Ok(next_kex) => {
                                        self.session.0.kex = Some(next_kex);
                                        return Ok(Async::Ready(()))
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                        // Else, i.e. if the other side has not started
                        // the key exchange, process its packets by simple
                        // not returning.
                    }
                    Some(Kex::KexDh(kexdh)) => {
                        let next_kex = kexdh.parse(self.session.0.config.as_ref(),
                                                   &mut self.buffer,
                                                   &mut self.buffer2,
                                                   &mut self.session.0.cipher,
                                                   buf,
                                                   &mut self.session.0.write_buffer);
                        match next_kex {
                            Ok(next_kex) => {
                                self.session.0.kex = Some(next_kex);
                                return Ok(Async::Ready(()));
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Some(Kex::NewKeys(newkeys)) => {
                        if buf[0] != msg::NEWKEYS {
                            return Err(Error::NewKeys);
                        }
                        // Ok, NEWKEYS received, now encrypted.
                        self.session.0.encrypted(EncryptedState::WaitingServiceRequest, newkeys);
                        return Ok(Async::Ready(()));
                    }
                    Some(kex) => {
                        self.session.0.kex = Some(kex);
                        return Ok(Async::Ready(()));
                    }
                    None => {}
                }

                // Start a key re-exchange, if the client is asking for it.
                if buf[0] == msg::KEXINIT {
                    // Now, if we're encrypted:
                    if let Some(ref mut enc) = self.session.0.encrypted {

                        // If we're not currently rekeying, but buf is a rekey request
                        if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                            let kexinit = KexInit::received_rekey(
                                exchange,
                                try!(negociation::Server::read_kex(buf, &self.session.0.config.as_ref().preferred)),
                                &enc.session_id
                            );
                            self.session.0.kex = Some(try!(kexinit.server_parse(self.session.0.config.as_ref(),
                                                                                &mut self.session.0.cipher,
                                                                                buf,
                                                                                &mut self.session.0.write_buffer)));
                        }
                        return Ok(Async::Ready(()))
                    }
                }

                // No kex going on, and the version id is done.
                self.encrypted_future = Some(try!(self.session.server_read_encrypted(&mut self.handler, buf, &mut self.buffer)));
                Ok(Async::Ready(()))
            }
        }
    }
}

impl Session {
    fn flush(&mut self) {
        if let Some(ref mut enc) = self.0.encrypted {
            if enc.flush(&self.0.config.as_ref().limits,
                         &mut self.0.cipher,
                         &mut self.0.write_buffer) {
                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                    let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                    kexinit.server_write(&self.0.config.as_ref(),
                                         &mut self.0.cipher,
                                         &mut self.0.write_buffer);
                    enc.rekey = Some(Kex::KexInit(kexinit))
                }
            }
        }
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// Sends a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.0.disconnect(reason, description, language_tag);
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        if self.0.wants_reply {
            if let Some(ref mut enc) = self.0.encrypted {
                self.0.wants_reply = false;
                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
            }
        }
    }

    /// Send a "failure" reply to a global request.
    pub fn request_failure(&mut self) {
        if let Some(ref mut enc) = self.0.encrypted {
            self.0.wants_reply = false;
            push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
        }
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_SUCCESS);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    /// Send a "failure" reply to a global request.
    pub fn channel_failure(&mut self, channel: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get_mut(&channel) {
                assert!(channel.confirmed);
                if channel.wants_reply {
                    channel.wants_reply = false;
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_FAILURE);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub fn channel_open_failure(&mut self,
                                channel: u32,
                                reason: ChannelOpenFailure,
                                description: &str,
                                language: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                enc.write.push_u32_be(channel);
                enc.write.push_u32_be(reason as u32);
                enc.write.extend_ssh_string(description.as_bytes());
                enc.write.extend_ssh_string(language.as_bytes());
            })
        }
    }


    /// Close a channel.
    pub fn close(&mut self, channel: u32) {
        self.0.byte(channel, msg::CHANNEL_CLOSE);
        self.flush();
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: u32) {
        self.0.byte(channel, msg::CHANNEL_EOF);
        self.flush();
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    pub fn data(&mut self,
                channel: u32,
                extended: Option<u32>,
                data: &[u8])
                -> Result<usize, Error> {
        if let Some(ref mut enc) = self.0.encrypted {
            enc.data(channel, extended, data)
        } else {
            unreachable!()
        }
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(&mut self, channel: u32, client_can_do: bool) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"xon-xoff");
                    enc.write.push(0);
                    enc.write.push(if client_can_do { 1 } else { 0 });
                })
            }
        }
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(&mut self, channel: u32, exit_status: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exit-status");
                    enc.write.push(0);
                    enc.write.push_u32_be(exit_status)
                })
            }
        }
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub fn exit_signal_request(&mut self,
                               channel: u32,
                               signal: Sig,
                               core_dumped: bool,
                               error_message: &str,
                               language_tag: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exit-signal");
                    enc.write.push(0);
                    enc.write.extend_ssh_string(signal.name().as_bytes());
                    enc.write.push(if core_dumped { 1 } else { 0 });
                    enc.write.extend_ssh_string(error_message.as_bytes());
                    enc.write.extend_ssh_string(language_tag.as_bytes());
                })
            }
        }
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_forwarded_tcpip(&mut self,
                                        connected_address: &str,
                                        connected_port: u32,
                                        originator_address: &str,
                                        originator_port: u32)
                                        -> Option<u32> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            match enc.state {
                Some(EncryptedState::Authenticated) => {
                    debug!("sending open request");

                    let sender_channel =
                        enc.new_channel(self.0.config.window_size,
                                        self.0.config.maximum_packet_size);
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"forwarded-tcpip");

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel);

                        // window.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size);

                        // max packet size.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size);

                        enc.write.extend_ssh_string(connected_address.as_bytes());
                        enc.write.push_u32_be(connected_port); // sender channel id.
                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    Some(sender_channel)
                }
                _ => None,
            }
        } else {
            None
        };
        self.flush();
        result
    }
}

use std::io::BufReader;
use std::net::ToSocketAddrs;

use futures::stream::Stream;
use futures::{Future, Poll, Async};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Timeout, Handle};

pub fn run<H: Handler + Clone + 'static>(config: Arc<Config>, addr: &str, handler: H) {


    let addr = addr.to_socket_addrs().unwrap().next().unwrap();
    let mut l = Core::new().unwrap();
    let handle = Arc::new(l.handle());
    let socket = TcpListener::bind(&addr, &handle).unwrap();

    let done = socket.incoming().for_each(move |(socket, addr)| {

        let timeout = if let Some(t) = config.connection_timeout {
            Some(try!(Timeout::new(t, &handle)))
        } else {
            None
        };
        let connection = server::Connection::new(
            config.clone(),
            socket,
            handler.clone(),
            timeout
        );
        handle.spawn(connection.map_err(|err| println!("err {:?}", err)));
        Ok(())
    });
    l.run(done).unwrap();
}
