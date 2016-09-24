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
use std::io::{Write, BufRead};
use std;
use std::sync::Arc;
use rand;
use rand::Rng;
use time;

use super::*;

use negociation::{Select, Named};
use msg;
use cipher::CipherT;

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
    /// Authentication rejections must happen in constant time for security reasons. Thrussh does not handle this by default.
    pub auth_rejection_time: time::Duration,
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
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME"),
                               env!("CARGO_PKG_VERSION")),
            methods: auth::MethodSet::all(),
            auth_banner: None,
            auth_rejection_time: time::Duration::seconds(1),
            keys: Vec::new(),
            window_size: 1 << 30,
            maximum_packet_size: 1 << 20,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct Connection {
    read_buffer: SSHBuffer,
    session: Session,
}


#[derive(Debug)]
pub struct Session(CommonSession<Config>);

impl std::ops::Deref for Connection {
    type Target = Session;
    fn deref(&self) -> &Session {
        &self.session
    }
}

impl std::ops::DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Session {
        &mut self.session
    }
}

pub trait Handler {

    /// Check authentication using the "none" method. Thrussh makes
    /// sure rejection happens in time `config.auth_rejection_time`,
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_none(&mut self, user: &str) -> bool {
        false
    }

    /// Check authentication using the "password" method. Thrussh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_password(&mut self, user: &str, password: &str) -> bool {
        false
    }

    /// Check authentication using the "publickey" method. Thrussh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_publickey(&mut self, user: &str, public_key: &key::PublicKey) -> bool {
        false
    }


    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    fn channel_close(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when a new session channel is created.
    #[allow(unused_variables)]
    fn channel_open_session(&mut self, channel: u32, session: &mut Session) {}

    /// Called when a new X11 channel is created.
    #[allow(unused_variables)]
    fn channel_open_x11(&mut self,
                        channel: u32,
                        originator_address: &str,
                        originator_port: u32,
                        session: &mut Session) {
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_direct_tcpip(&mut self,
                                 channel: u32,
                                 host_to_connect: &str,
                                 port_to_connect: u32,
                                 originator_address: &str,
                                 originator_port: u32,
                                 session: &mut Session) {
    }

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    fn data(&mut self, channel: u32, data: &[u8], session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    fn extended_data(&mut self,
                     channel: u32,
                     code: u32,
                     data: &[u8],
                     session: &mut Session)
                     -> Result<(), Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

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
                   -> Result<(), Error> {
        Ok(())
    }

    /// The client requests an X11 connection.
    #[allow(unused_variables)]
    fn x11_request(&mut self,
                   channel: u32,
                   single_connection: bool,
                   x11_auth_protocol: &str,
                   x11_auth_cookie: &str,
                   x11_screen_number: u32,
                   session: &mut Session)
                   -> Result<(), Error> {
        Ok(())
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    #[allow(unused_variables)]
    fn env_request(&mut self,
                   channel: u32,
                   variable_name: &str,
                   variable_value: &str,
                   session: &mut Session)
                   -> Result<(), Error> {
        Ok(())
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    fn shell_request(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// The client sends a command to execute, to be passed to a shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    fn exec_request(&mut self,
                    channel: u32,
                    data: &[u8],
                    session: &mut Session)
                    -> Result<(), Error> {
        Ok(())
    }

    /// The client asks to start the subsystem with the given name (such as sftp).
    #[allow(unused_variables)]
    fn subsystem_request(&mut self,
                         channel: u32,
                         name: &str,
                         session: &mut Session)
                         -> Result<(), Error> {
        Ok(())
    }

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    fn window_change_request(&mut self,
                             channel: u32,
                             col_width: u32,
                             row_height: u32,
                             pix_width: u32,
                             pix_height: u32,
                             session: &mut Session)
                             -> Result<(), Error> {
        Ok(())
    }

    /// The client is sending a signal (usually to pass to the currently running process).
    #[allow(unused_variables)]
    fn signal(&mut self,
              channel: u32,
              signal_name: Sig,
              session: &mut Session)
              -> Result<(), Error> {
        Ok(())
    }

    /// Used for reverse-forwarding ports, see [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn tcpip_forward(&mut self,
                     address: &str,
                     port: u32,
                     session: &mut Session)
                     -> Result<(), Error> {
        Ok(())
    }

    /// Used to stop the reverse-forwarding of a port, see [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(&mut self,
                            address: &str,
                            port: u32,
                            session: &mut Session)
                            -> Result<(), Error> {
        Ok(())
    }
}

impl KexInit {
    pub fn server_parse<C: CipherT>(mut self,
                                    config: &Config,
                                    cipher: &mut C,
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

    pub fn server_write<'k, C: CipherT>(&mut self,
                                        config: &'k Config,
                                        cipher: &mut C,
                                        write_buffer: &mut SSHBuffer) {
        self.exchange.server_kex_init.clear();
        negociation::write_kex(&config.preferred, &mut self.exchange.server_kex_init);
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer)
    }
}

impl KexDh {
    pub fn parse<C: CipherT>(mut self,
                             config: &Config,
                             buffer: &mut CryptoVec,
                             buffer2: &mut CryptoVec,
                             cipher: &mut C,
                             buf: &[u8],
                             write_buffer: &mut SSHBuffer)
                             -> Result<Kex, Error> {

        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            // Else, process it.
            assert!(buf[0] == msg::KEX_ECDH_INIT);
            let mut r = buf.reader(1);
            self.exchange.client_ephemeral.extend(try!(r.read_string()));
            let kex = try!(super::kex::Algorithm::server_dh(self.names.kex,
                                                            &mut self.exchange,
                                                            buf));
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
                                     .compute_exchange_hash(&config.keys[kexdhdone.key],
                                                            &kexdhdone.exchange,
                                                            buffer));

            buffer.clear();
            buffer.push(msg::KEX_ECDH_REPLY);
            config.keys[kexdhdone.key].push_to(buffer);
            // Server ephemeral
            buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
            // Hash signature
            config.keys[kexdhdone.key].add_signature(buffer, &hash);
            cipher.write(&buffer, write_buffer);

            cipher.write(&[msg::NEWKEYS], write_buffer);

            Ok(Kex::NewKeys(try!(kexdhdone.compute_keys(hash, buffer, buffer2, true))))
        }
    }
}

const AT_LEAST_ONE_PACKET:u8 = 1;
const AUTH_REJECTED:u8 = 2;


impl Connection {
    #[doc(hidden)]
    pub fn new(config: Arc<Config>) -> Self {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().server_id.as_bytes());

        let session = Connection {
            read_buffer: SSHBuffer::new(),
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
        };
        session
    }

    /// Process all packets available in the buffer, and returns
    /// whether at least one complete packet was read. `buffer` and `buffer2` are work spaces mostly used to compute keys. They are cleared before using, hence nothing is expected from them.
    #[doc(hidden)]
    pub fn read<R: BufRead, S: Handler>(&mut self,
                                        server: &mut S,
                                        stream: &mut R,
                                        buffer: &mut CryptoVec,
                                        buffer2: &mut CryptoVec)
                                        -> Result<u8, Error> {

        let mut flags = 0;

        loop {
            if flags & AUTH_REJECTED != 0 {
                // We have to wait.
                return Ok(flags)
            }
            match self.read_one_packet(server, stream, buffer, buffer2) {

                Ok(one_packet_flags) => {
                    flags |= one_packet_flags;
                    if one_packet_flags & AT_LEAST_ONE_PACKET == 0 {
                        // We don't have a full packet.
                        return Ok(flags)
                    }
                },
                Err(Error::IO(e)) => {
                    match e.kind() {
                        std::io::ErrorKind::UnexpectedEof |
                        std::io::ErrorKind::WouldBlock => return Ok(flags),
                        _ => return Err(Error::IO(e)),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    // returns whether a complete packet has been read.
    fn read_one_packet<R: BufRead, S: Handler>(&mut self,
                                               server: &mut S,
                                               stream: &mut R,
                                               buffer: &mut CryptoVec,
                                               buffer2: &mut CryptoVec)
                                               -> Result<u8, Error> {
        debug!("read {:?}", self.session);
        // Special case for the beginning.
        if self.session.0.encrypted.is_none() && self.session.0.kex.is_none() {

            let mut exchange;
            {
                let client_id = try!(self.read_buffer.read_ssh_id(stream));
                if let Some(client_id) = client_id {
                    exchange = Exchange::new();
                    exchange.client_id.extend(client_id);
                    debug!("client id, exchange = {:?}", exchange);
                } else {
                    return Ok(0)
                }
            }
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
            return Ok(AT_LEAST_ONE_PACKET);

        }



        // In all other cases:
        if let Some(buf) = try!(self.session.0.cipher.read(stream, &mut self.read_buffer)) {
            debug!("read buf = {:?}", buf);
            // Handle the transport layer.
            if buf[0] == msg::DISCONNECT {
                // transport
                return Err(Error::Disconnect);
            }
            if buf[0] <= 4 {
                return Ok(AT_LEAST_ONE_PACKET);
            }

            // Handle key exchange/re-exchange.
            match std::mem::replace(&mut self.session.0.kex, None) {

                Some(Kex::KexInit(kexinit)) => {
                    if kexinit.algo.is_some() || buf[0] == msg::KEXINIT ||
                       self.session.0.encrypted.is_none() {
                        let next_kex = kexinit.server_parse(self.session.0.config.as_ref(),
                                                            &mut self.session.0.cipher,
                                                            buf,
                                                            &mut self.session.0.write_buffer);
                        match next_kex {
                            Ok(next_kex) => {
                                self.session.0.kex = Some(next_kex);
                                return Ok(AT_LEAST_ONE_PACKET);
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
                                               buffer,
                                               buffer2,
                                               &mut self.session.0.cipher,
                                               buf,
                                               &mut self.session.0.write_buffer);
                    match next_kex {
                        Ok(next_kex) => {
                            self.session.0.kex = Some(next_kex);
                            return Ok(AT_LEAST_ONE_PACKET);
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
                    return Ok(AT_LEAST_ONE_PACKET);
                }
                Some(kex) => {
                    self.session.0.kex = Some(kex);
                    return Ok(AT_LEAST_ONE_PACKET);
                }
                None => {}
            }
            if ! try!(self.session.server_read_encrypted(server, buf, buffer)) {
                self.session.flush();
                Ok(AT_LEAST_ONE_PACKET | AUTH_REJECTED)
            } else {
                self.session.flush();
                Ok(AT_LEAST_ONE_PACKET)
            }
        } else {
            Ok(0)
        }
    }

    /// Write all computed packets to the stream. Returns whether all packets have been sent.
    pub fn write<W: Write>(&mut self, stream: &mut W) -> Result<bool, Error> {
        self.session.0.write_buffer.write_all(stream)
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

    /// Send a "success" reply to a /global/ request (requests without a channel number, such as TCP/IP forwarding or cancelling). Always call this function if the request was successful (it checks whether the client expects an answer).
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

    /// Send a "success" reply to a channel request. Always call this function if the request was successful (it checks whether the client expects an answer).
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

    /// Send data to a channel. On session channels, `extended` can be used to encode standard error by passing `Some(1)`, and stdout by passing `None`.
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

    /// Inform the client of whether they may perform control-S/control-Q flow control. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(&mut self, channel: u32, client_can_do: bool) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                assert!(channel.confirmed);
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"xon-xoff");
                    enc.write.push(0);
                    enc.write.push(if client_can_do {
                        1
                    } else {
                        0
                    });
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
                    enc.write.push(if core_dumped {
                        1
                    } else {
                        0
                    });
                    enc.write.extend_ssh_string(error_message.as_bytes());
                    enc.write.extend_ssh_string(language_tag.as_bytes());
                })
            }
        }
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a local port for which forwarding has been requested. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The TCP/IP packets can then be tunneled through the channel using `.data()`.
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

                    let mut sender_channel = 0;
                    while enc.channels.contains_key(&sender_channel) || sender_channel == 0 {
                        sender_channel = rand::thread_rng().gen()
                    }
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(b"forwarded-tcpip");
                        enc.write.push_u32_be(sender_channel); // sender channel id.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size); // max packet size.
                        //
                        enc.write.extend_ssh_string(connected_address.as_bytes());
                        enc.write.push_u32_be(connected_port); // sender channel id.
                        enc.write.extend_ssh_string(originator_address.as_bytes());
                        enc.write.push_u32_be(originator_port); // sender channel id.
                    });
                    enc.new_channel(sender_channel,
                                    self.0.config.window_size,
                                    self.0.config.maximum_packet_size);
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

use std::io::{ BufReader };
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Entry;

use std::net::ToSocketAddrs;
use mio::{Token, Poll, PollOpt, Ready, Events};
use mio::tcp::{TcpStream, TcpListener};
use std::time::Duration;
const SERVER_TOKEN:Token = Token(0);

struct ClientRecord<H> {
    stream: BufReader<TcpStream>,
    addr: std::net::SocketAddr,
    is_parked: bool,
    connection: Connection,
    handler:H
}


pub struct Server<H:Handler> {
    config: Arc<Config>,
    events: Events,
    handler: H,
    socket: TcpListener,
    sessions: Sessions<H>
}

struct Sessions<H> {
    poll: Poll,
    sessions: HashMap<Token, ClientRecord<H>>,
    parked: VecDeque<(Token, time::SteadyTime)>,
}

impl<H:Handler+Clone> Server<H> {

    pub fn new(config:Config, addr:&str, handler:H) -> Self {

        let addr = addr.to_socket_addrs().unwrap().next().unwrap();
        let socket = TcpListener::bind(&addr).unwrap();
        
        let poll = Poll::new().unwrap();

        poll.register(&socket, Token(0), Ready::all(), PollOpt::edge()).unwrap();

        Server {
            config: Arc::new(config),
            events: Events::with_capacity(1024),
            handler: handler,
            socket: socket,
            sessions: Sessions {
                poll: poll,
                parked: VecDeque::new(),
                sessions: HashMap::new(),
            }
        }
    }

    pub fn run(&mut self) {

        let mut buffer0 = CryptoVec::new();
        let mut buffer1 = CryptoVec::new();
        
        loop {
            match self.sessions.poll.poll(&mut self.events, Some(Duration::from_secs(1))) {
                Ok(n) if n > 0 => {
                    debug!("events: {:?}", n);
                    for events in self.events.into_iter() {
                        if events.token() == SERVER_TOKEN {

                            if let Ok((client_socket, addr)) = self.socket.accept() {
                                let mut id = Token(0);
                                while self.sessions.sessions.contains_key(&id) || id.0 == 0 {
                                    id = Token(rand::thread_rng().gen())
                                }
                                self.sessions.poll.register(&client_socket, id, Ready::all(), PollOpt::edge()).unwrap();
                                let co = server::Connection::new(self.config.clone());

                                let rec = ClientRecord {
                                    stream: BufReader::new(client_socket),
                                    addr: addr, is_parked: false, connection:co, handler: self.handler.clone()
                                };
                                
                                self.sessions.sessions.insert(id, rec);
                            }
                        } else {
                            let id = events.token();
                            if events.kind().is_error() || events.kind().is_hup() {
                                match self.sessions.sessions.entry(id) {
                                    Entry::Occupied(e) => {
                                        debug!("Removing, file {}, line {}", file!(), line!());
                                        let rec = e.remove();
                                        self.sessions.poll.deregister(rec.stream.get_ref()).unwrap();
                                    },
                                    _ => {}
                                };

                            } else {
                                if events.kind().is_readable() {
                                    self.sessions.read(id, false, &mut buffer0, &mut buffer1)
                                }
                                if events.kind().is_writable() {
                                    self.sessions.write(id)
                                }
                            }
                        }
                    }
                },
                Ok(_) => {
                    let parking_time = self.config.as_ref().auth_rejection_time;
                    self.sessions.unpark(parking_time, &mut buffer0, &mut buffer1)
                }
                Err(e) => {
                    debug!("{:?}", e);
                }
            }
        }
    }
}

impl<H:Handler> Sessions<H> {
    fn read(&mut self, id:Token, unpark: bool, buffer0: &mut CryptoVec, buffer1:&mut CryptoVec) {

        match self.sessions.entry(id) {
            Entry::Occupied(mut e) => {

                let time = time::SteadyTime::now();
                {
                    let rec = e.get_mut();

                    if !rec.is_parked || unpark {
                        debug!("reading from: {:?}", rec.addr);
                        rec.is_parked = false;
                        match rec.connection.read(&mut rec.handler, &mut rec.stream, buffer0, buffer1) {

                            Ok(r) => {
                                if r & AUTH_REJECTED != 0 {
                                    debug!("parking");
                                    self.parked.push_back((id, time));
                                    rec.is_parked = true;
                                }
                                return
                            },
                            Err(err) => debug!("error: {:?}", err)
                        }
                    } else {
                        return
                    }
                }
                debug!("Removing, file {}, line {}", file!(), line!());
                let rec = e.remove();
                self.poll.deregister(rec.stream.get_ref()).unwrap();
            },
            _ => {}
        };        
    }

    fn write(&mut self, id:Token) {

        match self.sessions.entry(id) {
            Entry::Occupied(mut e) => {

                let result = {
                    let rec = e.get_mut();
                    rec.connection.write(rec.stream.get_mut())
                };
                if result.is_err() {
                    debug!("Removing, file {}, line {}", file!(), line!());
                    let rec = e.remove();
                    self.poll.deregister(rec.stream.get_ref()).unwrap();                            
                }

            },
            _ => {}
        }

    }
    
    fn unpark(&mut self, parking_time:time::Duration, buffer0:&mut CryptoVec, buffer1:&mut CryptoVec) {
        if let Some((id, time)) = self.parked.pop_front() {
            if time + parking_time < time::SteadyTime::now() {
                // We can go.
                self.read(id, true, buffer0, buffer1);
                self.write(id)
            } else {
                self.parked.push_front((id,time))
            }
        }
    }
}
