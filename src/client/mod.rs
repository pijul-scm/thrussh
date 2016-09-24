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
use std::io::{Write, BufRead};
use std;

use {Disconnect, Error, Limits, Sig, ChannelOpenFailure, parse_public_key};
use encoding::Reader;
use key;
use msg;
use auth;
use cipher::CipherT;
use negociation;
use cryptovec::CryptoVec;
use negociation::Select;
use session::*;
use sshbuffer::*;
use cipher;
use kex;
use rand;
use rand::Rng;
use ring::signature;
use pty::Pty;
use untrusted;
use encoding::Encoding;
mod encrypted;

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
    pub preferred: negociation::Preferred,
}

impl std::default::Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME")
                               env!("CARGO_PKG_VERSION")),
            limits: Limits::default(),
            window_size: 200000,
            maximum_packet_size: 200000,
            preferred: Default::default(),
        }
    }
}

/// Client connection.
#[derive(Debug)]
#[doc(hidden)]
pub struct Connection {
    read_buffer: SSHBuffer,
    pub session: Session,
}

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

#[derive(Debug)]
pub struct Session(CommonSession<Config>);

pub trait Handler {
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
    fn channel_open_confirmation(&mut self,
                                 channel: u32,
                                 session: &mut Session)
                                 -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server closes a channel.
    #[allow(unused_variables)]
    fn channel_close(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }

    /// Called when the server rejected our request to open a channel.
    #[allow(unused_variables)]
    fn channel_open_failure(&mut self,
                            channel: u32,
                            reason: ChannelOpenFailure,
                            description: &str,
                            language: &str,
                            session: &mut Session)
                            -> Result<(), Error> {
        Ok(())
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_forwarded_tcpip(&mut self,
                                    channel: u32,
                                    connected_address: &str,
                                    connected_port: u32,
                                    originator_address: &str,
                                    originator_port: u32,
                                    session: &mut Session) {
    }

    /// Called when the server sends us data. The `extended_code` parameter is a stream identifier, `None` is usually the standard output, and `Some(1)` is the standard error. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2).
    #[allow(unused_variables)]
    fn data(&mut self,
            channel: u32,
            extended_code: Option<u32>,
            data: &[u8],
            session: &mut Session)
            -> Result<(), Error> {
        Ok(())
    }

    /// The server informs this client of whether the client may perform control-S/control-Q flow control. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    #[allow(unused_variables)]
    fn xon_xoff(&mut self,
                channel: u32,
                client_can_do: bool,
                session: &mut Session)
                -> Result<(), Error> {
        Ok(())
    }

    /// The remote process has exited, with the given exit status.
    #[allow(unused_variables)]
    fn exit_status(&mut self,
                   channel: u32,
                   exit_status: u32,
                   session: &mut Session)
                   -> Result<(), Error> {
        Ok(())
    }

    /// The remote process exited upon receiving a signal.
    #[allow(unused_variables)]
    fn exit_signal(&mut self,
                   channel: u32,
                   signal_name: Sig,
                   core_dumped: bool,
                   error_message: &str,
                   lang_tag: &str,
                   session: &mut Session)
                   -> Result<(), Error> {
        Ok(())
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes. This is useful if this client wants to
    /// send huge amounts of data, for instance if we have called
    /// `Session::data` before, and it returned less than the
    /// full amount of data.
    #[allow(unused_variables)]
    fn window_adjusted(&mut self, channel: u32, session: &mut Session) -> Result<(), Error> {
        Ok(())
    }
}









impl KexInit {
    pub fn client_parse<C: CipherT>(mut self,
                                    config: &Config,
                                    cipher: &mut C,
                                    buf: &[u8],
                                    write_buffer: &mut SSHBuffer)
                                    -> Result<KexDhDone, Error> {

        let algo = if self.algo.is_none() {
            // read algorithms from packet.
            self.exchange.server_kex_init.extend(buf);
            try!(super::negociation::Client::read_kex(buf, &config.preferred))
        } else {
            return Err(Error::Kex);
        };
        if !self.sent {
            self.client_write(config, cipher, write_buffer)
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
        self.exchange.client_kex_init.truncate(i0);


        Ok(KexDhDone {
            exchange: self.exchange,
            names: algo,
            kex: kex,
            key: 0,
            session_id: self.session_id,
        })
    }

    pub fn client_write<'k, C: CipherT>(&mut self,
                                        config: &'k Config,
                                        cipher: &mut C,
                                        write_buffer: &mut SSHBuffer) {
        self.exchange.client_kex_init.clear();
        negociation::write_kex(&config.preferred, &mut self.exchange.client_kex_init);
        self.sent = true;
        cipher.write(&self.exchange.client_kex_init, write_buffer)
    }
}


impl KexDhDone {
    pub fn client_parse<C: CipherT, H: Handler>(mut self,
                                                buffer: &mut CryptoVec,
                                                buffer2: &mut CryptoVec,
                                                client: &mut H,
                                                cipher: &mut C,
                                                buf: &[u8],
                                                write_buffer: &mut SSHBuffer)
                                                -> Result<Kex, Error> {

        if self.names.ignore_guessed {
            self.names.ignore_guessed = false;
            Ok(Kex::KexDhDone(self))
        } else {
            debug!("kexdhdone");
            // We've sent ECDH_INIT, waiting for ECDH_REPLY
            if buf[0] == msg::KEX_ECDH_REPLY {
                let hash = {
                    let mut reader = buf.reader(1);
                    let pubkey = try!(reader.read_string()); // server public key.
                    let pubkey = try!(parse_public_key(pubkey));
                    if !try!(client.check_server_key(&pubkey)) {
                        return Err(Error::UnknownKey);
                    }
                    let server_ephemeral = try!(reader.read_string());
                    self.exchange.server_ephemeral.extend(server_ephemeral);
                    let signature = try!(reader.read_string());

                    try!(self.kex.compute_shared_secret(&self.exchange.server_ephemeral));

                    let hash = try!(self.kex.compute_exchange_hash(&pubkey, &self.exchange, buffer));

                    let signature = {
                        let mut sig_reader = signature.reader(0);
                        let sig_type = try!(sig_reader.read_string());
                        assert_eq!(sig_type, b"ssh-ed25519");
                        try!(sig_reader.read_string())
                    };

                    match pubkey {
                        key::PublicKey::Ed25519(ref pubkey) => {
                            assert!(signature::verify(&signature::ED25519,
                                                      untrusted::Input::from(&pubkey),
                                                      untrusted::Input::from(hash.as_ref()),
                                                      untrusted::Input::from(signature)).is_ok());
                        }
                    };
                    debug!("signature = {:?}", signature);
                    debug!("exchange = {:?}", self.exchange);
                    hash
                };
                let mut newkeys = try!(self.compute_keys(hash, buffer, buffer2, false));
                cipher.write(&[msg::NEWKEYS], write_buffer);
                newkeys.sent = true;
                Ok(Kex::NewKeys(newkeys))
            } else {
                return Err(Error::Inconsistent);
            }
        }
    }
}


impl Connection {
    pub fn new(config: Arc<Config>) -> Self {
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().client_id.as_bytes());
        let session = Connection {
            read_buffer: SSHBuffer::new(),
            session: Session(CommonSession {
                write_buffer: write_buffer,
                auth_user: String::new(),
                auth_method: None,
                kex: None,
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
    /// whether at least one complete packet was read.
    /// `buffer` and `buffer2` are work spaces mostly used to compute keys. They are cleared before using, hence nothing is expected from them.
    pub fn read<R: BufRead, C: Handler>(&mut self,
                                        client: &mut C,
                                        stream: &mut R,
                                        buffer: &mut CryptoVec,
                                        buffer2: &mut CryptoVec)
                                        -> Result<bool, Error> {
        if self.session.0.disconnected {
            return Err(Error::Disconnect);
        }
        let mut at_least_one_was_read = false;
        loop {
            match self.read_one_packet(client, stream, buffer, buffer2) {
                Ok(true) => at_least_one_was_read = true,
                Ok(false) => return Ok(at_least_one_was_read),
                Err(Error::IO(e)) => {
                    match e.kind() {
                        std::io::ErrorKind::UnexpectedEof |
                        std::io::ErrorKind::WouldBlock => return Ok(at_least_one_was_read),
                        _ => return Err(Error::IO(e)),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn read_one_packet<R: BufRead, C: Handler>(&mut self,
                                               client: &mut C,
                                               stream: &mut R,
                                               buffer: &mut CryptoVec,
                                               buffer2: &mut CryptoVec)
                                               -> Result<bool, Error> {

        if self.session.0.encrypted.is_none() && self.session.0.kex.is_none() {

            let mut exchange;
            {
                let server_id = try!(self.read_buffer.read_ssh_id(stream));
                if let Some(server_id) = server_id {
                    exchange = Exchange::new();
                    exchange.server_id.extend(server_id);
                    debug!("server id, exchange = {:?}", exchange);
                } else {
                    return Ok(false);
                }
            }
            // Preparing the response
            exchange.client_id.extend(self.session.0.config.as_ref().client_id.as_bytes());
            let mut kexinit = KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            };
            kexinit.client_write(self.session.0.config.as_ref(),
                                 &mut self.session.0.cipher,
                                 &mut self.session.0.write_buffer);
            self.session.0.kex = Some(Kex::KexInit(kexinit));
            return Ok(true);
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
                return Ok(true);
            }

            // Handle key exchange/re-exchange.
            match std::mem::replace(&mut self.session.0.kex, None) {
                Some(Kex::KexInit(kexinit)) => {
                    if kexinit.algo.is_some() || buf[0] == msg::KEXINIT ||
                       self.session.0.encrypted.is_none() {
                        let kexdhdone = kexinit.client_parse(self.session.0.config.as_ref(),
                                                             &mut self.session.0.cipher,
                                                             buf,
                                                             &mut self.session.0.write_buffer);

                        match kexdhdone {
                            Ok(kexdhdone) => {
                                self.session.0.kex = Some(Kex::KexDhDone(kexdhdone));
                                return Ok(true);
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        try!(self.session.client_read_encrypted(client, buf, buffer));
                    }
                }
                Some(Kex::KexDhDone(kexdhdone)) => {
                    let kex = kexdhdone.client_parse(buffer,
                                                     buffer2,
                                                     client,
                                                     &mut self.session.0.cipher,
                                                     buf,
                                                     &mut self.session.0.write_buffer);
                    match kex {
                        Ok(kex) => {
                            self.session.0.kex = Some(kex);
                            return Ok(true);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Some(Kex::NewKeys(newkeys)) => {
                    if buf[0] != msg::NEWKEYS {
                        return Err(Error::NewKeys);
                    }
                    self.session.0.encrypted(EncryptedState::WaitingServiceRequest, newkeys);
                    // Ok, NEWKEYS received, now encrypted.
                    // We can't use flush here, because self.buffers is borrowed.
                    let p = b"\x05\0\0\0\x0Cssh-userauth";
                    self.session.0.cipher.write(p, &mut self.session.0.write_buffer);
                }
                Some(kex) => self.session.0.kex = Some(kex),
                None => {
                    debug!("calling read_encrypted");
                    try!(self.session.client_read_encrypted(client, buf, buffer));
                }
            }
            self.session.flush();
            Ok(true)
        } else {
            Ok(false)
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
                    kexinit.client_write(&self.0.config.as_ref(),
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

    /// Retrieves the current user.
    pub fn auth_user(&self) -> &str {
        &self.0.auth_user
    }

    /// Sends a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.0.disconnect(reason, description, language_tag);
    }

    /// Set the user.
    pub fn set_auth_user(&mut self, user: &str) {
        self.0.auth_user.clear();
        self.0.auth_user.push_str(user)
    }

    /// Set the authentication method.
    pub fn set_auth_public_key(&mut self, key: key::Algorithm) {
        self.0.auth_method = Some(auth::Method::PublicKey {
            key: key,
        });
    }

    /// Set the authentication method.
    pub fn set_auth_password(&mut self, password: String) {
        self.0.auth_method = Some(auth::Method::Password {
            password: password,
        });
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
    pub fn channel_is_open(&self, channel: u32) -> bool {
        if let Some(ref enc) = self.0.encrypted {
            if let Some(ref channel) = enc.channels.get(&channel) {
                return channel.confirmed;
            }
        }
        false
    }

    /// Tests whether we need an authentication method (for instance if the last attempt failed).
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
    pub fn channel_open_session(&mut self) -> Option<u32> {
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
                        enc.write.extend_ssh_string(b"session");
                        enc.write.push_u32_be(sender_channel); // sender channel id.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size); // max packet size.
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


    /// Request an X11 channel, on which the X11 protocol may be tunneled.
    pub fn channel_open_x11(&mut self,
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
                        enc.write.extend_ssh_string(b"x11");
                        enc.write.push_u32_be(sender_channel); // sender channel id.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size); // max packet size.
                        //
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

    /// Open a TCP/IP forwarding channel. This is usually done when a connection comes to a locally forwarded TCP/IP port. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The TCP/IP packets can then be tunneled through the channel using `.data()`.
    pub fn channel_open_direct_tcpip(&mut self,
                                     host_to_connect: &str,
                                     port_to_connect: u32,
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
                        enc.write.extend_ssh_string(b"direct-tcpip");
                        enc.write.push_u32_be(sender_channel); // sender channel id.
                        enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                        enc.write.push_u32_be(self.0.config.as_ref().maximum_packet_size); // max packet size.
                        //
                        enc.write.extend_ssh_string(host_to_connect.as_bytes());
                        enc.write.push_u32_be(port_to_connect); // sender channel id.
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

    /// Send data or "extended data" to the given channel. Extended data can be used to multiplex different data streams into a single channel.
    pub fn data(&mut self,
                channel: u32,
                extended: Option<u32>,
                data: &[u8])
                -> Result<usize, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            try!(enc.data(channel, extended, data))
        } else {
            return Err(Error::Inconsistent);
        };
        self.flush();
        Ok(result)
    }

    /// Request a pseudo-terminal with the given characteristics.
    pub fn request_pty(&mut self,
                       channel: u32,
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
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });

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
        self.flush();
    }

    /// Request X11 forwarding through an already opened X11 channel. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.1) for security issues related to cookies.
    pub fn request_x11(&mut self,
                       channel: u32,
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
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });
                    enc.write.push(if single_connection {
                        1
                    } else {
                        0
                    });
                    enc.write.extend_ssh_string(x11_authentication_protocol.as_bytes());
                    enc.write.extend_ssh_string(x11_authentication_cookie.as_bytes());
                    enc.write.push_u32_be(x11_screen_number);
                });
            }
        }
        self.flush();
    }

    /// Set a remote environment variable.
    pub fn set_env(&mut self,
                   channel: u32,
                   want_reply: bool,
                   variable_name: &str,
                   variable_value: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"env");
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });
                    enc.write.extend_ssh_string(variable_name.as_bytes());
                    enc.write.extend_ssh_string(variable_value.as_bytes());
                });
            }
        }
        self.flush();
    }


    /// Request a remote shell.
    pub fn request_shell(&mut self, want_reply: bool, channel: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"shell");
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });
                });
            }
        }
        self.flush();
    }

    /// Execute a remote program (will be passed to a shell). This can be used to implement scp (by calling a remote scp and tunneling to its standard input).
    pub fn exec(&mut self, channel: u32, want_reply: bool, command: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exec");
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });
                    enc.write.extend_ssh_string(command.as_bytes());
                });
            }
        }
        self.flush();
    }

    /// Signal a remote process.
    pub fn signal(&mut self, channel: u32, signal: Sig) {
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
        self.flush();
    }

    /// Request the start of a subsystem with the given name.
    pub fn request_subsystem(&mut self, want_reply: bool, channel: u32, name: &str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"subsystem");
                    enc.write.push(if want_reply {
                        1
                    } else {
                        0
                    });
                    enc.write.extend_ssh_string(name.as_bytes());
                });
            }
        }
        self.flush();
    }

    /// Inform the server that our window size has changed.
    pub fn window_change(&mut self,
                         channel: u32,
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
        self.flush();
    }

    /// Request the forwarding of a remote port to the client. The server will then open forwarding channels (which cause the client to call `.channel_open_forwarded_tcpip()`).
    pub fn tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"tcpip-forward");
                enc.write.push(if want_reply {
                    1
                } else {
                    0
                });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
        self.flush();
    }

    /// Cancel a previous forwarding request.
    pub fn cancel_tcpip_forward(&mut self, want_reply: bool, address: &str, port: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"cancel-tcpip-forward");
                enc.write.push(if want_reply {
                    1
                } else {
                    0
                });
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
        self.flush();
    }
}




use mio::{Token, Events, Ready, Poll, PollOpt};
use mio::tcp::TcpStream;

use std::default::Default;

use regex::Regex;
use std::net::ToSocketAddrs;
use std::fs::File;
// use std::ascii::AsciiExt; // case-insensitive equality.

use std::io::{BufReader};

use std::path::{Path, PathBuf};

#[derive(Debug)]
enum RunUntil {
    ChannelOpened(u32),
    ChannelClosed(u32),
}

pub struct Client {
    poll: Poll,
    events: Events,
    host: String,
    port: u16,
    buffer0: CryptoVec,
    buffer1: CryptoVec,
    connection: Connection,
}

pub struct Connected {
    client: Client,
    stream:BufReader<TcpStream>
}
use std::ops::{Deref, DerefMut};
impl Deref for Connected {
    type Target = Session;
    fn deref(&self) -> &Self::Target {
        &self.client.connection.session
    }
}

impl Deref for Client {
    type Target = Session;
    fn deref(&self) -> &Self::Target {
        &self.connection.session
    }
}
impl DerefMut for Connected {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client.connection.session
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection.session
    }
}


struct C<'s> {
    host: &'s str,
    port: u16,
    key_is_known: Option<bool>,
    key: Option<key::PublicKey>
}

impl<'s> Handler for C<'s> {
    fn check_server_key(&mut self, pubkey: &key::PublicKey) -> Result<bool, Error> {
        let known = try!(check_known_hosts(&self.host, self.port, pubkey));
        self.key_is_known = Some(known);
        debug!("Is key known? {:?}", known);
        if !known {
            self.key = Some(pubkey.clone())
        }
        Ok(true)
    }
}

fn ssh_path() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        if let Some(mut dir) = std::env::home_dir() {
            dir.push("ssh");
            return Some(dir);
        }
    } else {
        if let Some(mut dir) = std::env::home_dir() {
            dir.push(".ssh");
            return Some(dir);
        }
    }
    None
}

use user;

impl Client {
    /// Create a client, allocating a `Poll` and an SSH client configuration.
    pub fn new() -> Self {
        let poll = Poll::new().unwrap();
        Client {
            poll: poll,
            events: Events::with_capacity(1024),
            host: "".to_string(),
            port: 22,
            buffer0: CryptoVec::new(),
            buffer1: CryptoVec::new(),
            connection: Connection::new(Arc::new(Default::default())),
        }
    }


    /// Parse the ssh config file, from its default location (`~/.ssh/config` on Unix, and `%USERPROFILE%/ssh/config` on Windows.
    ///
    /// ```
    /// use thrussh::client::*;
    /// Client::new().default_ssh_config().unwrap();
    /// ```
    pub fn default_ssh_config(&mut self) -> Result<Option<std::net::SocketAddr>, Error> {
        if let Some(mut path) = ssh_path() {
            path.push("config");
            let addr = try!(self.ssh_config(&path));

            if !self.connection.has_auth_method() {

                for i in self.connection.config().preferred.key {
                    path.pop();
                    path.push(i.identity_file());
                    debug!("identity file: {:?}", path);
                    if let Ok(sec) = super::load_secret_key(&path) {
                        self.connection.set_auth_public_key(sec)
                    }
                }
            }
            if self.connection.auth_user().len() == 0 {
                self.connection.set_auth_user(&try!(user::get_user_name()))
            }
            Ok(addr)
        } else {
            Err(Error::NoSSHConfig)
        }
    }

    /// Read an SSH configuration file from a custom path.
    pub fn ssh_config<P: AsRef<Path>>
        (&mut self,
         path: P)
         -> Result<Option<std::net::SocketAddr>, Error> {

            let mut f = try!(File::open(path));

            let mut bufr = BufReader::new(&mut f);
            let mut buffer = String::new();
            let re = Regex::new(r#"^\s*([A-Za-z]+)\s*(=|\s)\s*("([^"]*)"|([^\s]*))\s*$"#).unwrap();

            // let mut has_canonical_match = false;
            let mut is_on = false;
            // First pass.
            loop {
                buffer.clear();
                if try!(bufr.read_line(&mut buffer)) == 0 {
                    break;
                }
                if let Some(cap) = re.captures(&buffer) {
                    if is_on {
                        match (cap.at(1), cap.at(4).or(cap.at(5))) {
                            (Some("Host"), _) => is_on = false,
                            (Some("Match"), _) => is_on = false,

                            //
                            (Some("HostName"), Some(hostname)) => {
                                self.host.clear();
                                self.host.push_str(hostname)
                            }
                            (Some("IdentityFile"), Some(path)) => {
                                debug!("identity file: {:?}", path);
                                self.connection.set_auth_public_key(try!(super::load_secret_key(path)))
                            }
                            (Some("Port"), Some(port_)) => self.port = port_.parse().unwrap_or(0),
                            (Some("User"), Some(user_)) => self.connection.set_auth_user(user_),
                            (Some(a),Some(b)) => println!("unsupported option: {:?} {:?}", a,b),
                            _ => {}
                        }
                    } else {
                        match (cap.at(1), cap.at(4).or(cap.at(5))) {
                            (Some("Host"), Some(h)) if h == self.host => is_on = true,
                            // (Some("Match"), Some(h))  => break,
                            _ => {}
                        }
                    }
                }
            }
            /*if has_canonical_match {
                // Second pass, looking only for canonical matches.
                try!(bufr.seek(std::io::SeekFrom::Start(0)));
            }*/
            Ok(None)
        }

    /// Set the host name, replacing any previously set name. This can be a name from the config file.
    pub fn set_host(&mut self, host: &str) {
        self.host.clear();
        self.host.push_str(host)
    }

    /// Set the port.
    pub fn set_port(&mut self, port: u16) {
        self.port = port
    }

    /// Connect this client.
    pub fn connect(self) -> Result<Connected, Error> {
        let addr = try!((&self.host[..], self.port).to_socket_addrs()).next().unwrap();
        let sock = try!(TcpStream::connect(&addr));
        try!(self.poll
             .register(&sock, Token(0), Ready::all(), PollOpt::edge()));
        Ok(Connected {
            client: self,
            stream: BufReader::new(sock)
        })
    }
}




impl Connected {

    /// Attempt (or re-attempt) authentication. Returns `Ok(Some(…))`
    /// if the server's host key is unknown, `Ok(None)` if
    /// authentication succeeded, and errors in all other cases.
    pub fn authenticate(&mut self) -> Result<Option<key::PublicKey>, Error> {
        try!(self.client.poll
             .reregister(self.stream.get_ref(),
                         Token(0),
                         Ready::all(),
                         PollOpt::edge()));
        let mut d = C {
            host: &self.client.host,
            port: self.client.port,
            key_is_known: None,
            key: None
        };


        try!(self.client.connection.write(self.stream.get_mut()));
        loop {
            match self.client.poll.poll(&mut self.client.events, None) {
                Ok(n) if n > 0 => {
                    for events in self.client.events.into_iter() {
                        let kind = events.kind();
                        if kind.is_error() || kind.is_hup() {
                            return Err(From::from(Error::HUP));
                        } else {
                            if kind.is_readable() {
                                try!(self.client.connection.read(&mut d,
                                                                 &mut self.stream,
                                                                 &mut self.client.buffer0,
                                                                 &mut self.client.buffer1));
                                if d.key_is_known == Some(false) {
                                    return Ok(Some(d.key.unwrap()))
                                }

                                if self.client.connection
                                    .session
                                    .is_authenticated() {
                                        return Ok(None)
                                    }
                                if !self.client.connection
                                    .session
                                    .has_auth_method() {
                                        return Err(Error::AuthFailed)
                                    }
                            }
                            if kind.is_writable() {
                                try!(self.client.connection.write(self.stream.get_mut()));
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        if self.client.connection.session.is_authenticated() {
            Ok(None)
        } else {
            Err(Error::AuthFailed)
        }
    }
    /// Write the host into the known_hosts file.
    pub fn learn_host(&self, key: &key::PublicKey) -> Result<(), Error> {
        try!(learn_known_hosts(&self.client.host, self.client.port, key));
        Ok(())
    }

    /// Waiting until the given channel is open.
    pub fn wait_channel_open<C: Handler>(&mut self,
                                                          c: &mut C,
                                                          channel: u32)
                                                          -> Result<(), Error> {
        try!(self.client.poll
             .reregister(self.stream.get_ref(),
                         Token(0),
                         Ready::all(),
                         PollOpt::edge()));
        try!(self.run(c, Some(RunUntil::ChannelOpened(channel))));
        Ok(())
    }

    /// Waiting until the given channel is closed by the remote side.
    pub fn wait_channel_close<C: Handler>(&mut self,
                                                           c: &mut C,
                                                           channel: u32)
                                                           -> Result<(), Error> {
        try!(self.client.poll
             .reregister(self.stream.get_ref(),
                         Token(0),
                         Ready::all(),
                         PollOpt::edge()));
        try!(self.run(c, Some(RunUntil::ChannelClosed(channel))));
        Ok(())
    }

    fn run<R: Handler>(&mut self,
                       client: &mut R,
                       until: Option<RunUntil>)
                       -> Result<(), Error> {

        try!(self.client.connection.write(self.stream.get_mut()));
        loop {
            match self.client.poll.poll(&mut self.client.events, None) {
                Ok(n) if n > 0 => {

                    for events in self.client.events.into_iter() {
                        let kind = events.kind();
                        if kind.is_error() || kind.is_hup() {
                            return Err(From::from(Error::HUP));
                        } else {
                            if kind.is_readable() {
                                try!(self.client.connection.read(client,
                                                          &mut self.stream,
                                                          &mut self.client.buffer0,
                                                          &mut self.client.buffer1));
                                match until {
                                    Some(RunUntil::ChannelOpened(x)) if self.client.connection
                                        .session
                                        .channel_is_open(x) => {
                                            return Ok(());
                                        }
                                    Some(RunUntil::ChannelClosed(x)) if !self.client.connection
                                        .session
                                        .channel_is_open(x) => {
                                            return Ok(());
                                        }
                                    _ => {}
                                }
                            }
                            if kind.is_writable() {
                                try!(self.client.connection.write(self.stream.get_mut()));
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Run the protocol until some condition is satisfied on the client.
    pub fn run_until<R: Handler, F: Fn(&Client, &mut R) -> bool>
        (&mut self,
         client: &mut R,
         until: F)
         -> Result<(), Error> {
            try!(self.client.connection.write(self.stream.get_mut()));
            while !until(&self.client, client) {
                match self.client.poll.poll(&mut self.client.events, None) {
                    Ok(n) if n > 0 => {
                        for events in self.client.events.into_iter() {
                            let kind = events.kind();
                            if kind.is_error() || kind.is_hup() {
                                return Err(From::from(Error::HUP));
                            } else {
                                if kind.is_readable() {
                                    try!(self.client.connection.read(client,
                                                                     &mut self.stream,
                                                                     &mut self.client.buffer0,
                                                                     &mut self.client.buffer1));
                                }
                                if kind.is_writable() {
                                    try!(self.client.connection.write(self.stream.get_mut()));
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
            Ok(())
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
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error> {
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
