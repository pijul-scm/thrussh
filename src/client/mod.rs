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

use {Disconnect, Error, Limits, Sig, ChannelOpenFailure};
use key;
use msg;
use auth;
use cipher::CipherT;
use negociation;
use cryptobuf::CryptoBuf;
use negociation::Select;
use session::*;
use sshbuffer::*;
use cipher;
use kex;
use rand;
use rand::Rng;
use pty::Pty;

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
        {
            let buf = self.exchange.client_kex_init.as_slice();
            cipher.write(&buf[i0..], write_buffer);
        }
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
        cipher.write(self.exchange.client_kex_init.as_slice(), write_buffer)
    }
}


impl KexDhDone {
    pub fn client_parse<C: CipherT, H: Handler>(mut self,
                                                buffer: &mut CryptoBuf,
                                                buffer2: &mut CryptoBuf,
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
                let hash = try!(self.client_compute_exchange_hash(client, buf, buffer));
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
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
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
                                        buffer: &mut CryptoBuf,
                                        buffer2: &mut CryptoBuf)
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
                                               buffer: &mut CryptoBuf,
                                               buffer2: &mut CryptoBuf)
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
                    let p = [msg::SERVICE_REQUEST,
                             0,
                             0,
                             0,
                             12,
                             b's',
                             b's',
                             b'h',
                             b'-',
                             b'u',
                             b's',
                             b'e',
                             b'r',
                             b'a',
                             b'u',
                             b't',
                             b'h'];
                    self.session.0.cipher.write(&p, &mut self.session.0.write_buffer);
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
    pub fn needs_auth_method(&self) -> bool {
        self.0.auth_method.is_none()
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
