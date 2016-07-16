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

use {Error, Limits, Client, ChannelType, ChannelParameters, ClientSession};
use super::key;
use super::msg;
use super::auth;
use super::cipher::CipherT;
use super::negociation;
use std::io::{Write, BufRead};
use ReturnCode;
use std;
use cryptobuf::CryptoBuf;
use negociation::Select;
use state::*;
use sshbuffer::*;
use std::collections::HashMap;
use cipher;
use kex;
use pty;

use rand;
use rand::{Rng};

mod encrypted;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub limits: Limits,
    pub window_size: u32,
    pub maxpacket: u32,
    pub preferred: negociation::Preferred,
}

impl std::default::Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME")
                               env!("CARGO_PKG_VERSION")),
            // Following the recommendations of
            // https://tools.ietf.org/html/rfc4253#section-9
            limits: Limits {
                rekey_write_limit: 1 << 30, // 1 Gb
                rekey_read_limit: 1 << 30, // 1 Gb
                rekey_time_limit_s: 3600.0
            },
            window_size: 200000,
            maxpacket: 200000,
            preferred: negociation::PREFERRED,
        }
    }
}

#[derive(Debug)]
pub struct Connection<'a> {
    buffers: SSHBuffers,
    state: Option<ServerState<Arc<Config>>>,
    auth_method: Option<auth::Method<'a, key::Algorithm>>,
    config: Arc<Config>
}

impl KexInit {
    pub fn client_parse<C:CipherT>(mut self, config:&Config, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<KexDhDone, Error> {

        let algo = if self.algo.is_none() {
            // read algorithms from packet.
            self.exchange.server_kex_init.extend(buf);
            try!(super::negociation::Client::read_kex(buf, &config.preferred))
        } else {
            return Err(Error::Kex)
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
        let kex = try!(kex::Algorithm::client_dh(algo.kex, &mut self.exchange.client_ephemeral, &mut self.exchange.client_kex_init));
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

    pub fn client_write<'k, C:CipherT>(&mut self, config:&'k Config, cipher:&mut C, write_buffer:&mut SSHBuffer) {
        self.exchange.client_kex_init.clear();
        negociation::write_kex(&config.preferred, &mut self.exchange.client_kex_init);
        self.sent = true;
        cipher.write(self.exchange.client_kex_init.as_slice(), write_buffer)
    }
}


impl KexDhDone {
    pub fn client_parse<C:CipherT, Cl:Client>(mut self, buffer:&mut CryptoBuf, buffer2: &mut CryptoBuf, client:&mut Cl, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<Kex, Error> {

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
                return Err(Error::Inconsistent)
            }
        }
    }
}


impl<'a> Connection<'a> {

    pub fn new(config:Arc<Config>) -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        let mut session = Connection {
            buffers: SSHBuffers::new(),
            state: None,
            auth_method: None,
            config: config
        };
        session.buffers.write.send_ssh_id(session.config.as_ref().client_id.as_bytes());
        session
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, C: super::Client> (&mut self,
                                               client: &mut C,
                                               stream: &mut R,
                                               buffer: &mut CryptoBuf,
                                               buffer2: &mut CryptoBuf)
                                               -> Result<super::ReturnCode, Error> {
        debug!("read");
        let state = std::mem::replace(&mut self.state, None);
        // debug!("state = {:?}", state);
        match state {
            None => {
                let mut exchange;
                {
                    let server_id = try!(self.buffers.read.read_ssh_id(stream));
                    if let Some(server_id) = server_id {
                        exchange = Exchange::new();
                        exchange.server_id.extend(server_id);
                        debug!("server id, exchange = {:?}", exchange);
                    } else {
                        return Ok(ReturnCode::WrongPacket);
                    }
                }
                // Preparing the response
                exchange.client_id.extend(self.config.as_ref().client_id.as_bytes());
                let mut kexinit = KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                };
                let mut cipher = cipher::Clear;
                kexinit.client_write(self.config.as_ref(), &mut cipher, &mut self.buffers.write);
                self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                Ok(ReturnCode::Ok)
            },
            Some(ServerState::Kex(kex)) => {

                let mut cipher = cipher::Clear;
                if let Some(buf) = try!(cipher.read(stream, &mut self.buffers.read)) {
                    debug!("buf = {:?}", buf);
                    if buf[0] == msg::DISCONNECT {
                        // transport
                        return Ok(ReturnCode::Disconnect)
                    }
                    if buf[0] <= 4 {
                        self.state = Some(ServerState::Kex(kex));
                        return Ok(ReturnCode::Ok)
                    }
                    match kex {
                        Kex::KexInit(kexinit) => {
                            let kexdhdone = try!(kexinit.client_parse(self.config.as_ref(), &mut cipher, buf, &mut self.buffers.write));
                            self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)))
                        },
                        Kex::KexDhDone(kexdhdone) => {
                            self.state = Some(ServerState::Kex(
                                try!(kexdhdone.client_parse(buffer, buffer2, client, &mut cipher, buf, &mut self.buffers.write))
                            ))
                        },
                        Kex::NewKeys(newkeys) => {
                            if buf[0] != msg::NEWKEYS {
                                return Err(Error::NewKeys)
                            }
                            let encrypted = newkeys.encrypted(EncryptedState::WaitingServiceRequest, self.config.clone());
                            
                            // Ok, NEWKEYS received, now encrypted.
                            // We can't use flush here, because self.buffers is borrowed.
                            let p = [msg::SERVICE_REQUEST,
                                     0,0,0,12, b's',b's',b'h',b'-',b'u',b's',b'e',b'r',b'a',b'u',b't',b'h'];
                            encrypted.cipher.write(&p, &mut self.buffers.write);

                            self.state = Some(ServerState::Encrypted(encrypted));
                        },
                        kex => self.state = Some(ServerState::Kex(kex))
                    }
                    Ok(ReturnCode::Ok)
                } else {
                    self.state = Some(ServerState::Kex(kex));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Encrypted(mut enc)) => {
                if let Some(buf) = try!(enc.cipher.read(stream, &mut self.buffers.read)) {
                    debug!("read buf {:?}", buf);
                    if buf[0] == msg::DISCONNECT {
                        return Ok(ReturnCode::Disconnect)
                    }
                    if buf[0] <= 4 {
                        // transport
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    if buf[0] > 20 && buf[0] < 50 {
                        if let Some(kex) = std::mem::replace(&mut enc.rekey, None) {
                            match kex {
                                Kex::KexInit(kexinit) => {
                                    let kexdhdone = try!(kexinit.client_parse(self.config.as_ref(), &mut enc.cipher, buf, &mut self.buffers.write));
                                    self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)))
                                },
                                Kex::KexDhDone(kexdhdone) => {
                                    self.state = Some(ServerState::Kex(
                                        try!(kexdhdone.client_parse(buffer, buffer2, client, &mut enc.cipher, buf, &mut self.buffers.write))
                                    ))
                                },
                                Kex::NewKeys(newkeys) => {
                                    if buf[0] == msg::NEWKEYS {
                                        enc.exchange = Some(newkeys.exchange);
                                        enc.kex = newkeys.kex;
                                        enc.key = newkeys.key;
                                        enc.cipher = newkeys.cipher;
                                        enc.mac = newkeys.names.mac;
                                    } else {
                                        return Err(Error::Inconsistent)
                                    }
                                }
                                kex => enc.rekey = Some(kex)
                            }
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    if buf[0] == msg::KEXINIT {
                        if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                            let kexinit = KexInit::received_rekey(
                                exchange,
                                try!(negociation::Client::read_kex(buf, &self.config.as_ref().preferred)),
                                &enc.session_id
                            );
                            enc.rekey = Some(
                                Kex::KexDhDone(try!(kexinit.client_parse(self.config.as_ref(), &mut enc.cipher, buf, &mut self.buffers.write)))
                            );
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    debug!("calling read_encrypted");
                    try!(enc.client_read_encrypted(client,
                                                   &self.auth_method,
                                                   buf,
                                                   buffer));

                } else {
                    self.state = Some(ServerState::Encrypted(enc));
                    return Ok(ReturnCode::NotEnoughBytes)
                }
                // If there are pending packets (and we've not started to rekey), flush them.
                self.state = Some(ServerState::Encrypted(enc));
                self.flush();
                Ok(ReturnCode::Ok)
            }
        }
    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self,
                           stream: &mut W)
                           -> Result<bool, Error> {
        debug!("write, buffer: {:?}", self.buffers.write);
        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        Ok(true)
    }

    pub fn authenticate(&mut self, method: auth::Method<'a, key::Algorithm>) -> Result<(), Error> {
        debug!("authenticate: {:?} {:?}", self.state, method);
        let result = match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingAuthRequest(_)) => {
                        enc.write_auth_request(&method);
                        enc.flush(&self.config.as_ref().limits, &mut self.buffers);
                        Ok(())
                    },
                    _ => Err(Error::Inconsistent)
                }
            },
            _ => { Err (Error::Inconsistent) }
        };
        self.auth_method = Some(method);
        result
    }

    pub fn is_authenticated(&self) -> bool {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::Authenticated) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn needs_auth_method(&self) -> Option<auth::M> {
        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingAuthRequest(ref auth_request)) if auth_request.was_rejected => {
                        Some(auth_request.methods)
                    }
                    Some(EncryptedState::WaitingAuthRequest(ref auth_request)) if self.auth_method.is_none() => {
                        Some(auth_request.methods)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn as_client_session<'b>(&'b mut self) -> Option<ClientSession<'b>> {
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => Some(ClientSession(enc)),
            _ => None
        }

    }

    pub fn flush(&mut self) {
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                debug!("flushing");
                if enc.flush(&self.config.as_ref().limits, &mut self.buffers) {

                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                        let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                        kexinit.client_write(&self.config.as_ref(),
                                             &mut enc.cipher,
                                             &mut self.buffers.write);
                        enc.rekey = Some(Kex::KexInit(kexinit))
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'e> ClientSession<'e> {

    pub fn channels(&'e self) -> &'e HashMap<u32, super::ChannelParameters> {
        &self.0.channels
    }

    pub fn channel_open(&mut self, channel_type:super::ChannelType) -> Option<u32> {
        let config = Config::default();
        match self.0.state {
            Some(EncryptedState::Authenticated) => {
                debug!("sending open request");

                let mut sender_channel = 0;
                while self.0.channels.contains_key(&sender_channel) || sender_channel == 0 {
                    sender_channel = rand::thread_rng().gen()
                }
                push_packet!(self.0.write, {
                    self.0.write.push(msg::CHANNEL_OPEN);

                    match channel_type {
                        ChannelType::Session => {
                            self.0.write.extend_ssh_string(b"session");
                            self.0.write.push_u32_be(sender_channel); // sender channel id.
                            self.0.write.push_u32_be(config.window_size); // window.
                            self.0.write.push_u32_be(config.maxpacket); // max packet size.
                        },
                        ChannelType::X11 { originator_address, originator_port } => {
                            self.0.write.extend_ssh_string(b"x11");
                            self.0.write.push_u32_be(sender_channel); // sender channel id.
                            self.0.write.push_u32_be(config.window_size); // window.
                            self.0.write.push_u32_be(config.maxpacket); // max packet size.
                            //
                            self.0.write.extend_ssh_string(originator_address.as_bytes());
                            self.0.write.push_u32_be(originator_port); // sender channel id.
                        },
                        ChannelType::ForwardedTcpip { connected_address, connected_port, originator_address, originator_port } => {
                            self.0.write.extend_ssh_string(b"forwarded-tcpip");
                            self.0.write.push_u32_be(sender_channel); // sender channel id.
                            self.0.write.push_u32_be(config.window_size); // window.
                            self.0.write.push_u32_be(config.maxpacket); // max packet size.
                            //
                            self.0.write.extend_ssh_string(connected_address.as_bytes());
                            self.0.write.push_u32_be(connected_port); // sender channel id.
                            self.0.write.extend_ssh_string(originator_address.as_bytes());
                            self.0.write.push_u32_be(originator_port); // sender channel id.
                        },
                        ChannelType::DirectTcpip { host_to_connect, port_to_connect, originator_address, originator_port } => {
                            self.0.write.extend_ssh_string(b"direct-tcpip");
                            self.0.write.push_u32_be(sender_channel); // sender channel id.
                            self.0.write.push_u32_be(config.window_size); // window.
                            self.0.write.push_u32_be(config.maxpacket); // max packet size.
                            //
                            self.0.write.extend_ssh_string(host_to_connect.as_bytes());
                            self.0.write.push_u32_be(port_to_connect); // sender channel id.
                            self.0.write.extend_ssh_string(originator_address.as_bytes());
                            self.0.write.push_u32_be(originator_port); // sender channel id.
                        }
                    }
                });
                let parameters = ChannelParameters {
                    recipient_channel: 0,
                    sender_channel: sender_channel,
                    sender_window_size: config.window_size,
                    recipient_window_size: 0,
                    sender_maximum_packet_size: config.maxpacket,
                    recipient_maximum_packet_size: 0,
                    confirmed: false,
                    wants_reply: false
                };
                self.0.channels.insert(sender_channel, parameters);
                Some(sender_channel)
            }
            _ => None
        }
    }


    pub fn data(&mut self, channel: u32, extended: Option<u32>, data: &[u8]) -> Result<usize, Error> {
        self.0.data(channel, extended, data)
    }

    pub fn request_pty(&mut self, channel:u32, term:&str, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, terminal_modes:&[(pty::Option, u32)]) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write,{
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"pty-req");
                // self.0.write.push(if want_reply { 1 } else { 0 });
                self.0.write.push(0);

                self.0.write.extend_ssh_string(term.as_bytes());
                self.0.write.push_u32_be(col_width);
                self.0.write.push_u32_be(row_height);
                self.0.write.push_u32_be(pix_width);
                self.0.write.push_u32_be(pix_height);

                self.0.write.push_u32_be((5 * (1+terminal_modes.len())) as u32);
                for &(code, value) in terminal_modes {
                    self.0.write.push(code as u8);
                    self.0.write.push_u32_be(value)
                }
                // 0 code (to terminate the list)
                self.0.write.push(0);
                self.0.write.push_u32_be(0);
            })
        }
    }

    pub fn request_x11(&mut self, channel:u32, single_connection: bool, x11_authentication_protocol: &str, x11_authentication_cookie: &str, x11_screen_number: u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"x11-req");
                // self.0.write.push(if self.want_reply { 1 } else { 0 });
                self.0.write.push(0);
                self.0.write.push(if single_connection { 1 } else { 0 });
                self.0.write.extend_ssh_string(x11_authentication_protocol.as_bytes());
                self.0.write.extend_ssh_string(x11_authentication_cookie.as_bytes());
                self.0.write.push_u32_be(x11_screen_number);
            })
        }
    }

    pub fn set_env(&mut self, channel:u32, variable_name:&str, variable_value:&str) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"env");
                // self.0.write.push(if self.want_reply { 1 } else { 0 });
                self.0.write.push(0);
                self.0.write.extend_ssh_string(variable_name.as_bytes());
                self.0.write.extend_ssh_string(variable_value.as_bytes());
            })
        }
    }


    pub fn request_shell(&mut self, channel:u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"shell");
                // self.0.write.push(if self.want_reply { 1 } else { 0 });
                self.0.write.push(0);
            })
        }
    }

    pub fn exec(&mut self, channel:u32, command:&str) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"exec");
                // self.0.write.push(if self.want_reply { 1 } else { 0 });
                self.0.write.push(0);
                self.0.write.extend_ssh_string(command.as_bytes());
            })
        }
    }

    pub fn request_subsystem(&mut self, channel:u32, name:&str) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"subsystem");
                // self.0.write.push(if self.want_reply { 1 } else { 0 });
                self.0.write.push(0);
                self.0.write.extend_ssh_string(name.as_bytes());
            })
        }
    }

    pub fn window_change(&mut self, channel:u32, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"window-change");
                self.0.write.push(0); // this packet never wants reply
                self.0.write.push_u32_be(col_width);
                self.0.write.push_u32_be(row_height);
                self.0.write.push_u32_be(pix_width);
                self.0.write.push_u32_be(pix_height);
            })
        }
    }
    
    pub fn tcpip_forward(&mut self, address:&str, port:u32) {
        push_packet!(self.0.write, {
            self.0.write.push(msg::GLOBAL_REQUEST);
            self.0.write.extend_ssh_string(b"tcpip-forward");
            // self.0.write.push(if self.want_reply { 1 } else { 0 });
            self.0.write.push(0);
            self.0.write.extend_ssh_string(address.as_bytes());
            self.0.write.push_u32_be(port);
        })
    }

    pub fn cancel_tcpip_forward(&mut self, address:&str, port:u32) {
        push_packet!(self.0.write, {
            self.0.write.push(msg::GLOBAL_REQUEST);
            self.0.write.extend_ssh_string(b"cancel-tcpip-forward");
            // self.0.write.push(if self.want_reply { 1 } else { 0 });
            self.0.write.push(0);
            self.0.write.extend_ssh_string(address.as_bytes());
            self.0.write.push_u32_be(port);
        })
    }
}
