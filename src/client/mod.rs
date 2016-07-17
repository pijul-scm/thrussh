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

use {Error, Limits, Client, ChannelType, ChannelParameters};
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
use session::*;
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
    read_buffer: SSHBuffer,
    pub session: Session<'a>
}

#[derive(Debug)]
pub struct Session<'a>(CommonSession<'a, Config>);

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
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().client_id.as_bytes());
        let session = Connection {
            read_buffer: SSHBuffer::new(),
            session: Session(CommonSession {
                write_buffer: write_buffer,
                auth_method: None,
                kex: None,
                cipher: cipher::CLEAR_PAIR,
                encrypted: None,
                config: config,
                wants_reply: false
            }),
        };
        session
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, C: super::Client> (&mut self,
                                               client: &mut C,
                                               stream: &mut R,
                                               buffer: &mut CryptoBuf,
                                               buffer2: &mut CryptoBuf)
                                               -> Result<super::ReturnCode, Error> {
        if self.session.0.encrypted.is_none() && self.session.0.kex.is_none() {

            let mut exchange;
            {
                let server_id = try!(self.read_buffer.read_ssh_id(stream));
                if let Some(server_id) = server_id {
                    exchange = Exchange::new();
                    exchange.server_id.extend(server_id);
                    debug!("server id, exchange = {:?}", exchange);
                } else {
                    return Ok(ReturnCode::WrongPacket);
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
            kexinit.client_write(self.session.0.config.as_ref(), &mut self.session.0.cipher, &mut self.session.0.write_buffer);
            self.session.0.kex = Some(Kex::KexInit(kexinit));
            return Ok(ReturnCode::Ok)
        }



        // In all other cases:
        if let Some(buf) = try!(self.session.0.cipher.read(stream, &mut self.read_buffer)) {
            debug!("read buf = {:?}", buf);
            // Handle the transport layer.
            if buf[0] == msg::DISCONNECT {
                // transport
                return Ok(ReturnCode::Disconnect)
            }
            if buf[0] <= 4 {
                return Ok(ReturnCode::Ok)
            }

            // Handle key exchange/re-exchange.
            match std::mem::replace(&mut self.session.0.kex, None) {
                Some(Kex::KexInit(kexinit)) =>
                    if kexinit.algo.is_some() || buf[0] == msg::KEXINIT || self.session.0.encrypted.is_none() {
                        let kexdhdone = try!(kexinit.client_parse(self.session.0.config.as_ref(), &mut self.session.0.cipher, buf, &mut self.session.0.write_buffer));
                        self.session.0.kex = Some(Kex::KexDhDone(kexdhdone));
                    } else {
                        try!(self.session.client_read_encrypted(client, buf, buffer));
                    },
                Some(Kex::KexDhDone(kexdhdone)) =>
                    self.session.0.kex = Some(try!(kexdhdone.client_parse(buffer, buffer2, client, &mut self.session.0.cipher, buf, &mut self.session.0.write_buffer))),
                Some(Kex::NewKeys(newkeys)) => {
                    if buf[0] != msg::NEWKEYS {
                        return Err(Error::NewKeys)
                    }
                    self.session.0.encrypted(EncryptedState::WaitingServiceRequest, newkeys);
                    // Ok, NEWKEYS received, now encrypted.
                    // We can't use flush here, because self.buffers is borrowed.
                    let p = [msg::SERVICE_REQUEST,
                             0,0,0,12, b's',b's',b'h',b'-',b'u',b's',b'e',b'r',b'a',b'u',b't',b'h'];
                    self.session.0.cipher.write(&p, &mut self.session.0.write_buffer);
                },
                Some(kex) => self.session.0.kex = Some(kex),
                None => {
                    debug!("calling read_encrypted");
                    try!(self.session.client_read_encrypted(client, buf, buffer));
                }
            }
            self.session.flush();
            Ok(ReturnCode::Ok)
        } else {
            Ok(ReturnCode::NotEnoughBytes)
        }
    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self, stream: &mut W) -> Result<(), Error> {
        try!(self.session.0.write_buffer.write_all(stream));
        Ok(())
    }

    pub fn authenticate(&mut self, method: auth::Method<'a, key::Algorithm>) {
        debug!("authenticate: {:?} {:?}", self.session, method);
        if let Some(ref mut enc) = self.session.0.encrypted {
            if let Some(EncryptedState::WaitingAuthRequest(_)) = enc.state {
                enc.write_auth_request(&method);
                enc.flush(&self.session.0.config.as_ref().limits, &mut self.session.0.cipher, &mut self.session.0.write_buffer);
            }
        };
        self.session.0.auth_method = Some(method);
    }

    pub fn is_authenticated(&self) -> bool {

        if let Some(ref enc) = self.session.0.encrypted {
            if let Some(EncryptedState::Authenticated) = enc.state {
                return true
            }
        }
        false
    }

    pub fn needs_auth_method(&self) -> Option<auth::M> {
        if let Some(ref enc) = self.session.0.encrypted {
            match enc.state {
                Some(EncryptedState::WaitingAuthRequest(ref auth_request)) if auth_request.was_rejected => {
                    Some(auth_request.methods)
                }
                Some(EncryptedState::WaitingAuthRequest(ref auth_request)) if self.session.0.auth_method.is_none() => {
                    Some(auth_request.methods)
                }
                _ => None,
            }
        } else {
            None
        }
    }
    pub fn flush(&mut self) {
        self.session.flush()
    }
}

impl<'a> Session<'a> {

    fn flush(&mut self) {
        if let Some(ref mut enc) = self.0.encrypted {
            if enc.flush(&self.0.config.as_ref().limits, &mut self.0.cipher, &mut self.0.write_buffer) {
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

    pub fn channels(&self) -> Option<&HashMap<u32, ChannelParameters>> {
        if let Some(ref enc) = self.0.encrypted {
            Some(&enc.channels)
        } else {
            None
        }
    }

    pub fn channel_open(&mut self, channel_type:super::ChannelType) -> Option<u32> {
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

                        match channel_type {
                            ChannelType::Session => {
                                enc.write.extend_ssh_string(b"session");
                                enc.write.push_u32_be(sender_channel); // sender channel id.
                                enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                                enc.write.push_u32_be(self.0.config.as_ref().maxpacket); // max packet size.
                            },
                            ChannelType::X11 { originator_address, originator_port } => {
                                enc.write.extend_ssh_string(b"x11");
                                enc.write.push_u32_be(sender_channel); // sender channel id.
                                enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                                enc.write.push_u32_be(self.0.config.as_ref().maxpacket); // max packet size.
                                //
                                enc.write.extend_ssh_string(originator_address.as_bytes());
                                enc.write.push_u32_be(originator_port); // sender channel id.
                            },
                            ChannelType::ForwardedTcpip { connected_address, connected_port, originator_address, originator_port } => {
                                enc.write.extend_ssh_string(b"forwarded-tcpip");
                                enc.write.push_u32_be(sender_channel); // sender channel id.
                                enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                                enc.write.push_u32_be(self.0.config.as_ref().maxpacket); // max packet size.
                                //
                                enc.write.extend_ssh_string(connected_address.as_bytes());
                                enc.write.push_u32_be(connected_port); // sender channel id.
                                enc.write.extend_ssh_string(originator_address.as_bytes());
                                enc.write.push_u32_be(originator_port); // sender channel id.
                            },
                            ChannelType::DirectTcpip { host_to_connect, port_to_connect, originator_address, originator_port } => {
                                enc.write.extend_ssh_string(b"direct-tcpip");
                                enc.write.push_u32_be(sender_channel); // sender channel id.
                                enc.write.push_u32_be(self.0.config.as_ref().window_size); // window.
                                enc.write.push_u32_be(self.0.config.as_ref().maxpacket); // max packet size.
                                //
                                enc.write.extend_ssh_string(host_to_connect.as_bytes());
                                enc.write.push_u32_be(port_to_connect); // sender channel id.
                                enc.write.extend_ssh_string(originator_address.as_bytes());
                                enc.write.push_u32_be(originator_port); // sender channel id.
                            }
                        }
                    });
                    let parameters = ChannelParameters {
                        recipient_channel: 0,
                        sender_channel: sender_channel,
                        sender_window_size: self.0.config.as_ref().window_size,
                        recipient_window_size: 0,
                        sender_maximum_packet_size: self.0.config.as_ref().maxpacket,
                        recipient_maximum_packet_size: 0,
                        confirmed: false,
                        wants_reply: false
                    };
                    enc.channels.insert(sender_channel, parameters);
                    Some(sender_channel)
                }
                _ => None
            }
        } else {
            None
        };
        self.flush();
        result
    }

    pub fn data(&mut self, channel: u32, extended: Option<u32>, data: &[u8]) -> Result<usize, Error> {
        let result = if let Some(ref mut enc) = self.0.encrypted {
            try!(enc.data(channel, extended, data))
        } else {
            return Err(Error::Inconsistent)
        };
        self.flush();
        Ok(result)
    }

    pub fn request_pty(&mut self, channel:u32, term:&str, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32, terminal_modes:&[(pty::Option, u32)]) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write,{
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"pty-req");
                    // enc.write.push(if want_reply { 1 } else { 0 });
                    enc.write.push(0);

                    enc.write.extend_ssh_string(term.as_bytes());
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);

                    enc.write.push_u32_be((5 * (1+terminal_modes.len())) as u32);
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

    pub fn request_x11(&mut self, channel:u32, single_connection: bool, x11_authentication_protocol: &str, x11_authentication_cookie: &str, x11_screen_number: u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"x11-req");
                    // enc.write.push(if self.want_reply { 1 } else { 0 });
                    enc.write.push(0);
                    enc.write.push(if single_connection { 1 } else { 0 });
                    enc.write.extend_ssh_string(x11_authentication_protocol.as_bytes());
                    enc.write.extend_ssh_string(x11_authentication_cookie.as_bytes());
                    enc.write.push_u32_be(x11_screen_number);
                });
            }
        }
        self.flush();
    }

    pub fn set_env(&mut self, channel:u32, variable_name:&str, variable_value:&str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"env");
                    // enc.write.push(if self.want_reply { 1 } else { 0 });
                    enc.write.push(0);
                    enc.write.extend_ssh_string(variable_name.as_bytes());
                    enc.write.extend_ssh_string(variable_value.as_bytes());
                });
            }
        }
        self.flush();
    }


    pub fn request_shell(&mut self, channel:u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"shell");
                    // enc.write.push(if self.want_reply { 1 } else { 0 });
                    enc.write.push(0);
                });
            }
        }
        self.flush();
    }
    pub fn exec(&mut self, channel:u32, command:&str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exec");
                    // enc.write.push(if self.want_reply { 1 } else { 0 });
                    enc.write.push(0);
                    enc.write.extend_ssh_string(command.as_bytes());
                });
            }
        }
        self.flush();
    }

    pub fn request_subsystem(&mut self, channel:u32, name:&str) {
        if let Some(ref mut enc) = self.0.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"subsystem");
                    // enc.write.push(if self.want_reply { 1 } else { 0 });
                    enc.write.push(0);
                    enc.write.extend_ssh_string(name.as_bytes());
                });
            }
        }
        self.flush();
    }

    pub fn window_change(&mut self, channel:u32, col_width:u32, row_height:u32, pix_width:u32, pix_height:u32) {
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
    
    pub fn tcpip_forward(&mut self, address:&str, port:u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"tcpip-forward");
                // enc.write.push(if self.want_reply { 1 } else { 0 });
                enc.write.push(0);
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
        self.flush();
    }

    pub fn cancel_tcpip_forward(&mut self, address:&str, port:u32) {
        if let Some(ref mut enc) = self.0.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"cancel-tcpip-forward");
                // enc.write.push(if self.want_reply { 1 } else { 0 });
                enc.write.push(0);
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
        self.flush();
    }

}

