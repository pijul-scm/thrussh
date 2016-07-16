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

use super::*;

use negociation::{Preferred, PREFERRED, Select, Named};
use msg;
use cipher::CipherT;
use state::*;
use sshbuffer::*;
use cipher;
use negociation;
use key::PubKey;
use encoding::Reader;

#[derive(Debug)]
pub struct Config {
    pub server_id: String,
    pub methods: auth::M,
    pub auth_banner: Option<&'static str>,
    pub keys: Vec<key::Algorithm>,
    pub limits: Limits,
    pub window_size: u32,
    pub maximum_packet_size: u32,
    pub preferred: Preferred,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME"),
                               env!("CARGO_PKG_VERSION")),
            methods: auth::M::all(),
            auth_banner: None,
            keys: Vec::new(),
            window_size: 100,
            maximum_packet_size: 100,
            // Following the recommendations of https://tools.ietf.org/html/rfc4253#section-9
            limits: Limits {
                rekey_write_limit: 1 << 30, // 1 Gb
                rekey_read_limit: 1 << 30, // 1Gb
                rekey_time_limit_s: 3600.0,
            },
            preferred: PREFERRED,
        }
    }
}


// When we're rekeying, any packet can be answered to, but the
// answers can be sent only after the end of the rekeying. Since we
// don't know the future keys yet, these "pending packets" are left
// in the session's `write` buffer, and flushed later. The write
// buffer is also useful to prepare complete packets before we can
// pass them to the ciphers.
pub struct Connection {
    buffers: SSHBuffers,
    state: Option<ServerState<Arc<Config>>>,
    config: Arc<Config>
}

mod encrypted;


impl KexInit {
    pub fn server_parse<C:CipherT>(mut self, config:&Config, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<Kex, Error> {

        if buf[0] == msg::KEXINIT {
            debug!("server parse");
            let algo = if self.algo.is_none() {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                try!(super::negociation::Server::read_kex(buf, &config.preferred))
            } else {
                return Err(Error::Kex)
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)
            }
            let mut key = 0;
            while key < config.keys.len() && config.keys[key].name() != algo.key {
                key += 1
            }
            let next_kex =
                if key < config.keys.len() {
                    Kex::KexDh(KexDh {
                        exchange: self.exchange,
                        key: key,
                        names: algo,
                        session_id: self.session_id,
                    })
                } else {
                    return Err(Error::UnknownKey)
                };
            
            Ok(next_kex)
        } else {
            Ok(Kex::KexInit(self))
        }
    }

    pub fn server_write<'k, C:CipherT>(&mut self, config:&'k Config, cipher:&mut C, write_buffer:&mut SSHBuffer) {
        self.exchange.server_kex_init.clear();
        negociation::write_kex(&config.preferred, &mut self.exchange.server_kex_init);
        self.sent = true;
        cipher.write(self.exchange.server_kex_init.as_slice(), write_buffer)
    }
}

impl KexDh {
    pub fn parse<C:CipherT>(mut self, config:&Config, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<Kex, Error> {

        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            // Else, process it.
            assert!(buf[0] == msg::KEX_ECDH_INIT);
            let mut r = buf.reader(1);
            self.exchange.client_ephemeral.extend(try!(r.read_string()));
            let kex = try!(super::kex::Algorithm::server_dh(self.names.kex, &mut self.exchange, buf));
            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: self.exchange,
                kex: kex,
                key: self.key,
                names: self.names,
                session_id: self.session_id,
            };

            let hash = try!(kexdhdone.kex.compute_exchange_hash(&config.keys[kexdhdone.key], &kexdhdone.exchange, buffer));

            buffer.clear();
            buffer.push(msg::KEX_ECDH_REPLY);
            config.keys[kexdhdone.key].push_to(buffer);
            // Server ephemeral
            buffer.extend_ssh_string(kexdhdone.exchange.server_ephemeral.as_slice());
            // Hash signature
            config.keys[kexdhdone.key].add_signature(buffer, hash.as_bytes());
            cipher.write(buffer.as_slice(), write_buffer);

            cipher.write(&[msg::NEWKEYS], write_buffer);
            
            Ok(Kex::NewKeys(try!(kexdhdone.compute_keys(hash, buffer, buffer2, true))))
        }
    }
}



impl Connection {

    pub fn new(config:Arc<Config>) -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        let mut session = Connection {
            buffers: SSHBuffers::new(),
            state: None,
            config: config
        };
        session.buffers.write.send_ssh_id(session.config.as_ref().server_id.as_bytes());
        session
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, S: Server>(&mut self,
                                       server: &mut S,
                                       stream: &mut R,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<ReturnCode, Error> {
        
        let state = std::mem::replace(&mut self.state, None);
        // debug!("state: {:?}", state);
        match state {
            None => {
                let mut exchange;
                {
                    let client_id = try!(self.buffers.read.read_ssh_id(stream));
                    if let Some(client_id) = client_id {
                        exchange = Exchange::new();
                        exchange.client_id.extend(client_id);
                        debug!("client id, exchange = {:?}", exchange);
                    } else {
                        return Ok(ReturnCode::WrongPacket);
                    }
                }
                // Preparing the response
                exchange.server_id.extend(self.config.as_ref().server_id.as_bytes());
                let mut kexinit = KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                };
                let mut cipher = cipher::Clear;
                kexinit.server_write(self.config.as_ref(), &mut cipher, &mut self.buffers.write);
                self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                Ok(ReturnCode::Ok)
            }

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
                            let next_kex = try!(kexinit.server_parse(self.config.as_ref(), &mut cipher, buf, &mut self.buffers.write));
                            self.state = Some(ServerState::Kex(next_kex));
                        },
                        Kex::KexDh(kexdh) => {
                            let next_kex = try!(kexdh.parse(self.config.as_ref(), buffer, buffer2, &mut cipher, buf, &mut self.buffers.write));
                            self.state = Some(ServerState::Kex(next_kex));
                        },
                        Kex::NewKeys(newkeys) => {
                            if buf[0] != msg::NEWKEYS {
                                return Err(Error::NewKeys)
                            }
                            // Ok, NEWKEYS received, now encrypted.
                            self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest, self.config.clone())));
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
                debug!("read: encrypted {:?} {:?}", enc.state, enc.rekey);
                
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
                    if buf[0] >= 20 && buf[0] < 50 {
                        if let Some(kex) = std::mem::replace(&mut enc.rekey, None) {
                            
                            // if we are currently rekeying, and we received a negociation message.
                            match kex {
                                Kex::KexInit(kexinit) =>
                                    enc.rekey = Some(
                                        try!(kexinit.server_parse(self.config.as_ref(), &mut enc.cipher, buf, &mut self.buffers.write))
                                    ),
                                Kex::KexDh(kexdh) =>
                                    enc.rekey = Some(
                                        try!(kexdh.parse(self.config.as_ref(), buffer, buffer2, &mut enc.cipher, buf, &mut self.buffers.write))
                                    ),
                                Kex::NewKeys(newkeys) =>
                                    if buf[0] == msg::NEWKEYS {
                                        enc.exchange = Some(newkeys.exchange);
                                        enc.kex = newkeys.kex;
                                        enc.key = newkeys.key;
                                        enc.cipher = newkeys.cipher;
                                        enc.mac = newkeys.names.mac;
                                    } else {
                                        return Err(Error::Inconsistent)
                                    },
                                kex => enc.rekey = Some(kex)
                            }
                            self.state = Some(ServerState::Encrypted(enc));
                            return Ok(ReturnCode::Ok)
                        } else {
                            return Err(Error::Inconsistent)
                        }
                    }
                    if buf[0] == msg::KEXINIT {
                        // If we're not currently rekeying, but buf is a rekey request
                        if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                            let kexinit = KexInit::received_rekey(
                                exchange,
                                try!(negociation::Server::read_kex(buf, &self.config.as_ref().preferred)),
                                &enc.session_id
                            );
                            enc.rekey = Some(
                                try!(kexinit.server_parse(self.config.as_ref(), &mut enc.cipher, buf, &mut self.buffers.write))
                            );
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    debug!("calling read_encrypted");
                    try!(enc.server_read_encrypted(server,
                                                   buf,
                                                   buffer));

                } else {
                    self.state = Some(ServerState::Encrypted(enc));
                    return Ok(ReturnCode::NotEnoughBytes)
                }
                debug!("flushing");
                if enc.flush(&self.config.as_ref().limits, &mut self.buffers) {

                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                        let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                        kexinit.server_write(&self.config.as_ref(),
                                             &mut enc.cipher,
                                             &mut self.buffers.write);
                        enc.rekey = Some(Kex::KexInit(kexinit))
                    }
                }
                debug!("flushed");

                self.state = Some(ServerState::Encrypted(enc));
                Ok(ReturnCode::Ok)
            }
        }
    }

    pub fn write<W: Write>(&mut self, stream: &mut W) -> Result<(), Error> {
        // Finish pending writes, if any.
        try!(self.buffers.write_all(stream));
        Ok(())
    }


}

impl<'e> ServerSession<'e> {

    pub fn request_success(&mut self) {
        if self.0.wants_reply {
            push_packet!(self.0.write, self.0.write.push(msg::REQUEST_SUCCESS))
        }
    }

    pub fn request_failure(&mut self) {
        push_packet!(self.0.write, self.0.write.push(msg::REQUEST_FAILURE))
    }

    pub fn channel_success(&mut self, channel: u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            if channel.wants_reply {
                push_packet!(self.0.write, {
                    self.0.write.push(msg::CHANNEL_SUCCESS);
                    self.0.write.push_u32_be(channel.recipient_channel);
                })
            }
        }
    }

    pub fn channel_failure(&mut self, channel: u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            if channel.wants_reply {
                push_packet!(self.0.write, {
                    self.0.write.push(msg::CHANNEL_FAILURE);
                    self.0.write.push_u32_be(channel.recipient_channel);
                })
            }
        }
    }
    
    pub fn data(&mut self, channel: u32, extended: Option<u32>, data: &[u8]) -> Result<usize, Error> {
        self.0.data(channel, extended, data)
    }

    pub fn xon_xoff_request(&mut self, channel:u32, client_can_do: bool) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"xon-xoff");
                self.0.write.push(0);
                self.0.write.push(if client_can_do { 1 } else { 0 });
            })
        }
    }

    pub fn exit_status_request(&mut self, channel:u32, exit_status:u32) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"exit-status");
                self.0.write.push(0);
                self.0.write.push_u32_be(exit_status)
            })
        }
    }

    pub fn exit_signal_request(&mut self, channel:u32, signal:Sig, core_dumped:bool, error_message:&str, language_tag:&str) {
        if let Some(channel) = self.0.channels.get(&channel) {
            push_packet!(self.0.write, {
                self.0.write.push(msg::CHANNEL_REQUEST);

                self.0.write.push_u32_be(channel.recipient_channel);
                self.0.write.extend_ssh_string(b"exit-signal");
                self.0.write.push(0);
                self.0.write.extend_ssh_string(signal.name().as_bytes());
                self.0.write.push(if core_dumped { 1 } else { 0 });
                self.0.write.extend_ssh_string(error_message.as_bytes());
                self.0.write.extend_ssh_string(language_tag.as_bytes());
            })
        }
    }
}
