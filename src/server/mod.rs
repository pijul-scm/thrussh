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
use byteorder::{BigEndian, ByteOrder};

use super::*;

use negociation::{Preferred, PREFERRED, Select, Named};
use msg;
use cipher::CipherT;

use sshbuffer::*;
use cipher;
use negociation;
use key::PubKey;
use encoding::Reader;
use std::collections::HashMap;
use time;
use state::*;

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

// When we're rekeying, any packet can be answered to, but the
// answers can be sent only after the end of the rekeying. Since we
// don't know the future keys yet, these "pending packets" are left
// in the session's `write` buffer, and flushed later. The write
// buffer is also useful to prepare complete packets before we can
// pass them to the ciphers.
pub struct Connection {
    read_buffer: SSHBuffer,
    state: State
}
pub type State = CommonState<'static, Config>;

impl State {
    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.mac = newkeys.names.mac;
            self.cipher = newkeys.cipher;
        } else {
            self.encrypted = Some(Encrypted {
                exchange: Some(newkeys.exchange),
                kex: newkeys.kex,
                key: newkeys.key,
                mac: newkeys.names.mac,
                session_id: newkeys.session_id,
                state: Some(state),
                rekey: None,
                channels: HashMap::new(),
                wants_reply: false,
                write: CryptoBuf::new(),
                write_cursor: 0
            });
            self.cipher = newkeys.cipher;
        }
    }

    pub fn flush(&mut self) -> bool {
        // If there are pending packets (and we've not started to rekey), flush them.
        if let Some(ref mut enc) = self.encrypted {
            {
                let packets = enc.write.as_slice();
                while enc.write_cursor < enc.write.len() {
                    if self.write_buffer.bytes >= self.config.as_ref().limits.rekey_write_limit ||
                        time::precise_time_s() >= self.last_rekey_s + self.config.as_ref().limits.rekey_time_limit_s {


                            // Resetting those now is incorrect (since
                            // we're resetting before the rekeying), but
                            // since the bytes sent during rekeying will
                            // be counted, the limits are still an upper
                            // bound on the size that can be sent.
                            self.write_buffer.bytes = 0;
                            self.last_rekey_s = time::precise_time_s();
                            return true
                                
                        } else {
                            // Read a single packet, encrypt and send it.
                            let len = BigEndian::read_u32(&packets[enc.write_cursor .. ]) as usize;
                            debug!("flushing len {:?}", len);
                            let packet = &packets [(enc.write_cursor+4) .. (enc.write_cursor+4+len)];
                            self.cipher.write(packet, &mut self.write_buffer);
                            enc.write_cursor += 4+len
                        }
                }
            }
            if enc.write_cursor >= enc.write.len() {
                // If all packets have been written, clear.
                enc.write_cursor = 0;
                enc.write.clear();
            }
        }
        false
    }


}

impl Connection {

    pub fn new(config:Arc<Config>) -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        let mut write_buffer = SSHBuffer::new();
        write_buffer.send_ssh_id(config.as_ref().server_id.as_bytes());

        let session = Connection {
            read_buffer: SSHBuffer::new(),
            state: State {
                write_buffer: write_buffer,
                kex: None,
                auth_method: None, // Client only.
                cipher: cipher::CLEAR_PAIR,
                encrypted: None,
                config: config,
                last_rekey_s: time::precise_time_s(),
                wants_reply: false
            },
        };
        session
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, S: Server>(&mut self,
                                       server: &mut S,
                                       stream: &mut R,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<ReturnCode, Error> {
        debug!("read {:?}", self.state);
        // Special case for the beginning.
        if self.state.encrypted.is_none() && self.state.kex.is_none() {

            let mut exchange;
            {
                let client_id = try!(self.read_buffer.read_ssh_id(stream));
                if let Some(client_id) = client_id {
                    exchange = Exchange::new();
                    exchange.client_id.extend(client_id);
                    debug!("client id, exchange = {:?}", exchange);
                } else {
                    return Ok(ReturnCode::WrongPacket);
                }
            }
            // Preparing the response
            exchange.server_id.extend(self.state.config.as_ref().server_id.as_bytes());
            let mut kexinit = KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            };
            kexinit.server_write(self.state.config.as_ref(), &mut self.state.cipher, &mut self.state.write_buffer);
            self.state.kex = Some(Kex::KexInit(kexinit));
            return Ok(ReturnCode::Ok)

        }



        // In all other cases:
        if let Some(buf) = try!(self.state.cipher.read(stream, &mut self.read_buffer)) {
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
            match std::mem::replace(&mut self.state.kex, None) {

                Some(Kex::KexInit(kexinit)) => {
                    let next_kex = try!(kexinit.server_parse(self.state.config.as_ref(), &mut self.state.cipher, buf, &mut self.state.write_buffer));
                    self.state.kex = Some(next_kex);
                    return Ok(ReturnCode::Ok)
                },

                Some(Kex::KexDh(kexdh)) => {
                    let next_kex = try!(kexdh.parse(self.state.config.as_ref(), buffer, buffer2, &mut self.state.cipher, buf, &mut self.state.write_buffer));
                    self.state.kex = Some(next_kex);
                    return Ok(ReturnCode::Ok)
                },

                Some(Kex::NewKeys(newkeys)) => {
                    if buf[0] != msg::NEWKEYS {
                        return Err(Error::NewKeys)
                    }
                    // Ok, NEWKEYS received, now encrypted.
                    self.state.encrypted(EncryptedState::WaitingServiceRequest, newkeys);
                    return Ok(ReturnCode::Ok)
                },

                Some(kex) => {
                    self.state.kex = Some(kex);
                    return Ok(ReturnCode::Ok)
                }
                None => {
                    try!(self.state.server_read_encrypted(server, buf, buffer))
                }
            }

            if self.state.flush() {
                
                if let Some(ref mut enc) = self.state.encrypted {
                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                        let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                        kexinit.server_write(&self.state.config.as_ref(),
                                             &mut self.state.cipher,
                                             &mut self.state.write_buffer);
                        enc.rekey = Some(Kex::KexInit(kexinit))
                    }
                }
            }
            Ok(ReturnCode::Ok)
        } else {
            Ok(ReturnCode::NotEnoughBytes)
        }
    }

    pub fn write<W: Write>(&mut self, stream: &mut W) -> Result<(), Error> {
        try!(self.state.write_buffer.write_all(stream));
        Ok(())
    }

}

impl State {

    pub fn request_success(&mut self) {
        if self.wants_reply {
            if let Some(ref mut enc) = self.encrypted {
                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
            }
        }
    }

    pub fn request_failure(&mut self) {
        if let Some(ref mut enc) = self.encrypted {
            push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
        }
    }

    pub fn channel_success(&mut self, channel: u32) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                if channel.wants_reply {
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_SUCCESS);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    pub fn channel_failure(&mut self, channel: u32) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                if channel.wants_reply {
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_FAILURE);
                        enc.write.push_u32_be(channel.recipient_channel);
                    })
                }
            }
        }
    }

    pub fn data(&mut self, channel: u32, extended: Option<u32>, data: &[u8]) -> Result<usize, Error> {
        if let Some(ref mut enc) = self.encrypted {
            enc.data(channel, extended, data)
        } else {
            unreachable!()
        }
    }

    pub fn xon_xoff_request(&mut self, channel:u32, client_can_do: bool) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
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

    pub fn exit_status_request(&mut self, channel:u32, exit_status:u32) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
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

    pub fn exit_signal_request(&mut self, channel:u32, signal:Sig, core_dumped:bool, error_message:&str, language_tag:&str) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
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

}

