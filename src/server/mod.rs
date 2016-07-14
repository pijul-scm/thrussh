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
use time;
use std;
use super::negociation::{Preferred, PREFERRED, Select, Named};
use super::*;
use super::msg;
use super::cipher::CipherT;
use state::*;
use sshbuffer::*;
use cipher;
use negociation;
use key::PubKey;
use encoding::Reader;

#[derive(Debug)]
pub struct Config {
    pub server_id: String,
    pub methods: auth::Methods,
    pub auth_banner: Option<&'static str>,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
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
            methods: auth::Methods::all(),
            auth_banner: Some("SSH Authentication\r\n"), // CRLF separated lines.
            keys: Vec::new(),
            window_size: 100,
            maximum_packet_size: 100,
            // Following the recommendations of https://tools.ietf.org/html/rfc4253#section-9
            rekey_write_limit: 1 << 30, // 1 Gb
            rekey_read_limit: 1 << 30, // 1Gb
            rekey_time_limit_s: 3600.0,
            preferred: PREFERRED,
        }
    }
}

pub struct Session<'k> {
    buffers: SSHBuffers,
    write: CryptoBuf,
    state: Option<ServerState<&'k key::Algorithm>>,
}

mod read;
mod write;

impl <'k>Default for Session<'k> {
    fn default() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        Session {
            buffers: SSHBuffers::new(),
            write: CryptoBuf::new(),
            state: None,
        }
    }
}

impl <'k>Session<'k> {
    pub fn new() -> Self {
        Session::default()
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, S: Server>(&mut self,
                                       server: &mut S,
                                       config: &'k Config,
                                       stream: &mut R,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<ReturnCode, Error> {
        
        let state = std::mem::replace(&mut self.state, None);
        debug!("state: {:?}", state);
        match state {
            None => {
                let mut exchange;
                {
                    let client_id = try!(self.buffers.read.read_ssh_id(stream));
                    if let Some(client_id) = client_id {
                        exchange = Exchange::new();
                        exchange.client_id.extend_from_slice(client_id);
                        debug!("client id, exchange = {:?}", exchange);
                    } else {
                        return Ok(ReturnCode::WrongPacket);
                    }
                }
                // Preparing the response
                self.buffers.write.send_ssh_id(config.server_id.as_bytes());
                exchange.server_id.extend(config.server_id.as_bytes());
                self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                })));
                Ok(ReturnCode::Ok)
            }

            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {

                let cipher = cipher::Clear;
                if let Some(buf) = try!(cipher.read(stream, &mut self.buffers.read)) {

                    debug!("buf = {:?}", buf);

                    if buf[0] >= 1 && buf[0] <= 4 {
                        // transport
                        self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                        if buf[0] == msg::DISCONNECT {
                            return Ok(ReturnCode::Disconnect)
                        } else {
                            return Ok(ReturnCode::Ok)
                        }
                    }

                    let algo = if kexinit.algo.is_none() {
                        // read algorithms from packet.
                        kexinit.exchange.client_kex_init.extend_from_slice(buf);
                        try!(super::negociation::Server::read_kex(buf, &config.preferred))
                    } else {
                        return Err(Error::Kex)
                    };
                    if !kexinit.sent {
                        buffer.clear();
                        negociation::write_kex(&config.preferred, buffer);
                        kexinit.exchange.server_kex_init.extend_from_slice(buffer.as_slice());
                        kexinit.sent = true;
                        cipher.write(buffer.as_slice(), &mut self.buffers.write)
                    }
                    let next_kex =
                        if let Some(key) = config.keys.iter().find(|x| x.name() == algo.key) {
                            Kex::KexDh(KexDh {
                                exchange: kexinit.exchange,
                                key: key,
                                names: algo,
                                session_id: kexinit.session_id,
                            })
                        } else {
                            return Err(Error::UnknownKey)
                        };
                    
                    self.state = Some(ServerState::Kex(next_kex));
                    Ok(ReturnCode::Ok)

                } else {
                    self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }

            Some(ServerState::Kex(Kex::KexDh(mut kexdh))) => {


                let cipher = cipher::Clear;
                if let Some(buf) = try!(cipher.read(stream, &mut self.buffers.read)) {

                    debug!("buf= {:?}", buf);
                    if buf[0] >= 1 && buf[0] <= 4 {
                        // transport
                        self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                        if buf[0] == msg::DISCONNECT {
                            return Ok(ReturnCode::Disconnect)
                        } else {
                            return Ok(ReturnCode::Ok)
                        }
                    }
                    
                    if kexdh.names.ignore_guessed {
                        // If we need to ignore this packet.
                        kexdh.names.ignore_guessed = false;
                        self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                        Ok(ReturnCode::Ok)
                    } else {
                        // Else, process it.

                        assert!(buf[0] == msg::KEX_ECDH_INIT);
                        let mut r = buf.reader(1);
                        kexdh.exchange.client_ephemeral.extend_from_slice(try!(r.read_string()));
                        let kex = try!(super::kex::Algorithm::server_dh(kexdh.names.kex, &mut kexdh.exchange, buf));
                        // Then, we fill the write buffer right away, so that we
                        // can output it immediately when the time comes.
                        let kexdhdone = KexDhDone {
                            exchange: kexdh.exchange,
                            kex: kex,
                            key: kexdh.key,
                            names: kexdh.names,
                            session_id: kexdh.session_id,
                        };

                        let hash = try!(kexdhdone.kex.compute_exchange_hash(kexdhdone.key, &kexdhdone.exchange, buffer));

                        buffer.clear();
                        buffer.push(msg::KEX_ECDH_REPLY);
                        kexdhdone.key.push_to(buffer);
                        // Server ephemeral
                        buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                        // Hash signature
                        kexdhdone.key.add_signature(buffer, hash.as_bytes());
                        cipher.write(buffer.as_slice(), &mut self.buffers.write);

                        cipher.write(&[msg::NEWKEYS], &mut self.buffers.write);
                        
                        self.state = Some(ServerState::Kex(Kex::NewKeys(try!(kexdhdone.compute_keys(hash, buffer, buffer2, true)))));
                        Ok(ReturnCode::Ok)
                    }

                } else {
                    self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => {
                let cipher = cipher::Clear;
                if let Some(buf) = try!(cipher.read(stream, &mut self.buffers.read)) {

                    if buf[0] >= 1 && buf[0] <= 4 {
                        // transport
                        self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                        if buf[0] == msg::DISCONNECT {
                            return Ok(ReturnCode::Disconnect)
                        } else {
                            return Ok(ReturnCode::Ok)
                        }
                    }

                    if buf[0] == msg::NEWKEYS {
                        // Ok, NEWKEYS received, now encrypted.
                        self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                        Ok(ReturnCode::Ok)
                    } else {
                        Err(Error::NewKeys)
                    }

                } else {
                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }

            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?} {:?}", enc.state, enc.rekey);
                let (ret_code, rekeying_done) =
                    if let Some(buf) = try!(enc.cipher.read(stream, &mut self.buffers.read)) {
                        debug!("read buf {:?}", buf);

                        transport!(buf); // return in case of a transport layer packet.

                        /*let rek = try!(enc.server_read_rekey(buf,
                                                             config,
                                                             buffer,
                                                             buffer2,
                                                             &mut self.buffers.write));*/
                        /*if rek && enc.rekey.is_none() && buf[0] == msg::NEWKEYS {
                            // rekeying is finished.
                            (ReturnCode::Ok, true)
                        } else {*/
                        debug!("calling read_encrypted");
                        try!(enc.server_read_encrypted(config,
                                                       server,
                                                       buf,
                                                       buffer,
                                                       &mut self.buffers.write));
                        (ReturnCode::Ok, false)
                    } else {
                        (ReturnCode::NotEnoughBytes, false)
                    };

                match ret_code {
                    ReturnCode::Ok => {
                        if rekeying_done {
                            self.buffers.read.bytes = 0;
                            self.buffers.write.bytes = 0;
                            self.buffers.last_rekey_s = time::precise_time_s();
                        }
                        if enc.rekey.is_none() &&
                           (self.buffers.read.bytes >= config.rekey_read_limit ||
                            self.buffers.write.bytes >= config.rekey_write_limit ||
                            time::precise_time_s() >=
                            self.buffers.last_rekey_s + config.rekey_time_limit_s) {

                            if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {

                                let mut kexinit = KexInit {
                                    exchange: exchange,
                                    algo: None,
                                    sent: true,
                                    session_id: Some(enc.session_id.clone()),
                                };
                                kexinit.exchange.client_kex_init.clear();
                                kexinit.exchange.server_kex_init.clear();
                                kexinit.exchange.client_ephemeral.clear();
                                kexinit.exchange.server_ephemeral.clear();

                                debug!("sending kexinit");
                                enc.write_kexinit(&config.preferred,
                                                  &mut kexinit,
                                                  buffer,
                                                  &mut self.buffers.write);
                                enc.rekey = Some(Kex::KexInit(kexinit))
                            }
                        }
                        self.buffers.read.buffer.clear();
                        self.buffers.read.len = 0;
                    }
                    _ => {
                        debug!("not read buf, {:?}", self.buffers.read);
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(ret_code)
            }
            _ => {
                debug!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    pub fn write<W: Write>(&mut self, stream: &mut W) -> Result<(), Error> {

        // Finish pending writes, if any.
        try!(self.buffers.write_all(stream));
        Ok(())
    }
}
