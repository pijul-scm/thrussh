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
use super::super::*;
use super::super::msg;
use super::super::negociation;
use super::super::cipher::CipherT;
use super::super::cryptobuf::CryptoBuf;
use state::*;
use sshbuffer::{SSHBuffer,SSHBuffers};
use auth;
use std::io::BufRead;
use auth::AuthRequest;
use encoding::Reader;
use negociation::{Select, Preferred};

impl<'a> super::ClientSession<'a> {
    pub fn client_read_server_id<R: BufRead>(&mut self,
                                             stream: &mut R,
                                             mut exchange: Exchange,
                                             preferred: &Preferred)
                                             -> Result<ReturnCode, Error> {
        let read_server_id = {
            let server_id = try!(self.buffers.read.read_ssh_id(stream));
            debug!("server_id = {:?}", server_id);
            if let Some(server_id) = server_id {
                exchange.server_id.extend_from_slice(server_id);
                true
            } else {
                false
            }
        };

        if read_server_id {
            let kexinit = KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            };
            self.state = Some(kexinit.cleartext_write_kex_init(&preferred, &mut self.buffers.write, false));
            Ok(ReturnCode::Ok)
        } else {
            self.state = Some(ServerState::VersionOk(exchange));
            Ok(ReturnCode::NotEnoughBytes)
        }

    }
    pub fn client_kexinit(&mut self,
                          mut kexinit: KexInit,
                          keys: &[key::Algorithm],
                          pref: &negociation::Preferred)
                          -> Result<ReturnCode, Error> {
        // Have we determined the algorithm yet?
        if kexinit.algo.is_none() {
            {
                let payload = self.buffers.get_current_payload();
                transport!(payload);
                if payload[0] == msg::KEXINIT {
                    kexinit.algo = Some(try!(negociation::Client::read_kex(payload, keys, pref)));
                    kexinit.exchange.server_kex_init.extend_from_slice(payload);
                } else {
                    debug!("unknown packet, expecting KEXINIT, received {:?}", payload);
                }
            }
        }

        if let Some(names) = kexinit.algo {

            self.buffers.write.buffer.extend(b"\0\0\0\0\0");
            ////
            let kex = try!(super::super::kex::Algorithm::client_dh(names.kex, &mut kexinit.exchange, &mut self.buffers.write.buffer));

            super::super::complete_packet(&mut self.buffers.write.buffer, 0);
            self.buffers.write.seqn += 1;
            self.state = Some(ServerState::Kex(Kex::KexDhDone(KexDhDone {
                exchange: kexinit.exchange,
                names: names,
                kex: kex,
                session_id: kexinit.session_id,
            })));
        } else {
            self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)))
        }
        Ok(ReturnCode::Ok)
    }

    pub fn client_kexdhdone<C: Client>(&mut self,
                                       client: &C,
                                       mut kexdhdone: KexDhDone,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<ReturnCode, Error> {
        debug!("kexdhdone");
        // We've sent ECDH_INIT, waiting for ECDH_REPLY
        let hash = {
            let payload = self.buffers.get_current_payload();
            transport!(payload);
            if payload[0] != msg::KEX_ECDH_REPLY {
                self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                return Ok(ReturnCode::Ok);
            }
            try!(kexdhdone.client_compute_exchange_hash(client, payload, buffer))
        };
        let mut newkeys = try!(kexdhdone.compute_keys(hash, buffer, buffer2, false));

        debug!("sending NEWKEYS");
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::NEWKEYS);
        super::super::complete_packet(&mut self.buffers.write.buffer, 0);
        self.buffers.write.seqn += 1;
        newkeys.sent = true;

        self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));

        Ok(ReturnCode::Ok)
    }

    pub fn client_newkeys(&mut self,
                          buffer: &mut CryptoBuf,
                          mut newkeys: NewKeys)
                          -> Result<ReturnCode, Error> {

        let is_newkeys = {
            let payload = self.buffers.get_current_payload();
            transport!(payload);
            payload[0] == msg::NEWKEYS
        };
        if is_newkeys {

            newkeys.received = true;
            let encrypted = newkeys.encrypted(EncryptedState::ServiceRequest);
            buffer.clear();
            buffer.push(msg::SERVICE_REQUEST);
            buffer.extend_ssh_string(b"ssh-userauth");

            encrypted.cipher.write(buffer.as_slice(), &mut self.buffers.write);
            debug!("sending SERVICE_REQUEST");

            self.state = Some(ServerState::Encrypted(encrypted))
        }
        Ok(ReturnCode::Ok)
    }
}


impl Encrypted {
    pub fn client_rekey<C: Client>(&mut self,
                                   client: &C,
                                   buf: &[u8],
                                   rekey: Kex,
                                   config: &super::Config,
                                   buffer: &mut CryptoBuf,
                                   buffer2: &mut CryptoBuf)
                                   -> Result<bool, Error> {
        match rekey {
            Kex::KexInit(mut kexinit) => {
                if buf[0] == msg::KEXINIT {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::Client::read_kex(buf, &config.keys, &config.preferred)));
                        kexinit.exchange.server_kex_init.extend_from_slice(buf);
                    }
                    if kexinit.sent {
                        if let Some(names) = kexinit.algo {
                            self.rekey = Some(Kex::KexDh(KexDh {
                                exchange: kexinit.exchange,
                                names: names,
                                session_id: kexinit.session_id,
                            }))
                        } else {
                            self.rekey = Some(Kex::KexInit(kexinit));
                        }
                    } else {
                        self.rekey = Some(Kex::KexInit(kexinit));
                    }
                } else {
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            }
            Kex::KexDhDone(mut kexdhdone) => {
                if buf[0] == msg::KEX_ECDH_REPLY {
                    let hash = try!(kexdhdone.client_compute_exchange_hash(client, buf, buffer));
                    let new_keys = try!(kexdhdone.compute_keys(hash, buffer, buffer2, false));
                    self.rekey = Some(Kex::NewKeys(new_keys));
                } else {
                    self.rekey = Some(Kex::KexDhDone(kexdhdone))
                }
            }
            Kex::NewKeys(mut newkeys) => {
                if buf[0] == msg::NEWKEYS {

                    newkeys.received = true;
                    if !newkeys.sent {
                        self.rekey = Some(Kex::NewKeys(newkeys));
                    } else {

                        self.exchange = Some(newkeys.exchange);
                        self.kex = newkeys.kex;
                        self.key = newkeys.names.key;
                        self.cipher = newkeys.cipher;
                        self.mac = newkeys.names.mac;
                        return Ok(true);
                    }
                } else {
                    self.rekey = Some(Kex::NewKeys(newkeys));
                }
            }
            state => {
                self.rekey = Some(state);
            }
        }
        Ok(false)
    }


    pub fn client_service_request(&mut self,
                                  auth_method: &Option<auth::Method>,
                                  buffers: &mut SSHBuffers,
                                  buffer: &mut CryptoBuf)
                                  -> Result<(), Error> {
        debug!("request success");
        let auth_request = auth::AuthRequest {
            methods: auth::Methods::all(),
            partial_success: false,
            public_key: CryptoBuf::new(),
            public_key_algorithm: CryptoBuf::new(),
            public_key_is_ok: false,
            sent_pk_ok: false,
        };
        self.client_waiting_auth_request(&mut buffers.write, auth_request, auth_method, buffer);
        Ok(())
    }

    pub fn client_auth_request_success(&mut self,
                                       buf: &[u8],
                                       config: &super::Config,
                                       mut auth_request: AuthRequest,
                                       auth_method: &Option<auth::Method>,
                                       write_buffer: &mut SSHBuffer,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<(), Error> {
        // We're waiting for success.
        debug!("client_auth_request_success");

        debug!("line {}, buf = {:?}", line!(), buf);

        if buf[0] == msg::USERAUTH_SUCCESS {

            try!(self.client_waiting_channel_open(write_buffer, config, buffer))

        } else if buf[0] == msg::USERAUTH_FAILURE {

            let mut r = buf.reader(1);
            let remaining_methods = try!(r.read_string());

            auth_request.methods.keep_remaining(remaining_methods.split(|&c| c == b','));
            self.client_waiting_auth_request(write_buffer, auth_request, auth_method, buffer);

        } else if buf[0] == msg::USERAUTH_PK_OK {

            auth_request.public_key_is_ok = true;
            try!(self.client_send_signature(write_buffer, auth_request, config, buffer, buffer2));

        } else {
            debug!("unknown message: {:?}", buf);
            self.state = Some(EncryptedState::AuthRequestSuccess(auth_request))
        }
        Ok(())
    }

    pub fn client_channel_open_confirmation(&mut self,
                                            buf: &[u8],
                                            mut channels: ChannelParameters)
                                            -> Result<(), Error> {
        // Check whether we're receiving a confirmation message.
        debug!("channel_confirmation? {:?}", buf);
        if buf[0] == msg::CHANNEL_OPEN_CONFIRMATION {
            let mut reader = buf.reader(1);
            let id_send = try!(reader.read_u32());
            let id_recv = try!(reader.read_u32());
            let window = try!(reader.read_u32());
            let max_packet = try!(reader.read_u32());

            if channels.sender_channel == id_send {

                channels.recipient_channel = id_recv;
                channels.recipient_window_size = window;
                channels.recipient_maximum_packet_size = max_packet;

                debug!("id_send = {:?}", id_send);
                self.channels.insert(channels.sender_channel, channels);

                self.state = Some(EncryptedState::ChannelOpened(Some(id_send)));

            } else {

                unimplemented!()
            }
        } else {
            self.state = Some(EncryptedState::ChannelOpenConfirmation(channels));
        }
        Ok(())
    }
}
