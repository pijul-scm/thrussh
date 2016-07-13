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
use super::*;
use super::super::*;
use state::*;
use sshbuffer::{SSHBuffer};
use super::super::msg;
use super::super::negociation;
use super::super::encoding::Reader;
use super::super::cipher::CipherT;
use negociation::Select;
use auth::*;
use rand::{thread_rng, Rng};
use std;
use std::collections::hash_map::Entry;
use key::PubKey;
use negociation::Named;
use sodium;

impl<'k> Session<'k> {
    #[doc(hidden)]
    pub fn server_read_cleartext_kexdh(&mut self,
                                       mut kexdh: KexDh<&'k key::Algorithm>,
                                       buffer: &mut CryptoBuf,
                                       buffer2: &mut CryptoBuf)
                                       -> Result<ReturnCode, Error> {
        let kex = {
            let payload = self.buffers.get_current_payload();
            transport!(payload);

            debug!("payload = {:?}", payload);
            assert!(payload[0] == msg::KEX_ECDH_INIT);
            kexdh.exchange.client_ephemeral.extend_from_slice(&payload[5..]);
            try!(super::super::kex::Algorithm::server_dh(kexdh.names.kex, &mut kexdh.exchange, payload))
        };

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
        self.server_cleartext_kex_ecdh_reply(&kexdhdone, &hash);
        self.server_cleartext_send_newkeys();

        self.state = Some(ServerState::Kex(Kex::NewKeys(try!(kexdhdone.compute_keys(hash, buffer, buffer2, true)))));
        Ok(ReturnCode::Ok)
    }

    #[doc(hidden)]
    pub fn server_read_cleartext_newkeys(&mut self, newkeys: NewKeys<&'k key::Algorithm>) -> Result<ReturnCode, Error> {
        // We have sent a NEWKEYS packet, and are waiting to receive one. Is it this one?
        let payload_is_newkeys = {
            let payload = self.buffers.get_current_payload();
            transport!(payload);
            payload[0] == msg::NEWKEYS
        };
        if payload_is_newkeys {
            // Ok, NEWKEYS received, now encrypted.
            self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
            Ok(ReturnCode::Ok)
        } else {
            Err(Error::NewKeys)
        }
    }
}

impl <'k> Encrypted<&'k key::Algorithm> {
    pub fn server_read_encrypted<S: Server>(&mut self,
                                            config: &'k Config,
                                            server: &mut S,
                                            buf: &[u8],
                                            buffer: &mut CryptoBuf,
                                            write_buffer: &mut SSHBuffer)
                                            -> Result<(), Error> {
        // If we've successfully read a packet.
        debug!("buf = {:?}", buf);
        let state = std::mem::replace(&mut self.state, None);
        match state {
            Some(EncryptedState::WaitingServiceRequest) if buf[0] == msg::SERVICE_REQUEST => {

                let mut r = buf.reader(1);
                let request = try!(r.read_string());
                debug!("request: {:?}", std::str::from_utf8(request));
                debug!("decrypted {:?}", buf);
                if request == b"ssh-userauth" {

                    let auth_request = self.server_accept_service(config.auth_banner,
                                                                  config.methods,
                                                                  buffer,
                                                                  write_buffer);
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));

                } else {

                    self.state = Some(EncryptedState::WaitingServiceRequest)
                }
                Ok(())
            }
            Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                if buf[0] == msg::USERAUTH_REQUEST {

                    try!(self.server_read_auth_request(server, buf, auth_request, buffer, write_buffer))

                } else {
                    // Wrong request
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request))
                }
                Ok(())
            }

            Some(EncryptedState::WaitingSignature(auth_request)) => {
                debug!("receiving signature, {:?}", buf);
                if buf[0] == msg::USERAUTH_REQUEST {
                    // check signature.
                    try!(self.server_verify_signature(server, buf, buffer, auth_request, write_buffer));
                } else {
                    self.server_reject_auth_request(buffer, auth_request, write_buffer)
                }
                Ok(())
            }
            Some(EncryptedState::Authenticated) => {
                debug!("buf = {:?}", buf);
                match buf[0] {
                    msg::CHANNEL_OPEN => {
                        try!(self.server_handle_channel_open(config, server, buf, buffer, write_buffer))
                    }
                    buf_0 => {
                        let mut r = buf.reader(1);
                        let channel_num = try!(r.read_u32());

                        if let Entry::Occupied(mut e) = self.channels.entry(channel_num) {
                            buffer.clear();
                            debug!("buf: {:?}", buf);
                            match buf_0 {
                                msg::CHANNEL_DATA => {
                                    let channel = e.get_mut();
                                    let data = try!(r.read_string());

                                    // Ignore extra data.
                                    // https://tools.ietf.org/html/rfc4254#section-5.2
                                    if data.len() as u32 <= channel.sender_window_size {
                                        channel.sender_window_size -= data.len() as u32;
                                        let sender_channel = channel.sender_channel;
                                        let server_buf = ChannelBuf {
                                            buffer: buffer,
                                            channel: channel,
                                            write_buffer: write_buffer,
                                            cipher: &mut self.cipher,
                                            wants_reply: false,
                                        };
                                        try!(server.data(sender_channel, &data, server_buf))
                                    }
                                    debug!("{:?} / {:?}", channel.sender_window_size, config.window_size);
                                    if channel.sender_window_size < config.window_size / 2 {
                                        super::super::adjust_window_size(write_buffer,
                                                                         &mut self.cipher,
                                                                         config.window_size,
                                                                         buffer,
                                                                         channel)
                                    }
                                }
                                msg::CHANNEL_WINDOW_ADJUST => {
                                    let amount = try!(r.read_u32());
                                    let channel = e.get_mut();
                                    channel.recipient_window_size += amount;
                                }
                                msg::CHANNEL_REQUEST => {
                                    let req_type = try!(r.read_string());
                                    let wants_reply = try!(r.read_byte());
                                    let channel = e.get_mut();
                                    let sender_channel = channel.sender_channel;
                                    let server_buf = ChannelBuf {
                                        buffer: buffer,
                                        channel: channel,
                                        write_buffer: write_buffer,
                                        cipher: &mut self.cipher,
                                        wants_reply: wants_reply != 0,
                                    };
                                    match req_type {
                                        b"exec" => {
                                            let req = try!(r.read_string());
                                            try!(server.exec(sender_channel, req, server_buf));
                                        }
                                        x => {
                                            debug!("{:?}, line {:?} req_type = {:?}", file!(), line!(), std::str::from_utf8(x))
                                        }
                                    }
                                }
                                msg::CHANNEL_EOF |
                                msg::CHANNEL_CLOSE => {
                                    e.remove();
                                }
                                _ => unimplemented!(),
                            }
                        }
                    }
                }
                self.state = Some(EncryptedState::Authenticated);
                Ok(())
            }
            Some(state) => {
                debug!("buf: {:?}", buf);
                debug!("replacing state: {:?}", state);
                self.state = Some(state);
                Ok(())
            }
            None => Ok(()),
        }

    }

    fn server_handle_channel_open<S: Server>(&mut self,
                                             config: &super::Config,
                                             server: &mut S,
                                             buf: &[u8],
                                             buffer: &mut CryptoBuf,
                                             write_buffer: &mut SSHBuffer)
                                             -> Result<(), Error> {

        // https://tools.ietf.org/html/rfc4254#section-5.1
        let mut r = buf.reader(1);
        let typ = try!(r.read_string());
        let sender = try!(r.read_u32());
        let window = try!(r.read_u32());
        let maxpacket = try!(r.read_u32());

        debug!("waiting channel open: type = {:?} sender = {:?} window = {:?} maxpacket = {:?}",
               String::from_utf8_lossy(typ),
               sender,
               window,
               maxpacket);

        let mut sender_channel: u32 = 1;
        while self.channels.contains_key(&sender_channel) || sender_channel == 0 {
            sender_channel = thread_rng().gen()
        }
        let channel = ChannelParameters {
            recipient_channel: sender,
            sender_channel: sender_channel, /* "sender" is the local end, i.e. we're the sender, the remote is the recipient. */
            recipient_window_size: window,
            sender_window_size: config.window_size,
            recipient_maximum_packet_size: maxpacket,
            sender_maximum_packet_size: config.maximum_packet_size,
            confirmed: true
        };

        // Write the response immediately, so that we're ready when the stream becomes writable.
        server.new_channel(sender_channel);
        self.server_confirm_channel_open(buffer, &channel, config, write_buffer);
        //
        let sender_channel = channel.sender_channel;
        self.channels.insert(sender_channel, channel);
        self.state = Some(EncryptedState::Authenticated);
        Ok(())
    }

    pub fn server_read_auth_request<S: Server>(&mut self,
                                               server: &S,
                                               buf: &[u8],
                                               mut auth_request: AuthRequest,
                                               buffer: &mut CryptoBuf,
                                               write_buffer: &mut SSHBuffer)
                                               -> Result<(), Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let name = try!(r.read_string());
        let name = try!(std::str::from_utf8(name));
        let service_name = try!(r.read_string());
        let method = try!(r.read_string());
        debug!("name: {:?} {:?} {:?}",
               name, std::str::from_utf8(service_name),
               std::str::from_utf8(method));

        if service_name == b"ssh-connection" {

            if method == b"password" {

                try!(r.read_byte());
                let password = try!(r.read_string());
                let password = try!(std::str::from_utf8(password));
                let method = Method::Password {
                    user: name,
                    password: password,
                };
                match server.auth(auth_request.methods, &method) {
                    Auth::Success => self.server_auth_request_success(buffer, write_buffer),
                    Auth::Reject { remaining_methods, partial_success } => {
                        auth_request.methods = remaining_methods;
                        auth_request.partial_success = partial_success;
                        self.server_reject_auth_request(buffer, auth_request, write_buffer)
                    }
                }

            } else if method == b"publickey" {

                try!(r.read_byte()); // is not probe

                let pubkey_algo = try!(r.read_string());
                let pubkey = try!(r.read_string());

                let pubkey_ = match pubkey_algo {
                    b"ssh-ed25519" => {
                        let mut p = pubkey.reader(0);
                        try!(p.read_string());
                        key::PublicKey::Ed25519(
                            sodium::ed25519::PublicKey::copy_from_slice(try!(p.read_string()))
                        )
                    }
                    _ => unimplemented!(),
                };
                let method = Method::PublicKey {
                    user: name,
                    pubkey: pubkey_,
                };

                match server.auth(auth_request.methods, &method) {
                    Auth::Success => {

                        // Public key ?
                        auth_request.public_key.extend(pubkey);
                        auth_request.public_key_algorithm.extend(pubkey_algo);
                        self.server_send_pk_ok(buffer, &mut auth_request, write_buffer);
                        self.state = Some(EncryptedState::WaitingSignature(auth_request))

                    }
                    Auth::Reject { remaining_methods, partial_success } => {

                        auth_request.methods = remaining_methods;
                        auth_request.partial_success = partial_success;
                        self.server_reject_auth_request(buffer, auth_request, write_buffer)

                    }
                }
            } else {
                // Other methods of the base specification are insecure or optional.
                self.server_reject_auth_request(buffer, auth_request, write_buffer)
            }
        } else {
            // Unknown service
            unimplemented!()
        }
        Ok(())
    }


    pub fn server_verify_signature<S: Server>(&mut self,
                                              server: &S,
                                              buf: &[u8],
                                              buffer: &mut CryptoBuf,
                                              auth_request: AuthRequest,
                                              write_buffer: &mut SSHBuffer)
                                              -> Result<(), Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let user_name = try!(r.read_string());
        let service_name = try!(r.read_string());
        let method = try!(r.read_string());
        let is_probe = try!(r.read_byte()) == 0;
        if service_name == b"ssh-connection" && method == b"publickey" && !is_probe {

            let algo = try!(r.read_string());
            let key = try!(r.read_string());

            let pos0 = r.position;
            if algo == b"ssh-ed25519" {

                let key = {
                    let mut k = key.reader(0);
                    try!(k.read_string()); // should be equal to algo.
                    sodium::ed25519::PublicKey::copy_from_slice(try!(k.read_string()))
                };
                // Check that the user is still authorized (the client may have changed user since we accepted).
                let method = Method::PublicKey {
                    user: try!(std::str::from_utf8(user_name)),
                    pubkey: key::PublicKey::Ed25519(key.clone()),
                };

                match server.auth(auth_request.methods, &method) {
                    Auth::Success => {

                        let signature = try!(r.read_string());
                        let mut s = signature.reader(0);
                        // let algo_ =
                        try!(s.read_string());
                        let sig =
                            sodium::ed25519::Signature::copy_from_slice(try!(s.read_string()));

                        buffer.clear();
                        buffer.extend_ssh_string(self.session_id.as_bytes());
                        buffer.extend(&buf[0..pos0]);
                        // Verify signature.
                        if sodium::ed25519::verify_detached(&sig, buffer.as_slice(), &key) {

                            // EncryptedState::AuthRequestSuccess(auth_request)
                            self.server_auth_request_success(buffer, write_buffer)
                        } else {
                            self.server_reject_auth_request(buffer, auth_request, write_buffer)
                        }
                    }
                    _ => self.server_reject_auth_request(buffer, auth_request, write_buffer),
                }
            } else {
                self.server_reject_auth_request(buffer, auth_request, write_buffer)
            }
        } else {
            self.server_reject_auth_request(buffer, auth_request, write_buffer)
        }
        Ok(())
    }

    pub fn server_read_rekey(&mut self,
                             buf: &[u8],
                             config: &'k super::Config,
                             buffer: &mut CryptoBuf,
                             buffer2: &mut CryptoBuf,
                             write_buffer: &mut SSHBuffer)
                             -> Result<bool, Error> {
        debug!("server_read_rekey {:?}", buf);
        if buf[0] == msg::KEXINIT {
            match std::mem::replace(&mut self.rekey, None) {
                Some(Kex::KexInit(mut kexinit)) => {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::Server::read_kex(buf, &config.preferred)));
                    }
                    kexinit.exchange.client_kex_init.extend_from_slice(buf);

                    if !kexinit.sent {
                        debug!("sending kexinit");
                        self.write_kexinit(&config.preferred, &mut kexinit, buffer, write_buffer);
                        kexinit.sent = true;
                    }
                    if let Some(names) = kexinit.algo {
                        debug!("rekey ok");
                        if let Some(key) = config.keys.iter().find(|x| x.name() == names.key) {
                            self.rekey = Some(Kex::KexDh(KexDh {
                                exchange: kexinit.exchange,
                                names: names,
                                key: key,
                                session_id: kexinit.session_id,
                            }))
                        } else {
                            debug!("still kexinit");
                            panic!("")
                        }
                    } else {
                        debug!("still kexinit");
                        self.rekey = Some(Kex::KexInit(kexinit))
                    }
                    Ok(true)
                }
                None => {
                    // start a rekeying
                    if let Some(exchange) = std::mem::replace(&mut self.exchange, None) {
                        let mut kexinit = KexInit::rekey(
                            exchange,
                            try!(negociation::Server::read_kex(buf, &config.preferred)),
                            &self.session_id
                        );
                        debug!("sending kexinit");
                        buffer.clear();
                        negociation::write_kex(&config.preferred, buffer);
                        kexinit.exchange.server_kex_init.extend(buffer.as_slice());
                        self.cipher.write(buffer.as_slice(), write_buffer);
                        kexinit.sent = true;
                        kexinit.exchange.client_kex_init.extend_from_slice(buf);

                        if let Some(names) = kexinit.algo {
                            debug!("rekey ok");
                            if let Some(key) = config.keys.iter().find(|x| x.name() == names.key) {
                                self.rekey = Some(Kex::KexDh(KexDh {
                                    exchange: kexinit.exchange,
                                    names: names,
                                    key: key,
                                    session_id: kexinit.session_id,
                                }))
                            } else {
                                unreachable!() // could not have changed.
                            }
                        } else {
                            unreachable!()
                        }
                    }
                    Ok(true)
                }
                _ => {
                    // Error, maybe?
                    // unimplemented!()
                    Ok(true)
                }
            }
        } else {

            let packet_matches = match self.rekey {
                Some(Kex::KexDh(_)) if buf[0] == msg::KEX_ECDH_INIT => true,
                Some(Kex::NewKeys(_)) if buf[0] == msg::NEWKEYS => true,
                _ => false,
            };
            debug!("packet_matches: {:?}", packet_matches);
            if packet_matches {
                let rekey = std::mem::replace(&mut self.rekey, None);
                match rekey {
                    Some(Kex::KexDh(mut kexdh)) => {
                        debug!("KexDH");
                        let kex = {
                            kexdh.exchange.client_ephemeral.extend_from_slice(&buf[5..]);
                            try!(super::super::kex::Algorithm::server_dh(kexdh.names.kex, &mut kexdh.exchange, buf))
                        };
                        let kexdhdone = KexDhDone {
                            exchange: kexdh.exchange,
                            names: kexdh.names,
                            kex: kex,
                            key: kexdh.key,
                            session_id: kexdh.session_id,
                        };
                        let hash = try!(kexdhdone.kex.compute_exchange_hash(
                            kexdhdone.key,
                            &kexdhdone.exchange,
                            buffer));

                        // http://tools.ietf.org/html/rfc5656#section-4
                        buffer.clear();
                        buffer.push(msg::KEX_ECDH_REPLY);
                        kexdhdone.key.push_to(buffer);
                        // Server ephemeral
                        buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                        // Hash signature
                        kexdhdone.key.add_signature(buffer, hash.as_bytes());
                        //
                        self.cipher.write(buffer.as_slice(), write_buffer);

                        buffer.clear();
                        buffer.push(msg::NEWKEYS);
                        self.cipher.write(buffer.as_slice(), write_buffer);

                        debug!("new keys");
                        let new_keys = try!(kexdhdone.compute_keys(hash, buffer, buffer2, true));
                        self.rekey = Some(Kex::NewKeys(new_keys));
                        Ok(true)

                    }
                    Some(Kex::NewKeys(kexinit)) => {
                        debug!("NewKeys");
                        if buf[0] == msg::NEWKEYS {
                            self.exchange = Some(kexinit.exchange);
                            self.kex = kexinit.kex;
                            self.key = kexinit.key;
                            self.cipher = kexinit.cipher;
                            self.mac = kexinit.names.mac;
                        } else {
                            self.rekey = Some(Kex::NewKeys(kexinit))
                        }
                        Ok(true)
                    }
                    _ => Ok(true),
                }
            } else {
                Ok(false)
            }
        }
    }
}
