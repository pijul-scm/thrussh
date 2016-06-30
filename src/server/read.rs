use super::*;
use super::super::*;

use super::super::msg;
use super::super::negociation;
use super::super::encoding::Reader;

use rand::{thread_rng, Rng};
use std;
use std::io::BufRead;
use byteorder::{ByteOrder, ReadBytesExt};
use std::collections::hash_map::{Entry};

impl ServerSession {

    pub fn server_read_cleartext_kexinit<R: BufRead>(&mut self,
                                                     stream: &mut R,
                                                     kexinit: &mut KexInit,
                                                     keys: &[key::Algorithm])
                                                     -> Result<bool, Error> {
        if kexinit.algo.is_none() {
            // read algo from packet.
            if self.buffers.read.len == 0 {
                try!(self.buffers.set_clear_len(stream));
            }
            if try!(self.buffers.read(stream)) {
                {
                    let payload = self.buffers.get_current_payload();
                    kexinit.algo = Some(try!(negociation::read_kex(payload, keys)));
                    kexinit.exchange.client_kex_init.extend(payload);
                }
                self.buffers.read.clear_incr();
                Ok(true)
            } else {
                // A complete packet could not be read, we need to read more.
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }
    pub fn server_read_cleartext_kexdh<R: BufRead>(&mut self, stream:&mut R, mut kexdh:KexDh, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {

        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }

        if try!(self.buffers.read(stream)) {

            let kex = {
                let payload = self.buffers.get_current_payload();
                debug!("payload = {:?}", payload);
                assert!(payload[0] == msg::KEX_ECDH_INIT);
                kexdh.exchange.client_ephemeral.extend(&payload[5..]);
                try!(kexdh.kex.server_dh(&mut kexdh.exchange, payload))
            };
            self.buffers.read.clear_incr();

            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: kexdh.exchange,
                kex: kex,
                key: kexdh.key,
                cipher: kexdh.cipher,
                mac: kexdh.mac,
                follows: kexdh.follows,
                session_id: kexdh.session_id,
            };

            let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                &kexdhdone.exchange,
                                                                buffer));
            self.server_cleartext_kex_ecdh_reply(&kexdhdone, &hash);
            self.server_cleartext_send_newkeys();

            self.state = Some(ServerState::Kex(Kex::NewKeys(kexdhdone.compute_keys(hash, buffer, buffer2))));
            // self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));

            Ok(true)

        } else {
            // not enough bytes.
            self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
            Ok(false)
        }
    }
    pub fn server_read_cleartext_newkeys<R:BufRead>(&mut self, stream:&mut R, newkeys: NewKeys) -> Result<bool, Error> {
        // We have sent a NEWKEYS packet, and are waiting to receive one. Is it this one?
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }
        if try!(self.buffers.read(stream)) {

            let payload_is_newkeys = self.buffers.get_current_payload()[0] == msg::NEWKEYS;
            if payload_is_newkeys {
                // Ok, NEWKEYS received, now encrypted.
                self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                self.buffers.read.clear_incr();
                Ok(true)
            } else {
                Err(Error::NewKeys)
            }
        } else {
            // Not enough bytes
            self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
            Ok(false)
        }
    }
        
}

impl Encrypted {

    pub fn server_read_encrypted<A:Authenticate, S:Server>(&mut self, config:&Config<A>, server:&mut S,
                                                           buf:&[u8], buffer:&mut CryptoBuf, write_buffer:&mut SSHBuffer) -> Result<(),Error> {
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

                    try!(self.server_read_auth_request(&config.auth, buf, auth_request, buffer, write_buffer))

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
                    try!(self.server_verify_signature(buf, buffer, auth_request, write_buffer));
                } else {
                    self.server_reject_auth_request(buffer, auth_request, write_buffer)
                }
                Ok(())
            }
            Some(EncryptedState::ChannelOpened(recipient_channel)) => {

                match buf[0] {
                    msg::CHANNEL_OPEN => {
                        try!(self.server_handle_channel_open(config, server, buf, buffer, write_buffer))
                    },
                    buf_0 => {
                        let mut r = buf.reader(1);
                        let channel_num = try!(r.read_u32());
                        match self.channels.entry(channel_num) {

                            Entry::Occupied(mut e) => {
                                buffer.clear();
                                match buf_0 {
                                    msg::CHANNEL_DATA => {
                                        let channel = e.get_mut();
                                        let data = try!(r.read_string());

                                        // Ignore extra data.
                                        // https://tools.ietf.org/html/rfc4254#section-5.2
                                        if data.len() as u32 <= channel.sender_window_size {
                                            channel.sender_window_size -= data.len() as u32;
                                            let server_buf = ChannelBuf {
                                                buffer:buffer,
                                                channel: channel,
                                                write_buffer: write_buffer,
                                                cipher: &mut self.cipher,
                                                wants_reply: false
                                            };
                                            try!(server.data(&data, server_buf))
                                        }
                                        println!("{:?} / {:?}", channel.sender_window_size, config.window_size);
                                        if channel.sender_window_size < config.window_size/2 {
                                            buffer.clear();
                                            buffer.push(msg::CHANNEL_WINDOW_ADJUST);
                                            buffer.push_u32_be(channel.recipient_channel);
                                            buffer.push_u32_be(config.window_size - channel.sender_window_size);
                                            self.cipher.write_server_packet(write_buffer.seqn,
                                                                            buffer.as_slice(),
                                                                            &mut write_buffer.buffer);
                                            write_buffer.seqn += 1;
                                            channel.sender_window_size = config.window_size;
                                        }
                                    },
                                    msg::CHANNEL_WINDOW_ADJUST => {
                                        let amount = try!(r.read_u32());
                                        e.get_mut().recipient_window_size += amount
                                    },
                                    msg::CHANNEL_REQUEST => {
                                        let req_type = try!(r.read_string());
                                        let wants_reply = try!(r.read_byte());
                                        let server_buf = ChannelBuf {
                                            buffer:buffer,
                                            channel: e.get_mut(),
                                            write_buffer: write_buffer,
                                            cipher: &mut self.cipher,
                                            wants_reply: wants_reply != 0
                                        };
                                        match req_type {
                                            b"exec" => {
                                                let req = try!(r.read_string());
                                                try!(server.exec(req, server_buf));
                                            },
                                            x => {
                                                println!("{:?}, line {:?} req_type = {:?}", file!(), line!(), std::str::from_utf8(x))
                                            }
                                        }
                                    },
                                    msg::CHANNEL_EOF => {
                                        e.remove();
                                    },
                                    msg::CHANNEL_CLOSE => {
                                        e.remove();
                                    },
                                    _ => {
                                        unimplemented!()
                                    }
                                }
                            },
                            _ => {

                            }
                        }
                    }
                }
                self.state = Some(EncryptedState::ChannelOpened(recipient_channel));
                Ok(())
            }
            Some(state) => {
                debug!("buf: {:?}", buf);
                debug!("replacing state: {:?}", state);
                self.state = Some(state);
                Ok(())
            },
            None => {
                Ok(())
            }
        }

    }

    fn server_handle_channel_open<A, S:Server>(&mut self, config:&super::Config<A>, server:&mut S, buf:&[u8], buffer:&mut CryptoBuf, write_buffer:&mut SSHBuffer) -> Result<(), Error> {

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
            sender_channel: sender_channel, // "sender" is the local end, i.e. we're the sender, the remote is the recipient.
            recipient_window_size: window,
            sender_window_size: config.window_size,
            recipient_maximum_packet_size: maxpacket,
            sender_maximum_packet_size: config.maximum_packet_size
        };

        // Write the response immediately, so that we're ready when the stream becomes writable.
        server.new_channel(&channel);
        self.server_confirm_channel_open(buffer, &channel, config, write_buffer);
        //
        let sender_channel = channel.sender_channel;
        self.channels.insert(sender_channel, channel);
        self.state = Some(EncryptedState::ChannelOpened(Some(sender_channel)));
        Ok(())

    }
    
    pub fn server_read_auth_request<A:Authenticate>(&mut self, auth:&A, buf:&[u8], mut auth_request:AuthRequest, buffer:&mut CryptoBuf, write_buffer:&mut SSHBuffer) -> Result<(), Error> {
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

                // let x = buf[pos];
                // println!("is false? {:?}", x);
                try!(r.read_byte());
                let password = try!(r.read_string());
                let password = try!(std::str::from_utf8(password));
                let method = Method::Password {
                    user: name,
                    password: password
                };
                match auth.auth(auth_request.methods, &method) {
                    Auth::Success => {
                        self.server_auth_request_success(buffer, write_buffer)
                    },
                    Auth::Reject { remaining_methods, partial_success } => {
                        auth_request.methods = remaining_methods;
                        auth_request.partial_success = partial_success;
                        self.server_reject_auth_request(buffer, auth_request, write_buffer)
                    },
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
                    },
                    _ => unimplemented!()
                };
                let method = Method::Pubkey {
                    user: name,
                    pubkey: pubkey_,
                    seckey: None
                };

                match auth.auth(auth_request.methods, &method) {
                    Auth::Success => {

                        // Public key ?
                        auth_request.public_key.extend(pubkey);
                        auth_request.public_key_algorithm.extend(pubkey_algo);
                        self.server_send_pk_ok(buffer, &mut auth_request, write_buffer);
                        self.state = Some(EncryptedState::WaitingSignature(auth_request))
                        
                    },
                    Auth::Reject { remaining_methods, partial_success } => {

                        auth_request.methods = remaining_methods;
                        auth_request.partial_success = partial_success;
                        self.server_reject_auth_request(buffer, auth_request, write_buffer)

                    },
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


    pub fn server_verify_signature(&mut self, buf:&[u8], buffer:&mut CryptoBuf, auth_request: AuthRequest, write_buffer:&mut SSHBuffer) -> Result<(), Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let user_name = try!(r.read_string());
        let service_name = try!(r.read_string());
        let method = try!(r.read_string());
        let is_probe = try!(r.read_byte()) == 0;
        // TODO: check that the user is the same (maybe?)
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

                let signature = try!(r.read_string());
                let mut s = signature.reader(0);
                // let algo_ =
                try!(s.read_string());
                let sig = sodium::ed25519::Signature::copy_from_slice(try!(s.read_string()));

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
            } else {
                self.server_reject_auth_request(buffer, auth_request, write_buffer)
            }
        } else {
            self.server_reject_auth_request(buffer, auth_request, write_buffer)
        }
        Ok(())
    }

    pub fn server_read_rekey(&mut self, buf:&[u8], keys:&[key::Algorithm], buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf, write_buffer:&mut SSHBuffer) -> Result<bool, Error> {
        debug!("server_read_rekey {:?}", buf);
        if buf[0] == msg::KEXINIT {
            match std::mem::replace(&mut self.rekey, None) {
                Some(Kex::KexInit(mut kexinit)) => {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::read_kex(buf, keys)));
                    }
                    kexinit.exchange.client_kex_init.extend(buf);

                    if !kexinit.sent {
                        debug!("sending kexinit");
                        self.write_kexinit(keys, &mut kexinit, buffer, write_buffer);
                        kexinit.sent = true;
                    }
                    if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                        debug!("rekey ok");
                        self.rekey = Some(Kex::KexDh(KexDh {
                            exchange: kexinit.exchange,
                            kex: kex,
                            key: key,
                            cipher: cipher,
                            mac: mac,
                            follows: follows,
                            session_id: kexinit.session_id,
                        }))
                    } else {
                        debug!("still kexinit");
                        self.rekey = Some(Kex::KexInit(kexinit))
                    }
                    Ok(true)
                },
                None => {
                    // start a rekeying
                    if let Some(exchange) = std::mem::replace(&mut self.exchange, None) {
                        let mut kexinit = KexInit::rekey(
                            exchange,
                            try!(negociation::read_kex(buf, &keys)),
                            &self.session_id
                        );
                        debug!("sending kexinit");
                        buffer.clear();
                        negociation::write_kex(keys, buffer);
                        kexinit.exchange.server_kex_init.extend(buffer.as_slice());
                        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
                        write_buffer.seqn += 1;
                        kexinit.sent = true;
                        kexinit.exchange.client_kex_init.extend(buf);

                        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                            debug!("rekey ok");
                            self.rekey = Some(Kex::KexDh(KexDh {
                                exchange: kexinit.exchange,
                                kex: kex,
                                key: key,
                                cipher: cipher,
                                mac: mac,
                                follows: follows,
                                session_id: kexinit.session_id,
                            }))
                        } else {
                            unreachable!()
                        }
                    }
                    Ok(true)
                },
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
                _ => false
            };
            debug!("packet_matches: {:?}", packet_matches);
            if packet_matches {
                let rekey = std::mem::replace(&mut self.rekey, None);
                match rekey {
                    Some(Kex::KexDh(mut kexdh)) => {
                        debug!("KexDH");
                        let kex = {
                            kexdh.exchange.client_ephemeral.extend(&buf[5..]);
                            try!(kexdh.kex.server_dh(&mut kexdh.exchange, buf))
                        };
                        let kexdhdone = KexDhDone {
                            exchange: kexdh.exchange,
                            kex: kex,
                            key: kexdh.key,
                            cipher: kexdh.cipher,
                            mac: kexdh.mac,
                            follows: kexdh.follows,
                            session_id: kexdh.session_id,
                        };
                        let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                            &kexdhdone.exchange,
                                                                            buffer));

                        // http://tools.ietf.org/html/rfc5656#section-4
                        buffer.clear();
                        buffer.push(msg::KEX_ECDH_REPLY);
                        kexdhdone.key.public_host_key.extend_pubkey(buffer);
                        // Server ephemeral
                        buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                        // Hash signature
                        kexdhdone.key.add_signature(buffer, hash.as_bytes());
                        //
                        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
                        write_buffer.seqn += 1;

                        
                        buffer.clear();
                        buffer.push(msg::NEWKEYS);
                        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
                        write_buffer.seqn += 1;

                        debug!("new keys");
                        let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                        self.rekey = Some(Kex::NewKeys(new_keys));
                        Ok(true)

                    },
                    Some(Kex::NewKeys(kexinit)) => {
                        debug!("NewKeys");
                        if buf[0] == msg::NEWKEYS {
                            self.exchange = Some(kexinit.exchange);
                            self.kex = kexinit.kex;
                            self.key = kexinit.key;
                            self.cipher = kexinit.cipher;
                            self.mac = kexinit.mac;
                        } else {
                            self.rekey = Some(Kex::NewKeys(kexinit))
                        }
                        Ok(true)
                    },
                    _ => {
                        Ok(true)
                    }
                }
            } else {
                Ok(false)
            }
        }
    }

}
