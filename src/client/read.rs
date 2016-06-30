use super::super::*;
use super::super::msg;
use super::super::negociation;
use super::super::cipher::CipherT;
use std::io::BufRead;
use auth::AuthRequest;
use encoding::Reader;

impl<'a> super::ClientSession<'a> {
    pub fn client_read_server_id<R:BufRead>(&mut self, stream:&mut R, mut exchange:Exchange, keys:&[key::Algorithm]) -> Result<ReturnCode, Error> {
        let read_server_id = {
            let server_id = try!(self.buffers.read.read_ssh_id(stream));
            println!("server_id = {:?}", server_id);
            if let Some(server_id) = server_id {
                exchange.server_id.extend(server_id);
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
            self.state = Some(self.buffers.cleartext_write_kex_init(
                keys,
                false, // is_server
                kexinit));
            Ok(ReturnCode::Ok)
        } else {
            self.state = Some(ServerState::VersionOk(exchange));
            Ok(ReturnCode::NotEnoughBytes)
        }

    }
    pub fn client_kexinit(&mut self, mut kexinit:KexInit, keys:&[key::Algorithm]) -> Result<ReturnCode, Error> {
        // Have we determined the algorithm yet?
        if kexinit.algo.is_none() {
            {
                let payload = self.buffers.get_current_payload();
                transport!(payload);
                if payload[0] == msg::KEXINIT {
                    kexinit.algo = Some(try!(negociation::client_read_kex(payload, keys)));
                    kexinit.exchange.server_kex_init.extend(payload);
                } else {
                    println!("unknown packet, expecting KEXINIT, received {:?}", payload);
                }
            }
        }

        if let Some((mut kex, key, cipher, mac, follows)) = kexinit.algo {

            self.buffers.write.buffer.extend(b"\0\0\0\0\0");
            ////
            let kex = kex.client_dh(&mut kexinit.exchange, &mut self.buffers.write.buffer);

            super::super::complete_packet(&mut self.buffers.write.buffer, 0);
            self.buffers.write.seqn += 1;
            self.state = Some(ServerState::Kex(Kex::KexDhDone(KexDhDone {
                exchange: kexinit.exchange,
                kex: kex,
                key: key,
                cipher: cipher,
                mac: mac,
                follows: follows,
                session_id: kexinit.session_id,
            })));
        } else {
            self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)))
        }
        Ok(ReturnCode::Ok)
    }

    pub fn client_kexdhdone<C:ValidateKey>(&mut self, client:&C, mut kexdhdone:KexDhDone, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<ReturnCode, Error> {
        debug!("kexdhdone");
        // We've sent ECDH_INIT, waiting for ECDH_REPLY
        let hash = {
            let payload = self.buffers.get_current_payload();
            transport!(payload);
            if payload[0] != msg::KEX_ECDH_REPLY {
                self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                return Ok(ReturnCode::Ok)
            }
            try!(kexdhdone.client_compute_exchange_hash(client, payload, buffer))
        };
        let mut newkeys = kexdhdone.compute_keys(hash, buffer, buffer2, false);

        debug!("sending NEWKEYS");
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::NEWKEYS);
        super::super::complete_packet(&mut self.buffers.write.buffer, 0);
        self.buffers.write.seqn += 1;
        newkeys.sent = true;

        self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));

        Ok(ReturnCode::Ok)
    }

    pub fn client_newkeys(&mut self, buffer:&mut CryptoBuf, mut newkeys:NewKeys) -> Result<ReturnCode, Error> {

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

    pub fn client_rekey<C:ValidateKey>(&mut self, client:&C, buf:&[u8], rekey:Kex, keys:&[key::Algorithm], buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        match rekey {
            Kex::KexInit(mut kexinit) => {

                if buf[0] == msg::KEXINIT {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::client_read_kex(buf, keys)));
                        kexinit.exchange.server_kex_init.extend(buf);
                    }
                    if kexinit.sent {
                        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
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
                            self.rekey = Some(Kex::KexInit(kexinit));
                        }
                    } else {
                        self.rekey = Some(Kex::KexInit(kexinit));
                    }
                } else {
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            },
            Kex::KexDhDone(mut kexdhdone) => {
                if buf[0] == msg::KEX_ECDH_REPLY {
                    let hash = try!(kexdhdone.client_compute_exchange_hash(client, buf, buffer));
                    let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2, false);
                    self.rekey = Some(Kex::NewKeys(new_keys));
                } else {
                    self.rekey = Some(Kex::KexDhDone(kexdhdone))
                }
            },
            Kex::NewKeys(mut newkeys) => {

                if buf[0] == msg::NEWKEYS {

                    newkeys.received = true;
                    if !newkeys.sent {
                        self.rekey = Some(Kex::NewKeys(newkeys));
                    } else {

                        self.exchange = Some(newkeys.exchange);
                        self.kex = newkeys.kex;
                        self.key = newkeys.key;
                        self.cipher = newkeys.cipher;
                        self.mac = newkeys.mac;
                        return Ok(true)
                    }
                } else {
                    self.rekey = Some(Kex::NewKeys(newkeys));
                }
            },
            state => {
                self.rekey = Some(state);
            }
        }
        Ok(false)
    }


    pub fn client_service_request(&mut self, auth_method:&Option<auth::Method>, buffers:&mut SSHBuffers, buffer:&mut CryptoBuf) -> Result<(), Error> {
        println!("request success");
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

    pub fn client_auth_request_success<R:BufRead>(&mut self, stream:&mut R, config:&super::Config, mut auth_request:AuthRequest, auth_method:&Option<auth::Method>, buffers:&mut SSHBuffers, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        // We're waiting for success.
        let read_complete;
        debug!("client_auth_request_success");
        if let Some(buf) = try!(self.cipher.read(stream,&mut buffers.read)) {

            println!("line {}, buf = {:?}", line!(), buf);

            if buf[0] == msg::USERAUTH_SUCCESS {

                try!(self.client_waiting_channel_open(&mut buffers.write, config, buffer))

            } else if buf[0] == msg::USERAUTH_FAILURE {

                let mut r = buf.reader(1);
                let remaining_methods = try!(r.read_string());

                auth_request.methods.keep_remaining(remaining_methods.split(|&c| c==b','));
                self.client_waiting_auth_request(&mut buffers.write, auth_request, auth_method, buffer);

            } else if buf[0] == msg::USERAUTH_PK_OK {

                auth_request.public_key_is_ok = true;
                try!(self.client_send_signature(&mut buffers.write, auth_request, config, buffer, buffer2));

            } else {
                println!("unknown message: {:?}", buf);
                self.state = Some(EncryptedState::AuthRequestSuccess(auth_request))
            }
            read_complete = true

        } else {

            read_complete = false

        }
        Ok(read_complete)
    }

    pub fn client_channel_open_confirmation<R:BufRead>(&mut self, stream:&mut R, mut channels: ChannelParameters, read_buffer:&mut SSHBuffer) -> Result<bool, Error> {
        // Check whether we're receiving a confirmation message.
        let read_complete;

        if let Some(buf) = try!(self.cipher.read(stream, read_buffer)) {

            println!("channel_confirmation? {:?}", buf);
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

                    println!("id_send = {:?}", id_send);
                    self.channels.insert(channels.sender_channel, channels);

                    self.state = Some(EncryptedState::ChannelOpened(Some(id_send)));

                } else {

                    unimplemented!()
                }
            } else {
                self.state = Some(EncryptedState::ChannelOpenConfirmation(channels));
            }
            read_complete = true
        } else {
            self.state = Some(EncryptedState::ChannelOpenConfirmation(channels));
            read_complete = false
        };
        Ok(read_complete)
    }
}
