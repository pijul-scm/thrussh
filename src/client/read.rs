use super::super::*;
use super::super::msg;
use super::super::negociation;
use std::io::BufRead;
use auth::AuthRequest;
use encoding::Reader;
use std;

impl<'a> super::ClientSession<'a> {
    pub fn client_version_ok<R:BufRead>(&mut self, stream:&mut R, mut exchange: Exchange, config:&super::Config) -> Result<bool, Error> {
        println!("read: {:?}", exchange);
        // Have we received the version id?
        if exchange.server_id.len() == 0 {
            let server_id = try!(self.buffers.read_ssh_id(stream));
            println!("server_id = {:?}", server_id);
            if let Some(server_id) = server_id {
                exchange.server_id.extend(server_id);
            } else {
                self.state = Some(ServerState::VersionOk(exchange));
                return Ok(false)
            }
        }
        // Have we received the version id?
        if exchange.client_id.len() == 0 {
            self.buffers.send_ssh_id(config.client_id.as_bytes());
            exchange.client_id.extend(config.client_id.as_bytes());
        }
        let kexinit = KexInit {
            exchange: exchange,
            algo: None,
            sent: false,
            session_id: None,
        };
        self.state = Some(self.buffers.cleartext_write_kex_init(
            &config.keys,
            false, // is_server
            kexinit));

        Ok(true)
    }

    pub fn client_kexinit<R:BufRead>(&mut self, stream:&mut R, mut kexinit:KexInit, keys:&[key::Algorithm]) -> Result<bool, Error> {
        // Have we determined the algorithm yet?
        let mut received = false;
        if kexinit.algo.is_none() {
            if self.buffers.read.len == 0 {
                try!(self.buffers.set_clear_len(stream));
            }
            if try!(self.buffers.read(stream)) {
                {
                    let payload = self.buffers.get_current_payload();
                    if payload[0] == msg::KEXINIT {
                        kexinit.algo = Some(try!(negociation::client_read_kex(payload, keys)));
                        kexinit.exchange.server_kex_init.extend(payload);
                    } else {
                        println!("unknown packet, expecting KEXINIT, received {:?}", payload);
                    }
                }
                self.buffers.read.seqn += 1;
                self.buffers.read.clear();
                received = true;
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
        Ok(received)

    }

    pub fn client_kexdhdone<R:BufRead>(&mut self, stream:&mut R, mut kexdhdone:KexDhDone, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        debug!("kexdhdone");
        // We've sent ECDH_INIT, waiting for ECDH_REPLY
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }

        if try!(self.buffers.read(stream)) {

            let hash = try!(kexdhdone.client_compute_exchange_hash(self.buffers.get_current_payload(), buffer));
            let mut newkeys = kexdhdone.compute_keys(hash, buffer, buffer2);

            self.buffers.read.seqn += 1;
            self.buffers.read.clear();

            debug!("sending NEWKEYS");
            self.buffers.write.buffer.extend(b"\0\0\0\0\0");
            self.buffers.write.buffer.push(msg::NEWKEYS);
            super::super::complete_packet(&mut self.buffers.write.buffer, 0);
            self.buffers.write.seqn += 1;
            newkeys.sent = true;

            self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));

            Ok(true)

        } else {
            self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
            Ok(false)
        }

    }

    pub fn client_newkeys<R:BufRead>(&mut self, stream:&mut R, buffer:&mut CryptoBuf, mut newkeys:NewKeys) -> Result<bool, Error> {

        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }
        if try!(self.buffers.read(stream)) {

            {
                let is_newkeys = {
                    let payload = self.buffers.get_current_payload();
                    payload[0] == msg::NEWKEYS
                };
                if is_newkeys {

                    newkeys.received = true;
                    let mut encrypted = newkeys.encrypted(EncryptedState::ServiceRequest);
                    buffer.clear();
                    buffer.push(msg::SERVICE_REQUEST);
                    buffer.extend_ssh_string(b"ssh-userauth");
                
                    encrypted.cipher.write_client_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
                    self.buffers.write.seqn += 1;
                    debug!("sending SERVICE_REQUEST");

                    self.state = Some(ServerState::Encrypted(encrypted))
                }
            }
            self.buffers.read.seqn += 1;
            self.buffers.read.clear();

            Ok(true)
        } else {
            Ok(false)
        }
    }

}


impl Encrypted {

    pub fn client_rekey(&mut self, buf:&[u8], rekey:Kex, keys:&[key::Algorithm], buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
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
                    let hash = try!(kexdhdone.client_compute_exchange_hash(buf, buffer));
                    let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
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


    pub fn client_service_request<R:BufRead>(&mut self, stream:&mut R, auth_method:&Option<auth::Method>, buffers:&mut SSHBuffers, buffer:&mut CryptoBuf) -> Result<bool, Error> {
        println!("service request");
        let read_complete;

        let is_service_accept = {
            if let Some(buf) = try!(self.cipher.read_server_packet(stream, &mut buffers.read)) {
                read_complete = true;
                buf[0] == msg::SERVICE_ACCEPT
            } else {
                read_complete = false;
                false
            }
        };
        if read_complete {
            buffers.read.seqn += 1;
            buffers.read.clear();
        }
        if is_service_accept {
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
        } else {
            println!("other message");
            self.state = Some(EncryptedState::ServiceRequest);
        }
        Ok(read_complete)
    }

    pub fn client_auth_request_success<R:BufRead>(&mut self, stream:&mut R, mut auth_request:AuthRequest, auth_method:&Option<auth::Method>, buffers:&mut SSHBuffers, buffer:&mut CryptoBuf) -> Result<bool, Error> {
        // We're waiting for success.
        let read_complete;
        debug!("client_auth_request_success");
        if let Some(buf) = try!(self.cipher.read_server_packet(stream,&mut buffers.read)) {

            println!("line {}, buf = {:?}", line!(), buf);

            if buf[0] == msg::USERAUTH_SUCCESS {

                self.state = Some(EncryptedState::WaitingChannelOpen)

            } else if buf[0] == msg::USERAUTH_FAILURE {

                let mut r = buf.reader(1);
                let remaining_methods = try!(r.read_string());

                auth_request.methods.keep_remaining(remaining_methods.split(|&c| c==b','));
                self.client_waiting_auth_request(&mut buffers.write, auth_request, auth_method, buffer);

            } else if buf[0] == msg::USERAUTH_PK_OK {

                auth_request.public_key_is_ok = true;
                self.state = Some(EncryptedState::WaitingSignature(auth_request))

            } else {
                println!("unknown message: {:?}", buf);
                self.state = Some(EncryptedState::AuthRequestSuccess(auth_request))
            }
            read_complete = true

        } else {

            read_complete = false

        }


        if read_complete {
            buffers.read.seqn += 1;
            buffers.read.clear();
        }
        Ok(read_complete)
    }

    pub fn client_channel_open_confirmation<R:BufRead>(&mut self, stream:&mut R, mut channels: ChannelParameters, read_buffer:&mut SSHBuffer) -> Result<bool, Error> {
        // Check whether we're receiving a confirmation message.
        let read_complete;

        if let Some(buf) = try!(self.cipher.read_server_packet(stream, read_buffer)) {

            println!("channel_confirmation? {:?}", buf);
            if buf[0] == msg::CHANNEL_OPEN_CONFIRMATION {
                let mut reader = buf.reader(1);
                let id_send = try!(reader.read_u32());
                let id_recv = try!(reader.read_u32());
                let window = try!(reader.read_u32());
                let max_packet = try!(reader.read_u32());

                if channels.sender_channel == id_send {

                    channels.recipient_channel = id_recv;
                    channels.initial_window_size = std::cmp::min(window, channels.initial_window_size);
                    channels.maximum_packet_size = std::cmp::min(max_packet, channels.maximum_packet_size);

                    println!("id_send = {:?}", id_send);
                    self.channels.insert(channels.sender_channel, channels);

                    self.state = Some(EncryptedState::ChannelOpened(id_send));

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
        
        if read_complete {
            read_buffer.clear_incr();
        }
        Ok(read_complete)
    }
}
