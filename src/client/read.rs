use super::*;
use super::super::*;
use super::super::msg;
use super::super::negociation;
use std::io::{Read,BufRead};
use std;
use byteorder::{ByteOrder, BigEndian};
use super::super::encoding::Reader;

impl<'a> ClientSession<'a> {
    pub fn read_cleartext_kexinit<R: BufRead>(
        &mut self,
        stream: &mut R,
        mut kexinit: KexInit,
        keys:&[key::Algorithm])
        -> Result<bool, Error> {

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

        if kexinit.sent {
            if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                self.state = Some(ServerState::Kex(Kex::KexDh(KexDh {
                    exchange: kexinit.exchange,
                    kex: kex,
                    key: key,
                    cipher: cipher,
                    mac: mac,
                    follows: follows,
                    session_id: kexinit.session_id,
                })))
            } else {
                self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
            }
        } else {
            self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
        }
        Ok(received)
    }

    pub fn read_cleartext_kexdhdone<R:BufRead>(&mut self, stream:&mut R, mut kexdhdone:KexDhDone, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        println!("kexdhdone");
        // We've sent ECDH_INIT, waiting for ECDH_REPLY
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }

        if try!(self.buffers.read(stream)) {
            // Received ECDH_REPLY
            let hash = try!(kexdhdone.client_compute_exchange_hash(self.buffers.get_current_payload(), buffer));
            let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);

            self.state = Some(ServerState::Kex(Kex::NewKeys(new_keys)));
            self.buffers.read.clear_incr();

            Ok(true)
        } else {
            self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
            Ok(false)
        }
    }

    pub fn read_cleartext_newkeys<R:BufRead>(&mut self, stream:&mut R, mut newkeys:NewKeys) -> Result<bool, Error> {
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }
        if try!(self.buffers.read(stream)) {

            {
                let payload = self.buffers.get_current_payload();
                if payload[0] == msg::NEWKEYS {

                    newkeys.received = true;

                    if newkeys.sent {
                        self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                    } else {
                        self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                    }
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
    pub fn read_client_encrypted<R:BufRead>(&mut self, stream:&mut R, config:&super::Config, read_buffer:&mut SSHBuffer, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {

        let read_complete;

        let state = std::mem::replace(&mut self.state, None);
        match state {
            Some(EncryptedState::ServiceRequest) => {
                println!("service request");
                if let Some(buf) = try!(self.cipher.read_server_packet(stream, read_buffer)) {

                    println!("buf= {:?}",buf);
                    if buf[0] == msg::SERVICE_ACCEPT {
                        println!("request success");
                        let auth_request = auth::AuthRequest {
                            methods: auth::Methods::all(),
                            partial_success: false,
                            public_key: CryptoBuf::new(),
                            public_key_algorithm: CryptoBuf::new(),
                            public_key_is_ok: false,
                            sent_pk_ok: false,
                        };
                        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    } else {
                        println!("other message");
                        self.state = Some(EncryptedState::ServiceRequest);
                    }
                    read_complete = true
                } else {
                    read_complete = false
                };

                if read_complete {
                    read_buffer.clear_incr()
                }
            },
            Some(EncryptedState::AuthRequestSuccess(mut auth_request)) => {

                // We're waiting for success.
                
                if let Some(buf) = try!(self.cipher.read_server_packet(stream, read_buffer)) {

                    println!("line {}, buf = {:?}", line!(), buf);

                    if buf[0] == msg::USERAUTH_SUCCESS {

                        self.state = Some(EncryptedState::WaitingChannelOpen)

                    } else if buf[0] == msg::USERAUTH_FAILURE {

                        let mut r = buf.reader(1);
                        let remaining_methods = r.read_string().unwrap();

                        auth_request.methods.keep_remaining(remaining_methods.split(|&c| c==b','));

                        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request))

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
                    read_buffer.clear_incr();
                }
                
            },
            Some(EncryptedState::WaitingSignature(auth_request)) => {
                // The server is waiting for our authentication signature (also USERAUTH_REQUEST).
                self.state = Some(EncryptedState::WaitingSignature(auth_request));
                read_complete = false
            },
            Some(EncryptedState::WaitingChannelOpen) => {
                // The server is waiting for our CHANNEL_OPEN.
                self.state = Some(EncryptedState::WaitingChannelOpen);
                read_complete = false
            },
            Some(EncryptedState::ChannelOpenConfirmation(mut channels)) => {

                // Check whether we're receiving a confirmation message.
                if let Some(buf) = try!(self.cipher.read_server_packet(stream, read_buffer)) {


                    println!("channel_confirmation? {:?}", buf);
                    if buf[0] == msg::CHANNEL_OPEN_CONFIRMATION {

                        let id_send = BigEndian::read_u32(&buf[1..]);
                        let id_recv = BigEndian::read_u32(&buf[5..]);
                        let window = BigEndian::read_u32(&buf[9..]);
                        let max_packet = BigEndian::read_u32(&buf[13..]);

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
                    read_buffer.clear_incr()
                }
            }
            state => {
                println!("read state {:?}", state);
                if let Some(buf) = try!(self.cipher.read_server_packet(stream, read_buffer)) {

                    println!("msg: {:?}", buf);
                    try!(self.read_client_rekey(buf, config, buffer, buffer2));
                    read_complete = true
                } else {
                    read_complete = false
                };
                if read_complete {
                    read_buffer.clear_incr();
                }
                self.state = state;
            }
        }
        Ok(read_complete)
    }

    pub fn read_client_rekey(&mut self, buf:&[u8], config:&super::Config, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {

        match std::mem::replace(&mut self.rekey, None) {
            Some(Kex::KexInit(mut kexinit)) => {
                debug!("received KEXINIT");
                if kexinit.algo.is_none() {

                    if buf[0] != msg::KEXINIT {
                        self.rekey = Some(Kex::KexInit(kexinit));
                        return Ok(false)
                    }
                    
                    kexinit.algo = Some(try!(negociation::client_read_kex(buf, &config.keys)));
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
                Ok(true)
            },
            Some(Kex::KexDhDone(mut kexdhdone)) => {
                
                let hash = try!(kexdhdone.client_compute_exchange_hash(buf, buffer));
                let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                self.rekey = Some(Kex::NewKeys(new_keys));
                Ok(true)
            },
            Some(Kex::NewKeys(mut newkeys)) => {
                if buf[0] == msg::NEWKEYS {
                    newkeys.received = true;
                    if !newkeys.sent {
                        self.rekey = Some(Kex::NewKeys(newkeys));
                    }
                    Ok(true)
                } else {
                    self.rekey = Some(Kex::NewKeys(newkeys));
                    Ok(false)
                }
            },
            Some(state) => {
                self.rekey = Some(state);
                Ok(true)
            }
            None if buf[0] == msg::KEXINIT => {
                // The server is initiating a rekeying.
                let mut kexinit = KexInit::rekey(
                    std::mem::replace(&mut self.exchange, None).unwrap(),
                    try!(super::super::negociation::read_kex(buf, &config.keys)),
                    &self.session_id
                );
                kexinit.exchange.server_kex_init.extend(buf);
                self.rekey = Some(try!(kexinit.kexinit()));
                Ok(true)
            },
            None => {
                Ok(false)
            }
        }
    }
}
