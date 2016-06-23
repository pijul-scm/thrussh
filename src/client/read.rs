use super::super::*;
use super::super::msg;
use super::super::negociation;
use std::io::BufRead;
use auth::AuthRequest;
use encoding::Reader;
use std;

impl<'a> super::ClientSession<'a> {
    pub fn client_version_ok<R:BufRead>(&mut self, stream:&mut R, mut exchange: Exchange) -> Result<bool, Error> {
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

        if exchange.client_id.len() > 0 {
            self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                exchange: exchange,
                algo: None,
                sent: false,
                session_id: None,
            })));
        } else {
            self.state = Some(ServerState::VersionOk(exchange));
        }
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

    pub fn client_kexdhdone<R:BufRead>(&mut self, stream:&mut R, mut kexdhdone:KexDhDone, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        debug!("kexdhdone");
        // We've sent ECDH_INIT, waiting for ECDH_REPLY
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }

        if try!(self.buffers.read(stream)) {
            let hash = try!(kexdhdone.client_compute_exchange_hash(self.buffers.get_current_payload(), buffer));
            let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);

            self.state = Some(ServerState::Kex(Kex::NewKeys(new_keys)));
            self.buffers.read.seqn += 1;
            self.buffers.read.clear();

            Ok(true)
        } else {
            self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
            Ok(false)
        }

    }

    pub fn client_newkeys<R:BufRead>(&mut self, stream:&mut R, mut newkeys:NewKeys) -> Result<bool, Error> {

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


    pub fn client_service_request<R:BufRead>(&mut self, stream:&mut R, read_buffer:&mut SSHBuffer) -> Result<bool, Error> {
        println!("service request");
        let read_complete;
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
            read_buffer.seqn += 1;
            read_buffer.clear();
        }
        Ok(read_complete)
    }

    pub fn client_auth_request_success<R:BufRead>(&mut self, stream:&mut R, mut auth_request:AuthRequest, read_buffer:&mut SSHBuffer) -> Result<bool, Error> {
        // We're waiting for success.
        let read_complete;
        if let Some(buf) = try!(self.cipher.read_server_packet(stream,read_buffer)) {

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
            read_buffer.seqn += 1;
            read_buffer.clear();
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
                let id_send = reader.read_u32().unwrap();
                let id_recv = reader.read_u32().unwrap();
                let window = reader.read_u32().unwrap();
                let max_packet = reader.read_u32().unwrap();

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
