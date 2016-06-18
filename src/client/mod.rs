use byteorder::{ByteOrder, BigEndian};
use super::{CryptoBuf, Exchange, Error, ServerState, Kex, KexInit, KexDh, KexDhDone, EncryptedState, ChannelParameters};
use super::encoding::*;
use super::key;
use super::kex;
use super::msg;
use super::auth;
use super::negociation;
use std::io::{Write,BufRead};
use std;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64
}

impl std::default::Default for Config {
    fn default() -> Config {
        Config {
            client_id: "SSH-2.0-Russht_0.1".to_string(),
            keys: Vec::new(),
            // Following the recommendations of
            // https://tools.ietf.org/html/rfc4253#section-9
            rekey_write_limit: 1<<30, // 1 Gb
            rekey_read_limit: 1<<30, // 1 Gb
            rekey_time_limit_s: 3600.0
        }
    }
}

pub struct ClientSession<'a, C> {
    buffers: super::SSHBuffers,
    state: Option<ServerState<C>>,
    auth_method: Option<auth::Method<'a>>
}

pub trait Client {
    fn init(&self, channel:&ChannelParameters) -> Self;
}


impl<'a, C:Client> ClientSession<'a, C> {
    pub fn new() -> Self {
        ClientSession {
            buffers: super::SSHBuffers::new(),
            state: None,
            auth_method: None
        }
    }
    // returns whether a complete packet has been read.
    pub fn read<R: BufRead>(&mut self,
                                      config: &Config,
                                      client: &C,
                                      stream: &mut R,
                                      buffer: &mut CryptoBuf,
                                      buffer2: &mut CryptoBuf)
                                      -> Result<bool, Error> {
        println!("read");
        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                // We have neither sent nor received the version id.
                let server_id = try!(self.buffers.read_ssh_id(stream));
                println!("server_id = {:?}", server_id);
                if let Some(server_id) = server_id {
                    let mut exchange = Exchange::new();
                    exchange.server_id.extend(server_id);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            Some(ServerState::VersionOk(mut exchange)) => {
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
            },
            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                println!("kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                // Have we determined the algorithm yet?
                let mut received = false;
                if kexinit.algo.is_none() {
                    // We've sent ECDH_INIT, waiting for ECDH_REPLY
                    if self.buffers.read_len == 0 {
                        try!(self.buffers.set_clear_len(stream));
                    }

                    if try!(self.buffers.read(stream)) {
                        println!("received: {:?}", String::from_utf8_lossy(self.buffers.get_current_payload()));
                        kexinit.algo = Some(try!(negociation::client_read_kex(self.buffers.get_current_payload(), &config.keys)));

                        kexinit.exchange.server_kex_init.extend(self.buffers.get_current_payload());
                        self.buffers.recv_seqn += 1;
                        self.buffers.read_buffer.clear();
                        self.buffers.read_len = 0;
                        
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
            Some(ServerState::Kex(Kex::KexDhDone(mut kexdhdone))) => {

                println!("kexdhdone");


                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                if self.buffers.read_len == 0 {
                    try!(self.buffers.set_clear_len(stream));
                }

                if try!(self.buffers.read(stream)) {

                    let hash = {
                        let payload = self.buffers.get_current_payload();
                        // println!("payload = {:?}", payload);
                        assert!(payload[0] == msg::KEX_ECDH_REPLY);
                        let mut pos = 1;
                        let pubkey_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos += 4;
                        let pubkey = &payload[pos..pos+pubkey_len];
                        pos += pubkey_len;

                        let ephemeral_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos+=4;
                        let server_ephemeral = &payload[pos .. pos+ephemeral_len];
                        kexdhdone.exchange.server_ephemeral.extend(server_ephemeral);
                        pos+=ephemeral_len;

                        let signature_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos+=4;
                        let signature = &payload[pos .. pos+signature_len];
                        pos+=signature_len;

                        kexdhdone.kex.compute_shared_secret(&kexdhdone.exchange.server_ephemeral);

                        let pubkey = try!(super::read_public_key(pubkey));
                        let hash = try!(kexdhdone.kex.compute_exchange_hash(&pubkey,
                                                                            &kexdhdone.exchange,
                                                                            buffer));

                        let signature = {
                            let sig_type_len = BigEndian::read_u32(&signature) as usize;
                            let sig_type = &signature[4..4+sig_type_len];
                            let sig_len = BigEndian::read_u32(&signature[4+sig_type_len ..]) as usize;

                            super::sodium::ed25519::Signature::copy_from_slice(&signature[8+sig_type_len .. 8+sig_type_len+sig_len])
                        };

                        let verif = match pubkey {
                            key::PublicKey::Ed25519(ref pubkey) => {
                                super::sodium::ed25519::verify_detached(&signature, hash.as_bytes(), pubkey)
                            }
                        };
                        if !verif {
                            panic!("wrong server signature")
                        }
                        println!("signature = {:?}", signature);
                        println!("exchange = {:?}", kexdhdone.exchange);
                        hash
                    };
                    let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);

                    self.state = Some(ServerState::Kex(Kex::NewKeys(new_keys)));
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;

                    Ok(true)
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                    Ok(false)
                }

            },
            Some(ServerState::Kex(Kex::NewKeys(mut newkeys))) => {
                if self.buffers.read_len == 0 {
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
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;

                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Some(ServerState::Encrypted(mut enc)) => {
                println!("encrypted state");
                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::ServiceRequest) => {
                        println!("service request");
                        let buf_received = if let Some(buf) = try!(enc.cipher.read_server_packet(
                            &mut self.buffers.read_bytes,
                            self.buffers.recv_seqn,
                            stream,
                            &mut self.buffers.read_len,
                            &mut self.buffers.read_buffer)) {

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
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                            } else {
                                println!("other message");
                                enc.state = Some(EncryptedState::ServiceRequest);
                            }
                            true
                        } else {
                            println!("service request false, target {:?}", self.buffers.read_len);
                            false
                        };

                        if buf_received {
                            self.buffers.recv_seqn += 1;
                            self.buffers.read_buffer.clear();
                            self.buffers.read_len = 0;
                        }
                    },
                    /*Some(EncryptedState::WaitingAuthRequest(mut auth_request)) => {
                        // The server is waiting for our USERAUTH_REQUEST.
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    },*/
                    Some(EncryptedState::AuthRequestSuccess(mut auth_request)) => {

                        // We're waiting for success.
                        let read =
                            if let Some(buf) = try!(enc.cipher.read_server_packet(
                                &mut self.buffers.read_bytes,
                                self.buffers.recv_seqn,
                                stream,
                                &mut self.buffers.read_len,
                                &mut self.buffers.read_buffer)) {

                                println!("line {}, buf = {:?}", line!(), buf);

                                if buf[0] == msg::USERAUTH_SUCCESS {

                                    enc.state = Some(EncryptedState::WaitingChannelOpen)

                                } else if buf[0] == msg::USERAUTH_FAILURE {

                                    let mut r = buf.reader(1);
                                    let remaining_methods = r.read_string().unwrap();

                                    auth_request.methods.keep_remaining(remaining_methods.split(|&c| c==b','));

                                    enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request))

                                } else if buf[0] == msg::USERAUTH_PK_OK {

                                    auth_request.public_key_is_ok = true;
                                    enc.state = Some(EncryptedState::WaitingSignature(auth_request))

                                } else {
                                    println!("unknown message: {:?}", buf);
                                    enc.state = Some(EncryptedState::AuthRequestSuccess(auth_request))
                                }
                                true

                            } else {

                                false

                            };


                        if read {
                            self.buffers.recv_seqn += 1;
                            self.buffers.read_buffer.clear();
                            self.buffers.read_len = 0;
                        }
                        
                    },
                    Some(EncryptedState::WaitingSignature(mut auth_request)) => {
                        // The server is waiting for our authentication signature (also USERAUTH_REQUEST).
                        enc.state = Some(EncryptedState::WaitingSignature(auth_request))
                    },
                    Some(EncryptedState::WaitingChannelOpen) => {
                        // The server is waiting for our CHANNEL_OPEN.
                        enc.state = Some(EncryptedState::WaitingChannelOpen)
                    },
                    Some(EncryptedState::ChannelOpenConfirmation(mut channels)) => {

                        // Check whether we're receiving a confirmation message.
                        let read = if let Some(buf) = try!(enc.cipher.read_server_packet(
                            &mut self.buffers.read_bytes,
                            self.buffers.recv_seqn,
                            stream,
                            &mut self.buffers.read_len,
                            &mut self.buffers.read_buffer)) {


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

                                    let client = C::init(client, &channels);
                                    println!("id_send = {:?}", id_send);
                                    enc.channels.insert(channels.sender_channel,
                                                        super::Channel {
                                                            parameters: channels,
                                                            engine: client,
                                                        });

                                    enc.state = Some(EncryptedState::ChannelOpened(id_send));

                                } else {

                                    unimplemented!()
                                }
                            } else {
                                enc.state = Some(EncryptedState::ChannelOpenConfirmation(channels));
                            }
                            true
                        } else {
                            enc.state = Some(EncryptedState::ChannelOpenConfirmation(channels));
                            false
                        };
                        
                        if read {
                            self.buffers.recv_seqn += 1;
                            self.buffers.read_buffer.clear();
                            self.buffers.read_len = 0;
                        }
                    }
                    /*Some(EncryptedState::ChannelOpened(x)) => {
                        enc.state = Some(EncryptedState::ChannelOpened(x));
                        true
                    }*/
                    state => {
                        println!("read state {:?}", state);
                        let read = if let Some(buf) = try!(enc.cipher.read_server_packet(
                            &mut self.buffers.read_bytes,
                            self.buffers.recv_seqn,
                            stream,
                            &mut self.buffers.read_len,
                            &mut self.buffers.read_buffer)) {

                            println!("msg: {:?}", buf);
                            true
                        } else { false };

                        if read {
                            self.buffers.recv_seqn += 1;
                            self.buffers.read_buffer.clear();
                            self.buffers.read_len = 0;
                        }
                        enc.state = state;
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
        }

    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self,
                           config: &Config,
                           stream: &mut W,
                           buffer: &mut CryptoBuf,
                           buffer2: &mut CryptoBuf)
                           -> Result<bool, Error> {
        println!("write");
        // Finish pending writes, if any.
        if ! try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        self.buffers.write_buffer.clear();
        self.buffers.write_position = 0;

        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                self.buffers.send_ssh_id(stream, config.client_id.as_bytes());
                let mut exchange = Exchange::new();
                exchange.client_id.extend(config.client_id.as_bytes());
                println!("sent!: {:?}", exchange);
                self.state = Some(ServerState::VersionOk(exchange));
                Ok(true)
            },
            Some(ServerState::VersionOk(mut exchange)) => {
                println!("read: {:?}", exchange);
                // Have we received the version id?
                if exchange.client_id.len() == 0 {
                    self.buffers.send_ssh_id(stream, config.client_id.as_bytes());
                    exchange.client_id.extend(config.client_id.as_bytes());
                }

                if exchange.server_id.len() > 0 {
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
            },
            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                self.state = Some(try!(self.buffers.cleartext_write_kex_init(
                    &config.keys,
                    false, // is_server
                    kexinit,
                    stream)));
                Ok(true)
            },
            Some(ServerState::Kex(Kex::KexDh(mut kexdh))) => {

                self.buffers.write_buffer.extend(b"\0\0\0\0\0");

                let kex = try!(kexdh.kex.client_dh(&mut kexdh.exchange, &mut self.buffers.write_buffer));

                super::complete_packet(&mut self.buffers.write_buffer, 0);
                self.buffers.sent_seqn += 1;
                try!(self.buffers.write_all(stream));

                self.state = Some(ServerState::Kex(Kex::KexDhDone(KexDhDone {
                    exchange: kexdh.exchange,
                    kex: kex,
                    key: kexdh.key,
                    cipher: kexdh.cipher,
                    mac: kexdh.mac,
                    follows: kexdh.follows,
                    session_id: kexdh.session_id,
                })));
                Ok(true)

            },
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => {
                // We're waiting for ECDH_REPLY from server, nothing to write.
                self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                Ok(true)
            },
            Some(ServerState::Kex(Kex::NewKeys(mut newkeys))) => {

                if !newkeys.sent {
                    debug!("sending NEWKEYS");
                    self.buffers.write_buffer.extend(b"\0\0\0\0\0");
                    self.buffers.write_buffer.push(msg::NEWKEYS);
                    super::complete_packet(&mut self.buffers.write_buffer, 0);
                    self.buffers.sent_seqn += 1;

                    newkeys.sent = true;
                }
                if newkeys.received {
                    // Skipping over the WaitingServiceRequest state,
                    // since we're immediately sending the request.
                    let mut encrypted = newkeys.encrypted(EncryptedState::ServiceRequest);
                    buffer.clear();
                    buffer.push(msg::SERVICE_REQUEST);
                    buffer.extend_ssh_string(b"ssh-userauth");

                    encrypted.cipher.write_client_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
                    self.buffers.sent_seqn += 1;
                    try!(self.buffers.write_all(stream));
                    println!("sending SERVICE_REQUEST");
                    self.state = Some(ServerState::Encrypted(encrypted));
                } else {
                    try!(self.buffers.write_all(stream));
                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)))
                }
                Ok(true)

            }
            Some(ServerState::Encrypted(mut enc)) => {
                println!("encrypted");
                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::WaitingAuthRequest(mut auth_request)) => {
                        // The server is waiting for our USERAUTH_REQUEST.
                        buffer.clear();

                        buffer.push(msg::USERAUTH_REQUEST);
                        let method_ok = match self.auth_method {
                            Some(auth::Method::Password { user, password }) => {

                                buffer.extend_ssh_string(user.as_bytes());
                                buffer.extend_ssh_string(b"ssh-connection");
                                buffer.extend_ssh_string(b"password");
                                buffer.push(1);
                                buffer.extend_ssh_string(password.as_bytes());
                                true
                            },
                            Some(auth::Method::Pubkey { ref user, ref pubkey, .. }) => {
                                buffer.extend_ssh_string(user.as_bytes());
                                buffer.extend_ssh_string(b"ssh-connection");
                                buffer.extend_ssh_string(b"publickey");
                                buffer.push(0); // This is a probe
                                buffer.extend_ssh_string(pubkey.name().as_bytes());
                                pubkey.extend_pubkey(buffer);
                                true
                            },
                            _ => {
                                false
                            }
                        };
                        if method_ok {
                            println!("method ok");
                            enc.cipher.write_client_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
                            self.buffers.sent_seqn += 1;
                            try!(self.buffers.write_all(stream));
                            enc.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
                        } else {
                            println!("method not ok");
                            enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        }
                    },

                    Some(EncryptedState::WaitingSignature(mut auth_request)) => {
                        // The server is waiting for our authentication signature (also USERAUTH_REQUEST).

                        buffer.clear();

                        buffer.extend_ssh_string(enc.session_id.as_bytes());
                        let i0 = buffer.len();

                        buffer.push(msg::USERAUTH_REQUEST);
                        buffer.extend_ssh_string(b"pe");
                        buffer.extend_ssh_string(b"ssh-connection");

                        buffer.extend_ssh_string(b"publickey");
                        buffer.push(1); // This is a probe
                        buffer.extend_ssh_string(config.keys[0].name().as_bytes());
                        config.keys[0].public_host_key.extend_pubkey(buffer);

                        // Extend with signature.
                        println!("========== signing");
                        buffer2.clear();
                        config.keys[0].add_signature(buffer2, buffer.as_slice());
                        buffer.extend(buffer2.as_slice());

                        // Send
                        enc.cipher.write_client_packet(self.buffers.sent_seqn,
                                                       &(buffer.as_slice())[i0..], // Skip the session id.
                                                       &mut self.buffers.write_buffer);

                        self.buffers.sent_seqn += 1;
                        try!(self.buffers.write_all(stream));

                        enc.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
                        
                    },
                    Some(EncryptedState::WaitingChannelOpen) => {
                        // The server is waiting for our CHANNEL_OPEN.
                        /*
                        let typ_len = BigEndian::read_u32(&buf[1..]) as usize;
                        let typ = &buf[5..5 + typ_len];
                        let sender = BigEndian::read_u32(&buf[5 + typ_len..]);
                        let window = BigEndian::read_u32(&buf[9 + typ_len..]);
                        let maxpacket = BigEndian::read_u32(&buf[13 + typ_len..]);
                         */
                        let sender_channel = 23;
                        let window = 200000;
                        let maxpacket = 200000;

                        buffer.clear();
                        buffer.push(msg::CHANNEL_OPEN);
                        buffer.extend_ssh_string(b"channel name");
                        buffer.push_u32_be(sender_channel); // sender channel id.
                        buffer.push_u32_be(window); // window.
                        buffer.push_u32_be(maxpacket); // max packet size.
                        // Send
                        enc.cipher.write_client_packet(self.buffers.sent_seqn,
                                                       buffer.as_slice(),
                                                       &mut self.buffers.write_buffer);

                        self.buffers.sent_seqn += 1;
                        try!(self.buffers.write_all(stream));
                        enc.state = Some(EncryptedState::ChannelOpenConfirmation(
                            ChannelParameters {
                                recipient_channel: 0,
                                sender_channel: sender_channel,
                                initial_window_size: window,
                                maximum_packet_size: maxpacket,
                            }
                        ));
                            
                    },
                    Some(EncryptedState::ChannelOpened(id)) => {
                        println!("write state {:?}", state);

                        if let Some(ref mut channel) = enc.channels.get_mut(&id) {
                            println!("FOUND!");
                            /*buffer.clear();
                            buffer.push(msg::CHANNEL_DATA);
                            buffer.push_u32_be(channel.parameters.recipient_channel);
                            buffer.extend_ssh_string(b"blabla\r\n");
                            println!("{:?} {:?}", buffer.as_slice(), self.buffers.sent_seqn);
                            enc.cipher.write_client_packet(self.buffers.sent_seqn,
                                                           buffer.as_slice(),
                                                           &mut self.buffers.write_buffer);
                            println!("buf = {:?}", self.buffers.write_buffer.as_slice());
                            self.buffers.sent_seqn += 1;

                            try!(self.buffers.write_all(stream));
                             */
                        }
                        enc.state = state
                    }
                    state => {
                        debug!("write state {:?}", state);
                        enc.state = state
                    }
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
        }
        
    }

    pub fn needs_auth_method(&self) -> Option<auth::Methods> {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingAuthRequest(ref auth_request)) => {

                        println!("needs_auth_method: {:?}", auth_request);
                        Some(auth_request.methods)
                        
                    },
                    _ => None
                }
            },
            _ => None
        }
    }
    pub fn is_authenticated(&self) -> bool {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingChannelOpen)
                        | Some(EncryptedState::ChannelOpenConfirmation(_))
                        | Some(EncryptedState::ChannelOpened(_))
                        => {

                        true
                        
                    },
                    _ => false
                }
            },
            _ => false
        }
    }

    pub fn set_method(&mut self, method:auth::Method<'a>) {
        self.auth_method = Some(method)
    }

    pub fn msg<W:Write>(&mut self, stream:&mut W, buffer:&mut CryptoBuf, msg:&[u8]) -> Result<bool,Error> {

        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::ChannelOpened(x)) => {

                        let c = enc.channels.get(&x).unwrap();
                        buffer.clear();
                        buffer.push(msg::CHANNEL_DATA);
                        buffer.push_u32_be(c.parameters.recipient_channel);
                        buffer.extend_ssh_string(msg);
                        println!("{:?} {:?}", buffer.as_slice(), self.buffers.sent_seqn);
                        enc.cipher.write_client_packet(self.buffers.sent_seqn,
                                                       buffer.as_slice(),
                                                       &mut self.buffers.write_buffer);
                        println!("buf = {:?}", self.buffers.write_buffer.as_slice());
                        self.buffers.sent_seqn += 1;
                        try!(self.buffers.write_all(stream));
                        Ok(true)
                    },
                    _ => Ok(false)
                }
            },
            _ => Ok(false)
        }

    }
}
