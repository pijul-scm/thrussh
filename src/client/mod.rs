use super::{CryptoBuf, Exchange, Error, ServerState, Kex, KexInit, KexDh, KexDhDone, EncryptedState, ChannelParameters};
use super::encoding::*;
use super::key;
use super::msg;
use super::auth;
use super::negociation;
use rand;
use rand::Rng;
use std::io::{Write,BufRead};
use std;
use time;

mod read;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
    pub window: u32,
    pub maxpacket: u32
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
            rekey_time_limit_s: 3600.0,
            window:200000,
            maxpacket:200000
        }
    }
}

pub struct ClientSession<'a> {
    buffers: super::SSHBuffers,
    state: Option<ServerState>,
    auth_method: Option<auth::Method<'a>>
}


impl<'a> ClientSession<'a> {
    pub fn new() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        ClientSession {
            buffers: super::SSHBuffers::new(),
            state: None,
            auth_method: None
        }
    }
    // returns whether a complete packet has been read.
    pub fn read<R: BufRead>(&mut self,
                            config: &Config,
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
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => self.read_cleartext_kexinit(stream, kexinit, &config.keys),

            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                println!("kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => self.read_cleartext_kexdhdone(stream, kexdhdone, buffer, buffer2),

            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => self.read_cleartext_newkeys(stream, newkeys),
            
            Some(ServerState::Encrypted(mut enc)) => {
                println!("encrypted state");
                self.try_rekey(&mut enc, &config);
                let result = enc.read_client_encrypted(stream, config, &mut self.buffers.read, buffer, buffer2);
                self.state = Some(ServerState::Encrypted(enc));
                result
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
        self.buffers.write.clear();

        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                try!(self.buffers.send_ssh_id(stream, config.client_id.as_bytes()));
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
                    try!(self.buffers.send_ssh_id(stream, config.client_id.as_bytes()));
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
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => {
                self.state = Some(try!(self.buffers.cleartext_write_kex_init(
                    &config.keys,
                    false, // is_server
                    kexinit,
                    stream)));
                Ok(true)
            },
            Some(ServerState::Kex(Kex::KexDh(mut kexdh))) => {

                self.buffers.write.buffer.extend(b"\0\0\0\0\0");

                let kex = try!(kexdh.kex.client_dh(&mut kexdh.exchange, &mut self.buffers.write.buffer));

                super::complete_packet(&mut self.buffers.write.buffer, 0);
                self.buffers.write.seqn += 1;
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
                    self.buffers.write.buffer.extend(b"\0\0\0\0\0");
                    self.buffers.write.buffer.push(msg::NEWKEYS);
                    super::complete_packet(&mut self.buffers.write.buffer, 0);
                    self.buffers.write.seqn += 1;

                    newkeys.sent = true;
                }
                if newkeys.received {
                    // Skipping over the WaitingServiceRequest state,
                    // since we're immediately sending the request.
                    let mut encrypted = newkeys.encrypted(EncryptedState::ServiceRequest);
                    buffer.clear();
                    buffer.push(msg::SERVICE_REQUEST);
                    buffer.extend_ssh_string(b"ssh-userauth");

                    encrypted.cipher.write_client_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
                    self.buffers.write.seqn += 1;
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

                self.try_rekey(&mut enc, &config);

                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
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
                            enc.cipher.write_client_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
                            self.buffers.write.seqn += 1;
                            try!(self.buffers.write_all(stream));
                            enc.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
                        } else {
                            println!("method not ok");
                            enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        }
                    },

                    Some(EncryptedState::WaitingSignature(auth_request)) => {
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
                        enc.cipher.write_client_packet(self.buffers.write.seqn,
                                                       &(buffer.as_slice())[i0..], // Skip the session id.
                                                       &mut self.buffers.write.buffer);

                        self.buffers.write.seqn += 1;
                        try!(self.buffers.write_all(stream));

                        enc.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
                        
                    },
                    Some(EncryptedState::WaitingChannelOpen) => {
                        // The server is waiting for our CHANNEL_OPEN.
                        let mut sender_channel = 0;
                        while enc.channels.contains_key(&sender_channel) || sender_channel == 0 {
                            sender_channel = rand::thread_rng().gen()
                        }
                        buffer.clear();
                        buffer.push(msg::CHANNEL_OPEN);
                        buffer.extend_ssh_string(b"channel name");
                        buffer.push_u32_be(sender_channel); // sender channel id.
                        buffer.push_u32_be(config.window); // window.
                        buffer.push_u32_be(config.maxpacket); // max packet size.
                        // Send
                        enc.cipher.write_client_packet(self.buffers.write.seqn,
                                                       buffer.as_slice(),
                                                       &mut self.buffers.write.buffer);

                        self.buffers.write.seqn += 1;
                        try!(self.buffers.write_all(stream));
                        enc.state = Some(EncryptedState::ChannelOpenConfirmation(
                            ChannelParameters {
                                recipient_channel: 0,
                                sender_channel: sender_channel,
                                initial_window_size: config.window,
                                maximum_packet_size: config.maxpacket,
                            }
                        ));
                        
                    },
                    state => {
                        match std::mem::replace(&mut enc.rekey, None) {
                            Some(Kex::KexInit(mut kexinit)) => {

                                if !kexinit.sent {
                                    buffer.clear();
                                    negociation::write_kex(&config.keys, buffer);
                                    kexinit.exchange.client_kex_init.extend(buffer.as_slice());

                                    enc.cipher.write_client_packet(self.buffers.write.seqn, buffer.as_slice(),
                                                                   &mut self.buffers.write.buffer);
                                    
                                    self.buffers.write.seqn += 1;
                                    try!(self.buffers.write_all(stream));
                                    kexinit.sent = true;
                                }
                                if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                                    enc.rekey = Some(Kex::KexDh(KexDh {
                                        exchange: kexinit.exchange,
                                        kex: kex,
                                        key: key,
                                        cipher: cipher,
                                        mac: mac,
                                        follows: follows,
                                        session_id: kexinit.session_id,
                                    }))
                                } else {
                                    enc.rekey = Some(Kex::KexInit(kexinit))
                                }
                            },
                            Some(Kex::KexDh(mut kexdh)) => {
                                
                                buffer.clear();
                                let kex = try!(kexdh.kex.client_dh(&mut kexdh.exchange, buffer));
                                
                                enc.cipher.write_client_packet(self.buffers.write.seqn, buffer.as_slice(),
                                                               &mut self.buffers.write.buffer);
                                self.buffers.write.seqn += 1;
                                try!(self.buffers.write_all(stream));

                                enc.rekey = Some(Kex::KexDhDone(KexDhDone {
                                    exchange: kexdh.exchange,
                                    kex: kex,
                                    key: kexdh.key,
                                    cipher: kexdh.cipher,
                                    mac: kexdh.mac,
                                    follows: kexdh.follows,
                                    session_id: kexdh.session_id,
                                }));
                            },
                            Some(Kex::NewKeys(mut newkeys)) => {

                                if !newkeys.sent {
                                    enc.cipher.write_client_packet(self.buffers.write.seqn, &[msg::NEWKEYS],
                                                                         &mut self.buffers.write.buffer);
                                    self.buffers.write.seqn += 1;
                                    newkeys.sent = true;
                                }
                                if !newkeys.received {
                                    try!(self.buffers.write_all(stream));
                                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)))
                                }
                            },
                            Some(state) => {
                                enc.rekey = Some(state)
                            }
                            None => {},
                        }
                        enc.state = state
                    }
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
        }
        
    }
    pub fn try_rekey(&mut self, enc: &mut super::Encrypted, config:&Config) {
        if enc.rekey.is_none() &&
            (self.buffers.write.bytes >= config.rekey_write_limit
             || self.buffers.read.bytes >= config.rekey_read_limit
             || time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s) {
                let mut kexinit = KexInit {
                    exchange: std::mem::replace(&mut enc.exchange, None).unwrap(),
                    algo: None,
                    sent: false,
                    session_id: Some(enc.session_id.clone()),
                };
                kexinit.exchange.client_kex_init.clear();
                kexinit.exchange.server_kex_init.clear();
                kexinit.exchange.client_ephemeral.clear();
                kexinit.exchange.server_ephemeral.clear();
                enc.rekey = Some(Kex::KexInit(kexinit))
            } else {
                debug!("not yet rekeying, {:?}", self.buffers.write.bytes)
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

    pub fn opened_channel(&self) -> Option<u32> {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::ChannelOpened(x)) => Some(x),
                    _ => None
                }
            },
            _ => None
        }
    }

    pub fn set_method(&mut self, method:auth::Method<'a>) {
        self.auth_method = Some(method)
    }

    pub fn msg<W:Write>(&mut self, stream:&mut W, buffer:&mut CryptoBuf, msg:&[u8], channel:u32) -> Result<bool,Error> {

        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::ChannelOpened(_)) => {

                        let c = enc.channels.get(&channel).unwrap();
                        buffer.clear();
                        buffer.push(msg::CHANNEL_DATA);
                        buffer.push_u32_be(c.recipient_channel);
                        buffer.extend_ssh_string(msg);
                        println!("{:?} {:?}", buffer.as_slice(), self.buffers.write.seqn);
                        enc.cipher.write_client_packet(self.buffers.write.seqn,
                                                       buffer.as_slice(),
                                                       &mut self.buffers.write.buffer);
                        println!("buf = {:?}", self.buffers.write.buffer.as_slice());
                        self.buffers.write.seqn += 1;
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
