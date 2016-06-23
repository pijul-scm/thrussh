use byteorder::{ByteOrder, BigEndian};
use super::{CryptoBuf, Exchange, Error, ServerState, Kex, KexInit, KexDhDone, EncryptedState, ChannelBuf};
use super::encoding::*;
use super::key;
use super::msg;
use super::auth;
use std::io::{Write,BufRead};
use std;
use time;

mod write;
// use self::write::*;
mod read;
// use self::read::*;

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
    auth_method: Option<auth::Method<'a>>,
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
    pub fn read<R: BufRead, C:super::SSHHandler>(
        &mut self,
        config: &Config,
        client: &mut C,
        stream: &mut R,
        buffer: &mut CryptoBuf,
        buffer2: &mut CryptoBuf)
        -> Result<bool, Error> {

        debug!("read");
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
            Some(ServerState::VersionOk(exchange)) => self.client_version_ok(stream, exchange),
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => self.client_kexinit(stream, kexinit, &config.keys),
            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                debug!("reading kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => self.client_kexdhdone(stream, kexdhdone, buffer, buffer2),
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => self.client_newkeys(stream, newkeys),
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted state");
                self.try_rekey(&mut enc, &config);
                let state = std::mem::replace(&mut enc.state, None);

                let read_complete;

                match state {
                    Some(EncryptedState::ServiceRequest) => {
                        read_complete = try!(enc.client_service_request(stream, &mut self.buffers.read))
                    },
                    Some(EncryptedState::AuthRequestSuccess(auth_request)) => {
                        read_complete = try!(enc.client_auth_request_success(stream, auth_request, &mut self.buffers.read))
                    },
                    Some(EncryptedState::WaitingSignature(auth_request)) => {
                        // The server is waiting for our authentication signature (also USERAUTH_REQUEST).
                        enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                        read_complete = false
                    },
                    Some(EncryptedState::WaitingChannelOpen) => {
                        // The server is waiting for our CHANNEL_OPEN.
                        enc.state = Some(EncryptedState::WaitingChannelOpen);
                        read_complete = false
                    },
                    Some(EncryptedState::ChannelOpenConfirmation(channels)) => {
                        read_complete = try!(enc.client_channel_open_confirmation(stream, channels, &mut self.buffers.read))
                    }
                    state => {
                        debug!("read state {:?}", state);
                        let mut is_newkeys = false;
                        if let Some(buf) = try!(enc.cipher.read_server_packet(stream,&mut self.buffers.read)) {

                            println!("msg: {:?} {:?}", buf, enc.rekey);
                            match std::mem::replace(&mut enc.rekey, None) {
                                Some(rekey) => {
                                    is_newkeys = try!(enc.client_rekey(buf, rekey, &config.keys, buffer, buffer2))
                                }
                                None if buf[0] == msg::KEXINIT => {
                                    // The server is initiating a rekeying.
                                    let mut kexinit = KexInit::rekey(
                                        std::mem::replace(&mut enc.exchange, None).unwrap(),
                                        try!(super::negociation::read_kex(buf, &config.keys)),
                                        &enc.session_id
                                    );
                                    kexinit.exchange.server_kex_init.extend(buf);
                                    enc.rekey = Some(try!(kexinit.kexinit()));
                                },
                                None => {
                                    // standard response
                                    if buf[0] == msg::CHANNEL_DATA {

                                        let channel_num = BigEndian::read_u32(&buf[1..]);
                                        if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {

                                            let len = BigEndian::read_u32(&buf[5..]) as usize;
                                            let data = &buf[9..9 + len];
                                            buffer.clear();
                                            let server_buf = ChannelBuf {
                                                buffer:buffer,
                                                recipient_channel: channel.recipient_channel,
                                                sent_seqn: &mut self.buffers.write.seqn,
                                                write_buffer: &mut self.buffers.write.buffer,
                                                cipher: &mut enc.cipher
                                            };
                                            try!(client.data(&data, server_buf))
                                        }
                                    }
                                },
                            }
                            read_complete = true;
                        } else {
                            read_complete = false
                        };
                        if read_complete {
                            if is_newkeys {
                                self.buffers.read.bytes = 0;
                                self.buffers.write.bytes = 0;
                            }
                            self.buffers.read.clear_incr();
                        }
                        enc.state = state;
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(read_complete)
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
        debug!("write, buffer: {:?}", self.buffers.write);
        // Finish pending writes, if any.
        if ! try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }

        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                try!(self.buffers.send_ssh_id(stream, config.client_id.as_bytes()));
                let mut exchange = Exchange::new();
                exchange.client_id.extend(config.client_id.as_bytes());
                debug!("sent!: {:?}", exchange);
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
                    debug!("sending SERVICE_REQUEST");
                    self.state = Some(ServerState::Encrypted(encrypted));
                } else {
                    try!(self.buffers.write_all(stream));
                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)))
                }
                Ok(true)

            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted");

                self.try_rekey(&mut enc, &config);
                
                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                        try!(enc.client_waiting_auth_request(stream, &mut self.buffers, auth_request, &self.auth_method, buffer))
                    },

                    Some(EncryptedState::WaitingSignature(auth_request)) => {
                        // The server is waiting for our authentication signature (also USERAUTH_REQUEST).
                        try!(enc.client_send_signature(stream, &mut self.buffers, auth_request, config, buffer, buffer2));
                    },
                    Some(EncryptedState::WaitingChannelOpen) => {
                        try!(enc.client_waiting_channel_open(stream, &mut self.buffers, config, buffer))
                    },
                    state => {
                        match std::mem::replace(&mut enc.rekey, None) {
                            Some(rekey) => {
                                try!(enc.client_write_rekey(stream, &mut self.buffers, rekey, config, buffer))
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

    fn try_rekey(&mut self, enc: &mut super::Encrypted, config:&Config) {
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
                debug!("msg, encrypted, {:?} {:?}", enc.state, enc.rekey);

                match std::mem::replace(&mut enc.rekey, None) {
                    Some(Kex::NewKeys(mut newkeys)) => {
                        debug!("newkeys {:?}", newkeys);
                        if !newkeys.sent {
                            enc.cipher.write_client_packet(self.buffers.write.seqn, &[msg::NEWKEYS],
                                                           &mut self.buffers.write.buffer);
                            try!(self.buffers.write_all(stream));
                            self.buffers.write.seqn += 1;
                            newkeys.sent = true;
                        }
                        if !newkeys.received {
                            enc.rekey = Some(Kex::NewKeys(newkeys))
                        } else {
                            enc.exchange = Some(newkeys.exchange);
                            enc.kex = newkeys.kex;
                            enc.key = newkeys.key;
                            enc.cipher = newkeys.cipher;
                            enc.mac = newkeys.mac;
                        }
                    },
                    x => enc.rekey = x
                }

                if enc.rekey.is_none() {

                    match enc.state {
                        Some(EncryptedState::ChannelOpened(_)) => {

                            let c = enc.channels.get(&channel).unwrap();
                            buffer.clear();
                            buffer.push(msg::CHANNEL_DATA);
                            buffer.push_u32_be(c.recipient_channel);
                            buffer.extend_ssh_string(msg);
                            debug!("{:?} {:?}", buffer.as_slice(), self.buffers.write.seqn);
                            enc.cipher.write_client_packet(self.buffers.write.seqn,
                                                           buffer.as_slice(),
                                                           &mut self.buffers.write.buffer);
                            debug!("buf = {:?}", self.buffers.write.buffer.as_slice());
                            self.buffers.write.seqn += 1;
                            try!(self.buffers.write_all(stream));
                            Ok(true)
                        },
                        _ => Ok(false)
                    }

                } else {
                    Ok(false)
                }
            },
            _ => Ok(false)
        }
    }
}
