use byteorder::{ByteOrder, BigEndian};
use super::{CryptoBuf, Exchange, Error, ServerState, Kex, KexInit, EncryptedState, ChannelBuf};
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
    pub fn read<R: BufRead, C:super::Client + super::ValidateKey>(
        &mut self,
        config: &Config,
        client: &mut C,
        stream: &mut R,
        buffer: &mut CryptoBuf,
        buffer2: &mut CryptoBuf)
        -> Result<bool, Error> {

        debug!("read");
        let state = std::mem::replace(&mut self.state, None);
        println!("state = {:?}", state);
        match state {
            None => {
                // We have neither sent nor received the version id.
                // Do both (read and send).
                let mut exchange = Exchange::new();
                // Send our ID, and move on to the next state.
                self.buffers.write.send_ssh_id(config.client_id.as_bytes());
                exchange.client_id.extend(config.client_id.as_bytes());
                //
                self.client_read_server_id(stream, exchange, &config.keys)
            },
            Some(ServerState::VersionOk(mut exchange)) => {
                // We've sent our id, and are waiting for the server's id.
                self.client_read_server_id(stream, exchange, &config.keys)
            },
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => self.client_kexinit(stream, kexinit, &config.keys),
            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                debug!("reading kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => self.client_kexdhdone(client, stream, kexdhdone, buffer, buffer2),
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => self.client_newkeys(stream, buffer, newkeys),
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted state");
                self.try_rekey(&mut enc, &config);
                let state = std::mem::replace(&mut enc.state, None);

                let read_complete;

                match state {
                    Some(EncryptedState::ServiceRequest) => {
                        read_complete = try!(enc.client_service_request(stream, &self.auth_method, &mut self.buffers, buffer));
                    },
                    Some(EncryptedState::AuthRequestSuccess(auth_request)) => {
                        debug!("auth_request_success");
                        read_complete = try!(enc.client_auth_request_success(stream, config, auth_request, &self.auth_method, &mut self.buffers, buffer, buffer2));
                    },
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                        if let Some(buf) = try!(enc.cipher.read_server_packet(stream, &mut self.buffers.read)) {
                            read_complete = true;
                            if buf[0] == msg::USERAUTH_BANNER {
                                let mut r = buf.reader(1);
                                client.auth_banner(try!(std::str::from_utf8(try!(r.read_string()))))
                            }
                            println!("buf = {:?}", buf);
                        } else {
                            read_complete = false;
                        }
                        if read_complete {
                            self.buffers.read.clear_incr();
                        }
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
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
                                    is_newkeys = try!(enc.client_rekey(client, buf, rekey, &config.keys, buffer, buffer2))
                                }
                                None if buf[0] == msg::KEXINIT => {
                                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                                        // The server is initiating a rekeying.
                                        let mut kexinit = KexInit::rekey(
                                            exchange,
                                            try!(super::negociation::read_kex(buf, &config.keys)),
                                            &enc.session_id
                                        );
                                        kexinit.exchange.server_kex_init.extend(buf);
                                        enc.rekey = Some(try!(kexinit.kexinit()));
                                    }
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
                                                channel: channel,
                                                write_buffer: &mut self.buffers.write,
                                                cipher: &mut enc.cipher,
                                                wants_reply: false
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
                           buffer: &mut CryptoBuf)
                           -> Result<bool, Error> {
        debug!("write, buffer: {:?}", self.buffers.write);
        // Finish pending writes, if any.
        if ! try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }

        let state = std::mem::replace(&mut self.state, None);
        println!("state = {:?}", state);
        match state {
            None => {
                // Maybe the first time we get to talk with the server
                // is to write to it (i.e. the socket is only
                // writable). Send our id.
                self.buffers.write.send_ssh_id(config.client_id.as_bytes());
                try!(self.buffers.write_all(stream));
                let mut exchange = Exchange::new();
                exchange.client_id.extend(config.client_id.as_bytes());
                debug!("sent!: {:?}", exchange);
                self.state = Some(ServerState::VersionOk(exchange));
                Ok(true)
            },
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted");
                self.try_rekey(&mut enc, &config);
                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                        // This cannot be moved to read, because we
                        // might need to change the auth method (using
                        // user input) between read and write.
                        enc.client_waiting_auth_request(&mut self.buffers.write, auth_request, &self.auth_method, buffer);
                        try!(self.buffers.write_all(stream));
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
            },
            state => {
                self.state = state;
                Ok(true)
            }
        }
        
    }

    fn try_rekey(&mut self, enc: &mut super::Encrypted, config:&Config) {
        if enc.rekey.is_none() &&
            (self.buffers.write.bytes >= config.rekey_write_limit
             || self.buffers.read.bytes >= config.rekey_read_limit
             || time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s) {

                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                    let mut kexinit = KexInit {
                        exchange: exchange,
                        algo: None,
                        sent: false,
                        session_id: Some(enc.session_id.clone()),
                    };
                    kexinit.exchange.client_kex_init.clear();
                    kexinit.exchange.server_kex_init.clear();
                    kexinit.exchange.client_ephemeral.clear();
                    kexinit.exchange.server_ephemeral.clear();
                    enc.rekey = Some(Kex::KexInit(kexinit))
                }
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
                    Some(EncryptedState::ChannelOpened(Some(x))) => Some(x),
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
                    Some(Kex::KexDh(kexdh)) => {
                        enc.client_write_kexdh(buffer, &mut self.buffers.write, kexdh);
                        try!(self.buffers.write_all(stream));
                    }
                    x => enc.rekey = x
                }

                if enc.rekey.is_none() {

                    match enc.state {
                        Some(EncryptedState::ChannelOpened(_)) => {

                            if let Some(c) = enc.channels.get(&channel) {
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
                            } else {
                                Ok(false)
                            }
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
