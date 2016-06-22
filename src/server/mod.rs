use std::io::{Write, BufRead};
use time;
use std;

use super::*;
pub use super::auth::*;
use super::msg;
use super::cipher;

#[derive(Debug)]
pub struct Config<Auth> {
    pub server_id: String,
    pub methods: auth::Methods,
    pub auth_banner: Option<&'static str>,
    pub keys: Vec<key::Algorithm>,
    pub auth: Auth,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64
}

pub struct ServerSession {
    buffers: super::SSHBuffers,
    state: Option<ServerState>,
}


const SSH_EXTENDED_DATA_STDERR: u32 = 1;

impl<'a> ChannelBuf<'a> {
    pub fn stdout(&mut self, stdout:&[u8]) -> Result<(), Error> {
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_DATA);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.extend_ssh_string(stdout);

        self.cipher.write_server_packet(*self.sent_seqn,
                                        self.buffer.as_slice(),
                                        self.write_buffer);
                        
        *self.sent_seqn += 1;
        Ok(())
    }
    pub fn stderr(&mut self, stderr:&[u8]) -> Result<(), Error> {
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_EXTENDED_DATA);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.push_u32_be(SSH_EXTENDED_DATA_STDERR);
        self.buffer.extend_ssh_string(stderr);
        self.cipher.write_server_packet(*self.sent_seqn,
                                        self.buffer.as_slice(),
                                        self.write_buffer);
                        
        *self.sent_seqn += 1;
        Ok(())
    }
}


pub fn hexdump(x: &CryptoBuf) {
    let x = x.as_slice();
    let mut buf = Vec::new();
    let mut i = 0;
    while i < x.len() {
        if i % 16 == 0 {
            print!("{:04}: ", i)
        }
        print!("{:02x} ", x[i]);
        if x[i] >= 0x20 && x[i] <= 0x7e {
            buf.push(x[i]);
        } else {
            buf.push(b'.');
        }
        if i % 16 == 15 || i == x.len() - 1 {
            while i % 16 != 15 {
                print!("   ");
                i += 1
            }
            println!(" {}", std::str::from_utf8(&buf).unwrap());
            buf.clear();
        }
        i += 1
    }
}



mod read;
mod write;

impl ServerSession {
    pub fn new() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        ServerSession {
            buffers: super::SSHBuffers::new(),
            state: None,
        }
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, A: auth::Authenticate,S:SSHHandler>(
        &mut self,
        server:&mut S,
        config: &Config<A>,
        stream: &mut R,
        buffer: &mut CryptoBuf,
        buffer2: &mut CryptoBuf)
        -> Result<bool, Error> {

        let state = std::mem::replace(&mut self.state, None);
        // println!("state: {:?}", state);
        match state {
            None => {
                let client_id = try!(self.buffers.read_ssh_id(stream));
                if let Some(client_id) = client_id {
                    let mut exchange = Exchange::new();
                    exchange.client_id.extend(client_id);
                    debug!("client id, exchange = {:?}", exchange);
                    self.state = Some(ServerState::VersionOk(exchange));
                    Ok(true)
                } else {
                    Ok(false)
                }
            },

            Some(ServerState::Kex(Kex::KexInit(kexinit))) => self.server_read_cleartext_kexinit(stream, kexinit, &config.keys),

            Some(ServerState::Kex(Kex::KexDh(kexdh))) => self.server_read_cleartext_kexdh(stream, buffer, buffer2, kexdh),

            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => self.server_read_cleartext_newkeys(stream, newkeys),

            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?} {:?}", enc.state, enc.rekey);
                let (buf_is_some, rekeying_done) =
                    if let Some(buf) = try!(enc.cipher.read_client_packet(stream, &mut self.buffers.read)) {

                        if try!(enc.server_read_rekey(buf, &config.keys)) && enc.rekey.is_none() && buf[0] == msg::NEWKEYS {
                            // rekeying is finished.
                            (true, true)
                        } else {
                            debug!("calling read_encrypted");
                            enc.server_read_encrypted(&config.auth, server, buf, buffer, &mut self.buffers.write);
                            (true, false)
                        }
                    } else {
                        (false, false)
                    };

                if buf_is_some {
                    if self.buffers.read.bytes >= config.rekey_read_limit
                        || time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s {
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
                        }
                    if rekeying_done {
                        self.buffers.read.bytes = 0;
                        self.buffers.write.bytes = 0;
                        self.buffers.last_rekey_s = time::precise_time_s();
                    }
                    self.buffers.read.seqn += 1;
                    self.buffers.read.buffer.clear();
                    self.buffers.read.len = 0;
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(buf_is_some)
            }
            _ => {
                debug!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    // Returns whether the connexion is still alive.

    pub fn write<W: Write, A: auth::Authenticate, S:SSHHandler>(
        &mut self,
        config: &Config<A>,
        server: &mut S,
        stream: &mut W,
        buffer: &mut CryptoBuf,
        buffer2: &mut CryptoBuf)
        -> Result<bool, Error> {

        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }

        let state = std::mem::replace(&mut self.state, None);

        match state {
            Some(ServerState::VersionOk(mut exchange)) => {

                try!(self.buffers.send_ssh_id(stream, config.server_id.as_bytes()));
                exchange.server_id.extend(config.server_id.as_bytes());
                debug!("sent id, exchange = {:?}", exchange);

                self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                })));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => {

                self.state = Some(try!(self.buffers.cleartext_write_kex_init(&config.keys,
                                                                             true, // is_server
                                                                             kexinit,
                                                                             stream)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => {

                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                    &kexdhdone.exchange,
                                                                    buffer));
                self.server_cleartext_kex_ecdh_reply(&kexdhdone, &hash);
                self.server_cleartext_send_newkeys();
                try!(self.buffers.write_all(stream));

                self.state = Some(ServerState::Kex(Kex::NewKeys(kexdhdone.compute_keys(hash,
                                                                                       buffer,
                                                                                       buffer2))));
                Ok(true)
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("write: encrypted {:?} {:?}", enc.state, enc.rekey);
                if enc.rekey.is_none() && self.buffers.write.bytes >= config.rekey_write_limit
                    || time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s {
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
                let rekey_state = std::mem::replace(&mut enc.rekey, None);
                match rekey_state {
                    Some(rekey) => {
                        // If we are currently in the process of
                        // rekeying, send these packets first.  We can
                        // choose anyway.
                        try!(enc.server_write_rekey(stream, buffer, buffer2, &mut self.buffers, &config.keys, rekey))
                    },
                    None => {
                        let state = std::mem::replace(&mut enc.state, None);
                        match state {

                            Some(EncryptedState::ServiceRequest) => {
                                let auth_request = self.server_accept_service(config.auth_banner,
                                                                              config.methods,
                                                                              &mut enc,
                                                                              buffer);
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::RejectAuthRequest(auth_request)) => {

                                self.server_reject_auth_request(&mut enc, buffer, &auth_request);
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::WaitingSignature(mut auth_request)) => {
                                self.server_send_pk_ok(&mut enc, buffer, &mut auth_request);
                                enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::AuthRequestSuccess(_)) => {
                                buffer.clear();
                                buffer.push(msg::USERAUTH_SUCCESS);
                                enc.cipher.write_server_packet(self.buffers.write.seqn,
                                                               buffer.as_slice(),
                                                               &mut self.buffers.write.buffer);
                                self.buffers.write.seqn += 1;
                                enc.state = Some(EncryptedState::WaitingChannelOpen);
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::ChannelOpenConfirmation(channel)) => {

                                server.new_channel(&channel);
                                let sender_channel = channel.sender_channel;
                                self.server_confirm_channel_open(&mut enc, buffer, channel);
                                enc.state = Some(EncryptedState::ChannelOpened(sender_channel));
                                try!(self.buffers.write_all(stream));
                            }
                            Some(EncryptedState::ChannelOpened(recipient_channel)) => {

                                // self.flush_channels(&mut enc, buffer);
                                // try!(self.buffers.write_all(stream));
                                enc.state = Some(EncryptedState::ChannelOpened(recipient_channel))
                            }
                            state => enc.state = state,
                        }
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
            session => {
                // println!("write: unhandled {:?}", session);
                self.state = session;
                Ok(true)
            }
        }
    }
}
