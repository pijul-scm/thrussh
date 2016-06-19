use std::io::{Write, BufRead};
use std::marker::PhantomData;
use time;
use std;

use super::*;
use super::read;
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

pub struct ServerSession<T, S> {
    buffers: super::SSHBuffers,
    state: Option<ServerState<S>>,
    marker: PhantomData<T>,
}


pub struct ServerBuf<'a> {
    buffer:&'a mut CryptoBuf,
    recipient_channel: u32,
    sent_seqn: &'a mut usize,
    write_buffer: &'a mut CryptoBuf,
    cipher: &'a mut cipher::Cipher
}

const SSH_EXTENDED_DATA_STDERR: u32 = 1;

impl<'a> ServerBuf<'a> {
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


pub trait Serve<S> {
    fn init(&S, channel: &ChannelParameters) -> Self;
    fn data(&mut self, _: &[u8], _: ServerBuf) -> Result<(), Error> {
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

impl<T, S: Serve<T>> ServerSession<T, S> {
    pub fn new() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        ServerSession {
            buffers: super::SSHBuffers::new(),
            state: None,
            marker: PhantomData,
        }
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, A: auth::Authenticate>(&mut self,
                                                   config: &Config<A>,
                                                   stream: &mut R,
                                                   buffer: &mut CryptoBuf)
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

            Some(ServerState::Kex(Kex::KexInit(kexinit))) => self.read_cleartext_kexinit(stream, kexinit, &config.keys),

            Some(ServerState::Kex(Kex::KexDh(mut kexdh))) => {

                if self.buffers.read_len == 0 {
                    try!(self.buffers.set_clear_len(stream));
                }

                if try!(read(stream, &mut self.buffers.read_buffer, self.buffers.read_len, &mut self.buffers.read_bytes)) {

                    let kex = {
                        let payload = self.buffers.get_current_payload();
                        debug!("payload = {:?}", payload);
                        assert!(payload[0] == msg::KEX_ECDH_INIT);
                        kexdh.exchange.client_ephemeral.extend(&payload[5..]);
                        try!(kexdh.kex.server_dh(&mut kexdh.exchange, payload))
                    };
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;
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

                } else {
                    // not enough bytes.
                    self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                    Ok(false)
                }
            }
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => {
                // We have sent a NEWKEYS packet, and are waiting to receive one. Is it this one?
                if self.buffers.read_len == 0 {
                    try!(self.buffers.set_clear_len(stream));
                }
                if try!(read(stream, &mut self.buffers.read_buffer, self.buffers.read_len, &mut self.buffers.read_bytes)) {

                    let payload_is_newkeys = self.buffers.get_current_payload()[0] == msg::NEWKEYS;
                    if payload_is_newkeys {
                        // Ok, NEWKEYS received, now encrypted.
                        self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                        self.buffers.recv_seqn += 1;
                        self.buffers.read_buffer.clear();
                        self.buffers.read_len = 0;
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
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?}", enc.state);
                let buf_is_some =
                    if let Some(buf) = try!(enc.cipher.read_client_packet(&mut self.buffers.read_bytes,
                                                                          self.buffers.recv_seqn,
                                                                          stream,
                                                                          &mut self.buffers.read_len,
                                                                          &mut self.buffers.read_buffer)) {

                        if try!(enc.server_rekey(buf, &config.keys)) && enc.rekey.is_none() && buf[0] == msg::NEWKEYS {
                            // rekeying is finished.
                            self.buffers.read_bytes = 0;
                            self.buffers.written_bytes = 0;
                            self.buffers.last_rekey_s = time::precise_time_s();
                        } else {
                            debug!("calling read_encrypted");
                            let enc_state = read::read_encrypted(&config.auth, &mut enc, buf, buffer,
                                                                 &mut self.buffers.write_buffer,
                                                                 &mut self.buffers.sent_seqn
                            );
                            enc.state = Some(enc_state);


                            if self.buffers.read_bytes >= config.rekey_read_limit
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
                        }
                        debug!("buf = {:?}", buf);
                        true
                    } else {
                        debug!("buf_is_some: {:?}, target {:?}", false, self.buffers.read_len);
                        false
                    };
                if buf_is_some {
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;
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

    pub fn write<W: Write, A: auth::Authenticate>(&mut self,
                                            config: &Config<A>,
                                            server: &T,
                                            stream: &mut W,
                                            buffer: &mut CryptoBuf,
                                            buffer2: &mut CryptoBuf)
                                            -> Result<bool, Error> {

        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        self.buffers.write_buffer.clear();
        self.buffers.write_position = 0;

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
                self.cleartext_kex_ecdh_reply(&kexdhdone, &hash);
                self.cleartext_send_newkeys();
                try!(self.buffers.write_all(stream));

                self.state = Some(ServerState::Kex(Kex::NewKeys(kexdhdone.compute_keys(hash,
                                                                                       buffer,
                                                                                       buffer2))));
                Ok(true)
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("write: encrypted {:?}", enc.state);
                if enc.rekey.is_none() && self.buffers.written_bytes >= config.rekey_write_limit
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
                    debug!("not yet rekeying, {:?}", self.buffers.written_bytes)
                }
                let rekey_state = std::mem::replace(&mut enc.rekey, None);
                match rekey_state {
                    Some(Kex::KexInit(mut kexinit)) => {
                        if !kexinit.sent {
                            debug!("sending kexinit");
                            buffer.clear();
                            super::negociation::write_kex(&config.keys, buffer);
                            kexinit.exchange.server_kex_init.extend(buffer.as_slice());

                            enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
                            self.buffers.sent_seqn += 1;
                            try!(self.buffers.write_all(stream));
                            kexinit.sent = true;
                        }
                        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                            debug!("rekey ok");
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
                            debug!("still kexinit");
                            enc.rekey = Some(Kex::KexInit(kexinit))
                        }
                    },
                    Some(Kex::KexDh(kexinit)) => {
                        // Nothing to do here.
                        enc.rekey = Some(Kex::KexDh(kexinit))
                    },
                    Some(Kex::KexDhDone(kexdhdone)) => {

                        debug!("kexdhdone: {:?}", kexdhdone);

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
                        enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
                        self.buffers.sent_seqn += 1;

                        
                        buffer.clear();
                        buffer.push(msg::NEWKEYS);
                        enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
                        self.buffers.sent_seqn += 1;

                        try!(self.buffers.write_all(stream));
                        debug!("new keys");
                        let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                        enc.rekey = Some(Kex::NewKeys(new_keys));

                    },
                    Some(Kex::NewKeys(n)) => {
                        enc.rekey = Some(Kex::NewKeys(n));
                    },
                    None => {
                        let state = std::mem::replace(&mut enc.state, None);
                        match state {

                            Some(EncryptedState::ServiceRequest) => {
                                let auth_request = self.accept_service(config.auth_banner,
                                                                       config.methods,
                                                                       &mut enc,
                                                                       buffer);
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::RejectAuthRequest(auth_request)) => {

                                self.reject_auth_request(&mut enc, buffer, &auth_request);
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::WaitingSignature(mut auth_request)) => {
                                self.send_pk_ok(&mut enc, buffer, &mut auth_request);
                                enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::AuthRequestSuccess(_)) => {
                                buffer.clear();
                                buffer.push(msg::USERAUTH_SUCCESS);
                                enc.cipher.write_server_packet(self.buffers.sent_seqn,
                                                               buffer.as_slice(),
                                                               &mut self.buffers.write_buffer);
                                self.buffers.sent_seqn += 1;
                                enc.state = Some(EncryptedState::WaitingChannelOpen);
                                try!(self.buffers.write_all(stream));
                            }

                            Some(EncryptedState::ChannelOpenConfirmation(channel)) => {

                                let server = S::init(server, &channel);
                                let sender_channel = channel.sender_channel;
                                self.confirm_channel_open(&mut enc, buffer, channel, server);
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
