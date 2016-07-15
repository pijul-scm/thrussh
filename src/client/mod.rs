// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use {Error, Limits, Client, ChannelType, ChannelParameters};
use super::key;
use super::msg;
use super::auth;
use super::cipher::CipherT;
use super::negociation;
use std::io::{Write, BufRead};
use ReturnCode;
use std;
use cryptobuf::CryptoBuf;
use negociation::Select;
use state::*;
use sshbuffer::*;
use std::collections::HashMap;
use cipher;
use kex;

use rand;
use rand::{thread_rng, Rng};

mod encrypted;

const UNIT:&'static () = &();

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub limits: Limits,
    pub window_size: u32,
    pub maxpacket: u32,
    pub preferred: negociation::Preferred,
}

impl std::default::Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME")
                               env!("CARGO_PKG_VERSION")),
            // Following the recommendations of
            // https://tools.ietf.org/html/rfc4253#section-9
            limits: Limits {
                rekey_write_limit: 1 << 30, // 1 Gb
                rekey_read_limit: 1 << 30, // 1 Gb
                rekey_time_limit_s: 3600.0
            },
            window_size: 200000,
            maxpacket: 200000,
            preferred: negociation::PREFERRED,
        }
    }
}

#[derive(Debug)]
pub struct Session<'a> {
    buffers: SSHBuffers,
    state: Option<ServerState<&'static ()>>,
    auth_method: Option<auth::Method<'a, key::Algorithm>>,
}

impl<'a> Default for Session<'a> {
    fn default() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        Session {
            buffers: SSHBuffers::new(),
            state: None,
            auth_method: None,
        }
    }
}

impl KexInit {
    pub fn client_parse<C:CipherT>(mut self, config:&Config, buffer:&mut CryptoBuf, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<KexDhDone<&'static ()>, Error> {

        let algo = if self.algo.is_none() {
            // read algorithms from packet.
            self.exchange.server_kex_init.extend_from_slice(buf);
            try!(super::negociation::Client::read_kex(buf, &config.preferred))
        } else {
            return Err(Error::Kex)
        };
        if !self.sent {
            self.client_write(config, buffer, cipher, write_buffer)
        }
        buffer.clear();
        let kex = try!(kex::Algorithm::client_dh(algo.kex, &mut self.exchange, buffer));
        cipher.write(buffer.as_slice(), write_buffer);
        Ok(KexDhDone {
            exchange: self.exchange,
            names: algo,
            kex: kex,
            key: UNIT,
            session_id: self.session_id,
        })
    }

    pub fn client_write<'k, C:CipherT>(&mut self, config:&'k Config, buffer:&mut CryptoBuf, cipher:&mut C, write_buffer:&mut SSHBuffer) {
        buffer.clear();
        negociation::write_kex(&config.preferred, buffer);
        self.exchange.client_kex_init.extend_from_slice(buffer.as_slice());
        self.sent = true;
        cipher.write(buffer.as_slice(), write_buffer)
    }
}


impl KexDhDone<&'static ()> {
    pub fn client_parse<C:CipherT, Cl:Client>(mut self, buffer:&mut CryptoBuf, buffer2: &mut CryptoBuf, client:&mut Cl, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<Kex<&'static ()>, Error> {

        if self.names.ignore_guessed {
            self.names.ignore_guessed = false;
            Ok(Kex::KexDhDone(self))
        } else {
            debug!("kexdhdone");
            // We've sent ECDH_INIT, waiting for ECDH_REPLY
            if buf[0] == msg::KEX_ECDH_REPLY {
                let hash = try!(self.client_compute_exchange_hash(client, buf, buffer));
                let mut newkeys = try!(self.compute_keys(hash, buffer, buffer2, false));
                cipher.write(&[msg::NEWKEYS], write_buffer);
                newkeys.sent = true;
                Ok(Kex::NewKeys(newkeys))
            } else {
                return Err(Error::Inconsistent)
            }
        }
    }
}


impl<'a> Session<'a> {

    pub fn new(config:&Config) -> Self {
        let mut session = Session::default();
        session.buffers.write.send_ssh_id(config.client_id.as_bytes());
        session
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, C: super::Client> (&mut self,
                                               config: &Config,
                                               client: &mut C,
                                               stream: &mut R,
                                               buffer: &mut CryptoBuf,
                                               buffer2: &mut CryptoBuf)
                                               -> Result<super::ReturnCode, Error> {
        
        debug!("read");
        let state = std::mem::replace(&mut self.state, None);
        debug!("state = {:?}", state);
        match state {
            None => {
                let mut exchange;
                {
                    let server_id = try!(self.buffers.read.read_ssh_id(stream));
                    if let Some(server_id) = server_id {
                        exchange = Exchange::new();
                        exchange.server_id.extend_from_slice(server_id);
                        debug!("server id, exchange = {:?}", exchange);
                    } else {
                        return Ok(ReturnCode::WrongPacket);
                    }
                }
                // Preparing the response
                exchange.client_id.extend(config.client_id.as_bytes());
                let mut kexinit = KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                };
                let mut cipher = cipher::Clear;
                kexinit.client_write(config, buffer, &mut cipher, &mut self.buffers.write);
                self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                Ok(ReturnCode::Ok)
            },
            Some(ServerState::Kex(kex)) => {

                let mut cipher = cipher::Clear;
                if let Some(buf) = try!(cipher.read(stream, &mut self.buffers.read)) {
                    debug!("buf = {:?}", buf);
                    if buf[0] == msg::DISCONNECT {
                        // transport
                        return Ok(ReturnCode::Disconnect)
                    }
                    if buf[0] <= 4 {
                        self.state = Some(ServerState::Kex(kex));
                        return Ok(ReturnCode::Ok)
                    }
                    match kex {
                        Kex::KexInit(kexinit) => {
                            let kexdhdone = try!(kexinit.client_parse(config, buffer, &mut cipher, buf, &mut self.buffers.write));
                            self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)))
                        },
                        Kex::KexDhDone(kexdhdone) => {
                            self.state = Some(ServerState::Kex(
                                try!(kexdhdone.client_parse(buffer, buffer2, client, &mut cipher, buf, &mut self.buffers.write))
                            ))
                        },
                        Kex::NewKeys(newkeys) => {
                            if buf[0] != msg::NEWKEYS {
                                return Err(Error::NewKeys)
                            }
                            let encrypted = newkeys.encrypted(EncryptedState::WaitingServiceRequest);
                            
                            // Ok, NEWKEYS received, now encrypted.
                            // We can't use flush here, because self.buffers is borrowed.
                            let p = [msg::SERVICE_REQUEST,
                                     0,0,0,12, b's',b's',b'h',b'-',b'u',b's',b'e',b'r',b'a',b'u',b't',b'h'];
                            encrypted.cipher.write(&p, &mut self.buffers.write);

                            self.state = Some(ServerState::Encrypted(encrypted));
                        },
                        kex => self.state = Some(ServerState::Kex(kex))
                    }
                    Ok(ReturnCode::Ok)
                } else {
                    self.state = Some(ServerState::Kex(kex));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Encrypted(mut enc)) => {
                if let Some(buf) = try!(enc.cipher.read(stream, &mut self.buffers.read)) {
                    debug!("read buf {:?}", buf);
                    if buf[0] == msg::DISCONNECT {
                        return Ok(ReturnCode::Disconnect)
                    }
                    if buf[0] <= 4 {
                        // transport
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    if buf[0] > 20 && buf[0] < 50 {
                        if let Some(kex) = std::mem::replace(&mut enc.rekey, None) {
                            match kex {
                                Kex::KexInit(kexinit) => {
                                    let kexdhdone = try!(kexinit.client_parse(config, buffer, &mut enc.cipher, buf, &mut self.buffers.write));
                                    self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)))
                                },
                                Kex::KexDhDone(kexdhdone) => {
                                    self.state = Some(ServerState::Kex(
                                        try!(kexdhdone.client_parse(buffer, buffer2, client, &mut enc.cipher, buf, &mut self.buffers.write))
                                    ))
                                },
                                Kex::NewKeys(newkeys) => {
                                    if buf[0] == msg::NEWKEYS {
                                        enc.exchange = Some(newkeys.exchange);
                                        enc.kex = newkeys.kex;
                                        enc.key = newkeys.key;
                                        enc.cipher = newkeys.cipher;
                                        enc.mac = newkeys.names.mac;
                                    } else {
                                        return Err(Error::Inconsistent)
                                    }
                                }
                                kex => enc.rekey = Some(kex)
                            }
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    if buf[0] == msg::KEXINIT {
                        if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                            let kexinit = KexInit::received_rekey(
                                exchange,
                                try!(negociation::Client::read_kex(buf, &config.preferred)),
                                &enc.session_id
                            );
                            enc.rekey = Some(
                                Kex::KexDhDone(try!(kexinit.client_parse(config, buffer, &mut enc.cipher, buf, &mut self.buffers.write)))
                            );
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    }
                    debug!("calling read_encrypted");
                    try!(enc.client_read_encrypted(config,
                                                   client,
                                                   &self.auth_method,
                                                   buf,
                                                   buffer,
                                                   buffer2));

                } else {
                    self.state = Some(ServerState::Encrypted(enc));
                    return Ok(ReturnCode::NotEnoughBytes)
                }
                // If there are pending packets (and we've not started to rekey), flush them.
                if enc.flush(&config.limits, &mut self.buffers) {

                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                        let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                        kexinit.client_write(&config,
                                             buffer,
                                             &mut enc.cipher,
                                             &mut self.buffers.write);
                        enc.rekey = Some(Kex::KexInit(kexinit))
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(ReturnCode::Ok)

            }
            /*
                    Some(EncryptedState::Authenticated) => {
                        debug!("read state {:?}", state);
                        let mut is_newkeys = false;
                        if let Some(buf) = try!(enc.cipher.read(stream,&mut self.buffers.read)) {

                            transport!(buf);

                            debug!("msg: {:?} {:?}", buf, enc.rekey);
                            match std::mem::replace(&mut enc.rekey, None) {
                                Some(rekey) => {
                                    is_newkeys = try!(enc.client_rekey(client, buf, rekey, &config, buffer, buffer2))
                                }
                                None if buf[0] == msg::KEXINIT => {
                                    if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                                        // The server is initiating a rekeying.
                                        let mut kexinit = KexInit::rekey(
                                            exchange,
                                            try!(super::negociation::Client::read_kex(buf, &config.preferred)),
                                            &enc.session_id
                                        );
                                        kexinit.exchange.server_kex_init.extend_from_slice(buf);
                                        enc.rekey = Some(try!(kexinit.kexinit(&[])));
                                    }
                                }
                                None if buf[0] == msg::CHANNEL_OPEN_CONFIRMATION => {
                                    try!(enc.client_channel_open_confirmation(client, buf))
                                }
                                None if buf[0] == msg::CHANNEL_DATA => {

                                    let mut r = buf.reader(1);
                                    let channel_num = try!(r.read_u32());
                                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {

                                        let data = try!(r.read_string());
                                        channel.sender_window_size -= data.len() as u32;
                                        if channel.sender_window_size < config.window_size / 2 {
                                            super::adjust_window_size(&mut self.buffers.write,
                                                                      &mut enc.cipher,
                                                                      config.window_size,
                                                                      buffer,
                                                                      channel)
                                        }
                                        buffer.clear();
                                        let server_buf = ChannelBuf {
                                            buffer: buffer,
                                            channel: channel,
                                            write_buffer: &mut self.buffers.write,
                                            cipher: &mut enc.cipher,
                                            wants_reply: false,
                                        };
                                        try!(client.data(None, &data, server_buf))
                                    }
                                }
                                None if buf[0] == msg::CHANNEL_EXTENDED_DATA => {
                                    let mut r = buf.reader(1);
                                    let channel_num = try!(r.read_u32());
                                    let extended_code = try!(r.read_u32());
                                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                                        let data = try!(r.read_string());
                                        buffer.clear();
                                        let server_buf = ChannelBuf {
                                            buffer: buffer,
                                            channel: channel,
                                            write_buffer: &mut self.buffers.write,
                                            cipher: &mut enc.cipher,
                                            wants_reply: false,
                                        };
                                        try!(client.data(Some(extended_code), &data, server_buf))
                                    }
                                }
                                None if buf[0] == msg::CHANNEL_WINDOW_ADJUST => {
                                    let mut r = buf.reader(1);
                                    let channel_num = try!(r.read_u32());
                                    let amount = try!(r.read_u32());
                                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                                        channel.recipient_window_size += amount
                                    }
                                }
                                None => {
                                    info!("Unhandled packet: {:?}", buf);
                                }
                            }
                            read_complete = true;
                        } else {
                            read_complete = false
                        };
                        if read_complete && is_newkeys {
                            self.buffers.read.bytes = 0;
                            self.buffers.write.bytes = 0;
                        }
                        enc.state = state;
                    },
                    None => {
                        read_complete = false
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                if read_complete {
                    Ok(ReturnCode::Ok)
                } else {
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
             */
        }
    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self,
                           stream: &mut W)
                           -> Result<bool, Error> {
        debug!("write, buffer: {:?}", self.buffers.write);
        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        Ok(true)
    }

    pub fn authenticate(&mut self, config:&Config, method: auth::Method<'a, key::Algorithm>) -> Result<(), Error> {
        debug!("authenticate: {:?} {:?}", self.state, method);
        let result = match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingAuthRequest(_)) => {
                        enc.write_auth_request(&method);
                        enc.flush(&config.limits, &mut self.buffers);
                        Ok(())
                    },
                    _ => Err(Error::Inconsistent)
                }
            },
            _ => { Err (Error::Inconsistent) }
        };
        self.auth_method = Some(method);
        result
    }
    pub fn is_authenticated(&self) -> bool {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::Authenticated) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn needs_auth_method(&self) -> Option<auth::M> {

        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingAuthRequest(ref auth_request)) => {

                        debug!("needs_auth_method: {:?}", auth_request);
                        Some(auth_request.methods)

                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
    pub fn channels(&self) -> Option<&HashMap<u32, super::ChannelParameters>> {
        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                Some(&enc.channels)
            },
            _ => None
        }
    }

    pub fn channel_open(&mut self, channel_type:super::ChannelType, config:&Config) -> Option<u32> {
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::Authenticated) => {
                        debug!("sending open request");

                        let mut sender_channel = 0;
                        while enc.channels.contains_key(&sender_channel) || sender_channel == 0 {
                            sender_channel = rand::thread_rng().gen()
                        }
                        push_packet!(enc.write, {
                            enc.write.push(msg::CHANNEL_OPEN);

                            match channel_type {
                                ChannelType::Session => {
                                    enc.write.extend_ssh_string(b"session");
                                    enc.write.push_u32_be(sender_channel); // sender channel id.
                                    enc.write.push_u32_be(config.window_size); // window.
                                    enc.write.push_u32_be(config.maxpacket); // max packet size.
                                },
                                ChannelType::X11 { originator_address, originator_port } => {
                                    enc.write.extend_ssh_string(b"x11");
                                    enc.write.push_u32_be(sender_channel); // sender channel id.
                                    enc.write.push_u32_be(config.window_size); // window.
                                    enc.write.push_u32_be(config.maxpacket); // max packet size.
                                    //
                                    enc.write.extend_ssh_string(originator_address.as_bytes());
                                    enc.write.push_u32_be(originator_port); // sender channel id.
                                },
                                ChannelType::ForwardedTcpip { connected_address, connected_port, originator_address, originator_port } => {
                                    enc.write.extend_ssh_string(b"forwarded-tcpip");
                                    enc.write.push_u32_be(sender_channel); // sender channel id.
                                    enc.write.push_u32_be(config.window_size); // window.
                                    enc.write.push_u32_be(config.maxpacket); // max packet size.
                                    //
                                    enc.write.extend_ssh_string(connected_address.as_bytes());
                                    enc.write.push_u32_be(connected_port); // sender channel id.
                                    enc.write.extend_ssh_string(originator_address.as_bytes());
                                    enc.write.push_u32_be(originator_port); // sender channel id.
                                },
                                ChannelType::DirectTcpip { host_to_connect, port_to_connect, originator_address, originator_port } => {
                                    enc.write.extend_ssh_string(b"direct-tcpip");
                                    enc.write.push_u32_be(sender_channel); // sender channel id.
                                    enc.write.push_u32_be(config.window_size); // window.
                                    enc.write.push_u32_be(config.maxpacket); // max packet size.
                                    //
                                    enc.write.extend_ssh_string(host_to_connect.as_bytes());
                                    enc.write.push_u32_be(port_to_connect); // sender channel id.
                                    enc.write.extend_ssh_string(originator_address.as_bytes());
                                    enc.write.push_u32_be(originator_port); // sender channel id.
                                }
                            }
                        });
                        // Send
                        enc.flush(&config.limits, &mut self.buffers);

                        let parameters = ChannelParameters {
                            recipient_channel: 0,
                            sender_channel: sender_channel,
                            sender_window_size: config.window_size,
                            recipient_window_size: 0,
                            sender_maximum_packet_size: config.maxpacket,
                            recipient_maximum_packet_size: 0,
                            confirmed: false
                        };
                        enc.channels.insert(sender_channel, parameters);
                        Some(sender_channel)
                    }
                    _ => None
                }
            },
            _ => None
        }
    }

    /*
    pub fn channel_request<W: Write, R:channel_request::Req>(&mut self,
                                                             stream: &mut W,
                                                             buffer: &mut CryptoBuf,
                                                             channel: u32,
                                                             req: R)
                                                             -> Result<(), Error> {
        
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::Authenticated) => {
                        // No rekeying here, since we need answers
                        // from the server before we can send this
                        // request.
                        if let Some(c) = enc.channels.get_mut(&channel) {
                            req.req(c, buffer);
                            enc.cipher.write(buffer.as_slice(), &mut self.buffers.write);
                        }
                        Ok(())
                    },
                    _ => Err(Error::WrongState)
                }
            },
            _ => Err(Error::WrongState)
        }
    }

    pub fn msg<W: Write>(&mut self,
                         stream: &mut W,
                         buffer: &mut CryptoBuf,
                         msg: &[u8],
                         channel: u32)
                         -> Result<Option<usize>, Error> {

        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                debug!("msg, encrypted, {:?} {:?}", enc.state, enc.rekey);


                if enc.rekey.is_none() {

                    match enc.state {
                        Some(EncryptedState::Authenticated) => {
                            if let Some(c) = enc.channels.get_mut(&channel) {

                                let written = {
                                    let mut channel_buf = ChannelBuf {
                                        write_buffer: &mut self.buffers.write,
                                        cipher: &mut enc.cipher,
                                        wants_reply: false,
                                    };
                                    channel_buf.output(None, msg)
                                };
                                try!(self.buffers.write_all(stream));
                                Ok(Some(written))
                            } else {
                                Ok(None)
                            }
                        }
                        _ => Ok(None),
                    }

                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
     */
}
