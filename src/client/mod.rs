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
use super::{Error, ChannelBuf, ChannelParameters, ChannelType};
use super::encoding::*;
use super::key;
use super::msg;
use super::auth;
use super::cipher::CipherT;
use super::negociation;
use byteorder::{BigEndian, ByteOrder};
use std::io::{Write, BufRead};
use time;
use ReturnCode;
use std;
use cryptobuf::CryptoBuf;
use negociation::Select;
use state::*;
use sshbuffer::*;
use std::collections::HashMap;
use channel_request;
use rand;
use rand::Rng;
use cipher;
use kex;
//mod read;
//mod write;


const UNIT:&'static () = &();

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
    pub window_size: u32,
    pub maxpacket: u32,
    pub preferred: negociation::Preferred,
}

impl Config {
    fn needs_rekeying(&self, buffers:&SSHBuffers) -> bool {
        buffers.read.bytes >= self.rekey_read_limit ||
            buffers.write.bytes >= self.rekey_write_limit ||
            time::precise_time_s() >= buffers.last_rekey_s + self.rekey_time_limit_s
    }
}

impl std::default::Default for Config {
    fn default() -> Config {
        Config {
            client_id: format!("SSH-2.0-{}_{}",
                               "Thrussh", // env!("CARGO_PKG_NAME")
                               env!("CARGO_PKG_VERSION")),
            // Following the recommendations of
            // https://tools.ietf.org/html/rfc4253#section-9
            rekey_write_limit: 1 << 30, // 1 Gb
            rekey_read_limit: 1 << 30, // 1 Gb
            rekey_time_limit_s: 3600.0,
            window_size: 200000,
            maxpacket: 200000,
            preferred: negociation::PREFERRED,
        }
    }
}

pub struct Session<'a> {
    buffers: SSHBuffers,
    state: Option<ServerState<&'static ()>>,
    write: CryptoBuf,
    write_cursor: usize,
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
            write: CryptoBuf::new(),
            write_cursor: 0,
            auth_method: None,
        }
    }
}

impl KexInit {
    pub fn client_parse<'k, C:CipherT>(mut self, config:&'k Config, buffer:&mut CryptoBuf, cipher:&mut C, buf:&[u8], write_buffer:&mut SSHBuffer) -> Result<KexDh<&'k ()>, Error> {

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
        Ok(KexDh {
            exchange: self.exchange,
            key: UNIT,
            names: algo,
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

                            let mut cipher = cipher::Clear;

                            let mut kexdh = try!(kexinit.client_parse(config, buffer, &mut cipher, buf, &mut self.buffers.write));

                            buffer.clear();
                            let kex = try!(kex::Algorithm::client_dh(kexdh.names.kex, &mut kexdh.exchange, buffer));
                            cipher.write(buffer.as_slice(), &mut self.buffers.write);

                            self.state = Some(ServerState::Kex(Kex::KexDhDone(KexDhDone {
                                exchange: kexdh.exchange,
                                names: kexdh.names,
                                kex: kex,
                                key: UNIT,
                                session_id: kexdh.session_id,
                            })));
                        },
                        Kex::KexDhDone(mut kexdhdone) => {

                            if kexdhdone.names.ignore_guessed {
                                kexdhdone.names.ignore_guessed = false;
                                self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                            } else {
                                debug!("kexdhdone");
                                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                                if buf[0] == msg::KEX_ECDH_REPLY {

                                    let mut cipher = cipher::Clear;

                                    let hash = try!(kexdhdone.client_compute_exchange_hash(client, buf, buffer));
                                    let mut newkeys = try!(kexdhdone.compute_keys(hash, buffer, buffer2, false));

                                    cipher.write(&[msg::NEWKEYS], &mut self.buffers.write);
                                    newkeys.sent = true;
                                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                                } else {
                                    return Err(Error::Inconsistent)
                                }
                            }
                        },
                        Kex::NewKeys(newkeys) => {
                            if buf[0] != msg::NEWKEYS {
                                return Err(Error::NewKeys)
                            }
                            // Ok, NEWKEYS received, now encrypted.
                            self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
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
                            unimplemented!()
                        }
                        self.state = Some(ServerState::Encrypted(enc));
                        return Ok(ReturnCode::Ok)
                    } else {
                        return Err(Error::Inconsistent)
                    }
                    if buf[0] == msg::KEXINIT {
                        unimplemented!()
                    }
                    /*
                    debug!("calling read_encrypted");
                    try!(enc.server_read_encrypted(config,
                                                   server,
                                                   buf,
                                                   buffer,
                                                   &mut self.write));
                     */
                    unimplemented!()

                } else {
                    self.state = Some(ServerState::Encrypted(enc));
                    return Ok(ReturnCode::NotEnoughBytes)
                }
                // If there are pending packets (and we've not started to rekey), flush them.
                if enc.rekey.is_none() {
                    {
                        let packets = self.write.as_slice();
                        while self.write_cursor < self.write.len() {
                            if config.needs_rekeying(&self.buffers) {
                                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {

                                    let mut kexinit = KexInit::initiate_rekey(exchange, &enc.session_id);
                                    kexinit.client_write(&config,
                                                         buffer,
                                                         &mut enc.cipher,
                                                         &mut self.buffers.write);
                                    enc.rekey = Some(Kex::KexInit(kexinit))
                                }
                                break
                            } else {
                                // Read a single packet, encrypt and send it.
                                let len = BigEndian::read_u32(&packets[self.write_cursor .. ]) as usize;
                                let packet = &packets [(self.write_cursor+4) .. (self.write_cursor+4+len)];
                                enc.cipher.write(packet, &mut self.buffers.write);
                                self.write_cursor += 4+len
                            }
                        }
                    }
                    if self.write_cursor >= self.write.len() {
                        self.write_cursor = 0;
                        self.write.clear();
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(ReturnCode::Ok)

            }
            /*
                debug!("encrypted state {:?}", enc);
                // self.try_rekey(&mut enc, config);
                let state = std::mem::replace(&mut enc.state, None);

                let read_complete;

                match state {
                    Some(EncryptedState::ServiceRequest) => {

                        let is_service_accept = {
                            if let Some(buf) =
                                   try!(enc.cipher.read(stream, &mut self.buffers.read)) {
                                transport!(buf);
                                read_complete = true;
                                buf[0] == msg::SERVICE_ACCEPT
                            } else {
                                read_complete = false;
                                false
                            }
                        };
                        if is_service_accept {
                            try!(enc.client_service_request(&self.auth_method, &mut self.buffers, buffer))
                        }
                    }
                    Some(EncryptedState::AuthRequestAnswer(auth_request)) => {
                        debug!("auth_request_success");
                        if let Some(buf) = try!(enc.cipher.read(stream,&mut self.buffers.read)) {
                            read_complete = true;
                            try!(enc.client_auth_request_success(buf, auth_request, &self.auth_method, &mut self.buffers.write, buffer, buffer2));
                        } else {
                            read_complete = false;
                        }
                    }
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                        if let Some(buf) = try!(enc.cipher.read(stream, &mut self.buffers.read)) {

                            transport!(buf);

                            read_complete = true;
                            if buf[0] == msg::USERAUTH_BANNER {
                                let mut r = buf.reader(1);
                                client.auth_banner(try!(std::str::from_utf8(try!(r.read_string()))))
                            }
                            debug!("buf = {:?}", buf);
                        } else {
                            read_complete = false;
                        }
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    }
                    Some(EncryptedState::WaitingSignature(auth_request)) => {
                        // The server is waiting for our authentication signature (also USERAUTH_REQUEST).
                        enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                        read_complete = false
                    }
                    Some(EncryptedState::WaitingServiceRequest) => {
                        // This is a writing state for the client, we should send a service request.
                        enc.state = Some(EncryptedState::WaitingServiceRequest);
                        read_complete = false
                    }
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
                           config: &Config,
                           stream: &mut W,
                           buffer: &mut CryptoBuf)
                           -> Result<bool, Error> {
        debug!("write, buffer: {:?}", self.buffers.write);
        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        Ok(true)
        /*
        let state = std::mem::replace(&mut self.state, None);
        debug!("state = {:?}", state);
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
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted");
                // self.try_rekey(&mut enc, config);
                let state = std::mem::replace(&mut enc.state, None);
                match state {
                    Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                        // This cannot be moved to read, because we
                        // might need to change the auth method (using
                        // user input) between read and write: if we
                        // don't do it exactly there, the event loop
                        // won't call read/write again.
                        enc.client_waiting_auth_request(&mut self.buffers.write,
                                                        auth_request,
                                                        &self.auth_method,
                                                        buffer);
                        try!(self.buffers.write_all(stream));
                    }
                    state => {
                        if let Some(rekey) = std::mem::replace(&mut enc.rekey, None) {
                            try!(enc.client_write_rekey(stream, &mut self.buffers, rekey, config, buffer));
                        }
                        enc.state = state
                    }
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            }
            state => {
                self.state = state;
                Ok(true)
            }
        }
        */
    }
    /*
    fn try_rekey(&mut self, enc: &mut Encrypted<&'static ()>, config: &Config) {

        if let Some(rekey) = std::mem::replace(enc.rekey, None) {
            // If there's an ongoing rekeying.
            match rekey {
                Kex::NewKeys(mut newkeys) => {
                    debug!("newkeys {:?}", newkeys);
                    if !newkeys.sent {
                        enc.cipher.write(&[msg::NEWKEYS], &mut self.buffers.write);
                        try!(self.buffers.write_all(stream));
                        newkeys.sent = true;
                    }
                    if !newkeys.received {
                        enc.rekey = Some(Kex::NewKeys(newkeys))
                    } else {
                        enc.exchange = Some(newkeys.exchange);
                        enc.kex = newkeys.kex;
                        enc.key = newkeys.key;
                        enc.cipher = newkeys.cipher;
                        enc.mac = newkeys.names.mac;
                    }
                }
                Kex::KexDh(kexdh) => {
                    try!(enc.client_write_kexdh(buffer, &mut self.buffers.write, kexdh));
                    try!(self.buffers.write_all(stream));
                }
                x => enc.rekey = Some(x),
            }
        } else if (self.buffers.write.bytes >= config.rekey_write_limit ||
                   self.buffers.read.bytes >= config.rekey_read_limit ||
                   time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s) {

            // Else, if it's time to start a rekeying.
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
            // Else, if there's no need for a rekeying.
            debug!("not yet rekeying, {:?}", self.buffers.write.bytes)
        }
    }
    */


    /*
    pub fn needs_auth_method(&self) -> Option<auth::Methods> {

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

    pub fn channel_open(&mut self, channel_type:super::ChannelType, config:&Config, buffer:&mut CryptoBuf) -> Option<u32> {
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::Authenticated) => {
                        debug!("sending open request");


                        let mut sender_channel = 0;
                        while enc.channels.contains_key(&sender_channel) || sender_channel == 0 {
                            sender_channel = rand::thread_rng().gen()
                        }
                        buffer.clear();
                        buffer.push(msg::CHANNEL_OPEN);

                        match channel_type {
                            ChannelType::Session => {
                                buffer.extend_ssh_string(b"session");
                                buffer.push_u32_be(sender_channel); // sender channel id.
                                buffer.push_u32_be(config.window_size); // window.
                                buffer.push_u32_be(config.maxpacket); // max packet size.
                            },
                            ChannelType::X11 { originator_address, originator_port } => {
                                buffer.extend_ssh_string(b"x11");
                                buffer.push_u32_be(sender_channel); // sender channel id.
                                buffer.push_u32_be(config.window_size); // window.
                                buffer.push_u32_be(config.maxpacket); // max packet size.
                                //
                                buffer.extend_ssh_string(originator_address.as_bytes());
                                buffer.push_u32_be(originator_port); // sender channel id.
                            },
                            ChannelType::ForwardedTcpip { connected_address, connected_port, originator_address, originator_port } => {
                                buffer.extend_ssh_string(b"forwarded-tcpip");
                                buffer.push_u32_be(sender_channel); // sender channel id.
                                buffer.push_u32_be(config.window_size); // window.
                                buffer.push_u32_be(config.maxpacket); // max packet size.
                                //
                                buffer.extend_ssh_string(connected_address.as_bytes());
                                buffer.push_u32_be(connected_port); // sender channel id.
                                buffer.extend_ssh_string(originator_address.as_bytes());
                                buffer.push_u32_be(originator_port); // sender channel id.
                            },
                            ChannelType::DirectTcpip { host_to_connect, port_to_connect, originator_address, originator_port } => {
                                buffer.extend_ssh_string(b"direct-tcpip");
                                buffer.push_u32_be(sender_channel); // sender channel id.
                                buffer.push_u32_be(config.window_size); // window.
                                buffer.push_u32_be(config.maxpacket); // max packet size.
                                //
                                buffer.extend_ssh_string(host_to_connect.as_bytes());
                                buffer.push_u32_be(port_to_connect); // sender channel id.
                                buffer.extend_ssh_string(originator_address.as_bytes());
                                buffer.push_u32_be(originator_port); // sender channel id.
                            }
                        }
                        // Send
                        enc.cipher.write(buffer.as_slice(), &mut self.buffers.write);

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

    pub fn channels(&self) -> Option<&HashMap<u32, super::ChannelParameters>> {
        match self.state {
            Some(ServerState::Encrypted(ref enc)) => {
                Some(&enc.channels)
            },
            _ => None
        }
    }

    pub fn set_method(&mut self, method: auth::Method<'a, key::Algorithm>) {
        self.auth_method = Some(method)
    }

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
