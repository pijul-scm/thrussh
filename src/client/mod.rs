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
use super::{Error, ChannelBuf};
use super::encoding::*;
use super::key;
use super::msg;
use super::auth;
use super::cipher::CipherT;
use super::negociation;
use std::io::{Write, BufRead};
use time;
use ReturnCode;
use std;
mod write;
use cryptobuf::CryptoBuf;
use negociation::Select;
use state::*;
use sshbuffer::*;
use std::collections::HashMap;
mod read;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
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
            keys: Vec::new(),
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
    state: Option<ServerState>,
    auth_method: Option<auth::Method<'a>>,
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

impl<'a> Session<'a> {
    pub fn new() -> Self {
        Session::default()
    }
    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, C: super::Client>
        (&mut self,
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
                // We have neither sent nor received the version id.
                // Do both (read and send).
                let mut exchange = Exchange::new();
                // Send our ID, and move on to the next state.
                self.buffers.write.send_ssh_id(config.client_id.as_bytes());
                exchange.client_id.extend(config.client_id.as_bytes());
                //
                self.client_read_server_id(stream, exchange, &config.preferred)
            }
            Some(ServerState::VersionOk(exchange)) => {
                // We've sent our id, and are waiting for the server's id.
                self.client_read_server_id(stream, exchange, &config.preferred)
            }
            Some(ServerState::Kex(Kex::KexInit(kexinit))) => {
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {

                    self.client_kexinit(kexinit, &config.keys, &config.preferred)

                } else {
                    self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                debug!("reading kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(ReturnCode::Ok)
            }
            Some(ServerState::Kex(Kex::KexDhDone(mut kexdhdone))) => {
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {

                    if kexdhdone.names.ignore_guessed {
                        kexdhdone.names.ignore_guessed = false;
                        self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                        Ok(ReturnCode::Ok)
                    } else {
                        self.client_kexdhdone(client, kexdhdone, buffer, buffer2)
                    }
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => {
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {
                    self.client_newkeys(buffer, newkeys)
                } else {
                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            }
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("encrypted state {:?}", enc);
                self.try_rekey(&mut enc, config);
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
                            try!(enc.client_auth_request_success(buf, config, auth_request, &self.auth_method, &mut self.buffers.write, buffer, buffer2));
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
                    Some(EncryptedState::WaitingConnection) => {
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
                                            try!(super::negociation::Client::read_kex(buf, &config.keys, &config.preferred)),
                                            &enc.session_id
                                        );
                                        kexinit.exchange.server_kex_init.extend_from_slice(buf);
                                        enc.rekey = Some(try!(kexinit.kexinit()));
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
                self.try_rekey(&mut enc, config);
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

    }

    fn try_rekey(&mut self, enc: &mut Encrypted, config: &Config) {
        if enc.rekey.is_none() &&
           (self.buffers.write.bytes >= config.rekey_write_limit ||
            self.buffers.read.bytes >= config.rekey_read_limit ||
            time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s) {

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
                    Some(EncryptedState::WaitingConnection) => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }

    pub fn open_channel(&mut self, config:&Config, buffer:&mut CryptoBuf) -> Option<u32> {
        match self.state {
            Some(ServerState::Encrypted(ref mut enc)) => {
                match enc.state {
                    Some(EncryptedState::WaitingConnection) => {
                        debug!("sending open request");
                        Some(enc.client_waiting_channel_open(&mut self.buffers.write, config, buffer))
                    },
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

    pub fn set_method(&mut self, method: auth::Method<'a>) {
        self.auth_method = Some(method)
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

                match std::mem::replace(&mut enc.rekey, None) {
                    Some(Kex::NewKeys(mut newkeys)) => {
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
                            enc.key = newkeys.names.key;
                            enc.cipher = newkeys.cipher;
                            enc.mac = newkeys.names.mac;
                        }
                    }
                    Some(Kex::KexDh(kexdh)) => {
                        try!(enc.client_write_kexdh(buffer, &mut self.buffers.write, kexdh));
                        try!(self.buffers.write_all(stream));
                    }
                    x => enc.rekey = x,
                }

                if enc.rekey.is_none() {

                    match enc.state {
                        Some(EncryptedState::WaitingConnection) => {
                            if let Some(c) = enc.channels.get_mut(&channel) {

                                let written = {
                                    let mut channel_buf = ChannelBuf {
                                        buffer: buffer,
                                        channel: c,
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
}
