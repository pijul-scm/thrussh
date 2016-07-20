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
use cryptobuf::CryptoBuf;
use {Sig, Error, Client, ChannelOpenFailure};
use std;
use auth;
use session::*;
use msg;
use encoding::Reader;
use negociation::Named;
use key;
use key::PubKey;
use negociation;
use negociation::Select;

const SSH_CONNECTION:&'static [u8] = b"ssh-connection";

impl super::Session {
    #[doc(hidden)]
    pub fn client_read_encrypted<C: Client>(&mut self,
                                            client: &mut C,
                                            buf: &[u8],
                                            buffer: &mut CryptoBuf)
                                            -> Result<(), Error> {

        // Either this packet is a KEXINIT, in which case we start a key re-exchange.
        if buf[0] == msg::KEXINIT {
            // Now, if we're encrypted:
            if let Some(ref mut enc) = self.0.encrypted {

                // If we're not currently rekeying, but buf is a rekey request
                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                    let kexinit = KexInit::received_rekey(
                        exchange,
                        try!(negociation::Client::read_kex(buf, &self.0.config.as_ref().preferred)),
                        &enc.session_id
                    );
                    self.0.kex = Some(Kex::KexDhDone(
                        try!(kexinit.client_parse(
                            self.0.config.as_ref(),
                            &mut self.0.cipher,
                            buf,
                            &mut self.0.write_buffer
                        ))
                    ));
                }
                return Ok(())
            }
        }
        // If we've successfully read a packet.
        // debug!("state = {:?}, buf = {:?}", self.0.state, buf);
        let mut is_authenticated = false;
        if let Some(ref mut enc) = self.0.encrypted {

            let state = std::mem::replace(&mut enc.state, None);
            match state {
                Some(EncryptedState::WaitingServiceRequest) => {
                    if buf[0] == msg::SERVICE_ACCEPT {
                        let mut r = buf.reader(1);
                        if try!(r.read_string()) == b"ssh-userauth" {
                            let auth_request = auth::AuthRequest {
                                methods: auth::MethodSet::all(),
                                partial_success: false,
                                public_key: CryptoBuf::new(),
                                public_key_algorithm: CryptoBuf::new(),
                                public_key_is_ok: false,
                                sent_pk_ok: false,
                            };

                            if let Some(ref meth) = self.0.auth_method {
                                if enc.write_auth_request(meth) {
                                    enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                    return Ok(())
                                }
                            }
                            enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        } else {
                            enc.state = Some(EncryptedState::WaitingServiceRequest)
                        }
                    } else {
                        debug!("unknown message: {:?}", buf);
                        return Err(Error::Inconsistent)
                    }
                },
                Some(EncryptedState::WaitingAuthRequest(mut auth_request)) => {
                    if buf[0] == msg::USERAUTH_SUCCESS {

                        enc.state = Some(EncryptedState::Authenticated);

                    } else if buf[0] == msg::USERAUTH_FAILURE {

                        let mut r = buf.reader(1);
                        let remaining_methods = try!(r.read_string());
                        for method in remaining_methods.split(|&c| c == b',') {
                            if let Some(m) = auth::MethodSet::from_bytes(method) {
                                auth_request.methods &= m
                            }
                        }
                        self.0.auth_method = None;
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));

                    } else if buf[0] == msg::USERAUTH_PK_OK {

                        auth_request.public_key_is_ok = true;
                        if let Some(ref auth_method) = self.0.auth_method {
                            enc.client_send_signature(auth_method, buffer);
                        }
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    } else {
                        debug!("unknown message: {:?}", buf);
                        return Err(Error::Inconsistent)
                    }
                }
                Some(EncryptedState::Authenticated) => {
                    enc.state = Some(EncryptedState::Authenticated);
                    is_authenticated = true
                },
                None => unreachable!()
            }
        }
        if is_authenticated {
            match buf[0] {
                msg::CHANNEL_OPEN_CONFIRMATION => {
                    debug!("channel_confirmation? {:?}", buf);
                    let mut reader = buf.reader(1);
                    let id_send = try!(reader.read_u32());
                    let id_recv = try!(reader.read_u32());
                    let window = try!(reader.read_u32());
                    let max_packet = try!(reader.read_u32());

                    if let Some(ref mut enc) = self.0.encrypted {

                        if let Some(parameters) = enc.channels.get_mut(&id_send) {
                            
                            parameters.recipient_channel = id_recv;
                            parameters.recipient_window_size = window;
                            parameters.recipient_maximum_packet_size = max_packet;
                            parameters.confirmed = true;

                        } else {
                            // We've not requested this channel, close connection.
                            return Err(Error::Inconsistent)
                        }
                    }
                    try!(client.channel_open_confirmation(id_send, self));
                }
                msg::CHANNEL_CLOSE => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    if let Some(ref mut enc) = self.0.encrypted {
                        enc.channels.remove(&channel_num);
                    }
                    try!(client.channel_close(channel_num, self));
                }
                msg::CHANNEL_EOF => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    try!(client.channel_eof(channel_num, self));
                }
                msg::CHANNEL_OPEN_FAILURE => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    let reason_code = ChannelOpenFailure::from_u32(try!(r.read_u32())).unwrap();
                    let descr = try!(std::str::from_utf8(try!(r.read_string())));
                    let language = try!(std::str::from_utf8(try!(r.read_string())));
                    if let Some(ref mut enc) = self.0.encrypted {
                        enc.channels.remove(&channel_num);
                    }
                    try!(client.channel_open_failure(channel_num, reason_code, descr, language, self));
                }
                msg::CHANNEL_DATA => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    let data = try!(r.read_string());
                    try!(client.data(channel_num, None, &data, self));
                    let target = self.0.config.window_size;
                    if let Some(ref mut enc) = self.0.encrypted {
                        enc.adjust_window_size(channel_num, data, target);
                    }
                }
                msg::CHANNEL_EXTENDED_DATA => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    let extended_code = try!(r.read_u32());
                    let data = try!(r.read_string());
                    try!(client.data(channel_num, Some(extended_code), &data, self));
                    let target = self.0.config.window_size;
                    if let Some(ref mut enc) = self.0.encrypted {
                        enc.adjust_window_size(channel_num, data, target);
                    }
                }
                msg::CHANNEL_REQUEST => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    let req = try!(r.read_string());
                    match req {
                        b"forwarded_tcpip" => {
                            let a = try!(std::str::from_utf8(try!(r.read_string())));
                            let b = try!(r.read_u32());
                            let c = try!(std::str::from_utf8(try!(r.read_string())));
                            let d = try!(r.read_u32());
                            client.channel_open_forwarded_tcpip(channel_num, a, b, c, d, self);
                        },
                        b"xon-xoff" => {
                            try!(r.read_byte()); // should be 0.
                            let client_can_do = try!(r.read_byte());
                            try!(client.xon_xoff(channel_num, client_can_do != 0, self));
                        },
                        b"exit-status" => {
                            try!(r.read_byte()); // should be 0.
                            let exit_status = try!(r.read_u32());
                            try!(client.exit_status(channel_num, exit_status, self));
                        },
                        b"exit-signal" => {
                            try!(r.read_byte()); // should be 0.
                            let signal_name = try!(Sig::from_name(try!(r.read_string())));
                            let core_dumped = try!(r.read_byte());
                            let error_message = try!(std::str::from_utf8(try!(r.read_string())));
                            let lang_tag = try!(std::str::from_utf8(try!(r.read_string())));
                            try!(client.exit_signal(channel_num, signal_name, core_dumped!=0, error_message, lang_tag, self));
                        },
                        _ => {
                            unimplemented!()
                        }
                    }
                }
                msg::CHANNEL_WINDOW_ADJUST => {
                    let mut r = buf.reader(1);
                    let channel_num = try!(r.read_u32());
                    let amount = try!(r.read_u32());
                    if let Some(ref mut enc) = self.0.encrypted {
                        if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                            channel.recipient_window_size += amount
                        } else {
                            return Err(Error::WrongChannel)
                        }
                    }
                    try!(client.window_adjusted(channel_num, self));
                }
                _ => {
                    info!("Unhandled packet: {:?}", buf);
                }
            }
        }
        Ok(())
    }
}
impl Encrypted {
    pub fn write_auth_request(&mut self, auth_method: &auth::Method<key::Algorithm>) -> bool {
        // The server is waiting for our USERAUTH_REQUEST.
        push_packet!(self.write, {
            self.write.push(msg::USERAUTH_REQUEST);
            match *auth_method {
                auth::Method::Password { ref user, ref password } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(SSH_CONNECTION);
                    self.write.extend_ssh_string(b"password");
                    self.write.push(1);
                    self.write.extend_ssh_string(password.as_bytes());
                    true
                }
                auth::Method::PublicKey { ref user, ref key } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(SSH_CONNECTION);
                    self.write.extend_ssh_string(b"publickey");
                    self.write.push(0); // This is a probe
                    self.write.extend_ssh_string(key.name().as_bytes());
                    key.push_to(&mut self.write);
                    true
                }
            }
        })
    }

    pub fn client_send_signature(&mut self,
                                 method: &auth::Method<key::Algorithm>,
                                 buffer: &mut CryptoBuf) {
        debug!("sending signature {:?}", method);
        match method {
            &auth::Method::PublicKey { ref user, ref key } => {

                buffer.clear();
                buffer.extend_ssh_string(self.session_id.as_bytes());
                let i0 = buffer.len();
                buffer.push(msg::USERAUTH_REQUEST);
                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(SSH_CONNECTION);
                buffer.extend_ssh_string(b"publickey");
                buffer.push(1);
                buffer.extend_ssh_string(key.name().as_bytes());
                key.push_to(buffer);
                // Extend with self-signature.
                key.add_self_signature(buffer);
                debug!("packet : {:?}", &buffer.as_slice()[i0..]);
                push_packet!(self.write, {
                    self.write.extend(&buffer.as_slice()[i0..]);
                })
            },
            _ => { }
        }
    }
}
