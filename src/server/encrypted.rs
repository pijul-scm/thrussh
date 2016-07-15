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
use super::*;
use super::super::*;
use state::*;
use msg;
use encoding::Reader;
use auth::*;
use std;
use byteorder::{ByteOrder};
use rand::{thread_rng, Rng};
use key::Verify;

impl <'k> Encrypted<&'k key::Algorithm> {

    pub fn server_read_encrypted<S: Server>(&mut self,
                                            config: &'k Config,
                                            server: &mut S,
                                            buf: &[u8],
                                            buffer: &mut CryptoBuf)
                                            -> Result<(), Error> {
        // If we've successfully read a packet.
        debug!("state = {:?}, buf = {:?}", self.state, buf);
        let state = std::mem::replace(&mut self.state, None);
        match state {
            Some(EncryptedState::WaitingServiceRequest) if buf[0] == msg::SERVICE_REQUEST => {

                let mut r = buf.reader(1);
                let request = try!(r.read_string());
                debug!("request: {:?}", std::str::from_utf8(request));
                if request == b"ssh-userauth" {

                    let auth_request =
                        server_accept_service(config.auth_banner,
                                              config.methods,
                                              &mut self.write);
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));

                } else {

                    self.state = Some(EncryptedState::WaitingServiceRequest)
                }
                Ok(())
            },
            Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                if buf[0] == msg::USERAUTH_REQUEST {
                    try!(self.server_read_auth_request(server, buf, buffer, auth_request));
                    Ok(())
                } else {
                    // Wrong request
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    Ok(())
                }
            }
            Some(EncryptedState::Authenticated) => {
                self.state = Some(EncryptedState::Authenticated);
                self.server_read_authenticated(config, server, buf)
            },
            state => {
                self.state = state;
                Ok(())
            }
        }
    }

    pub fn server_read_authenticated<S: Server>(&mut self,
                                                config: &'k Config,
                                                server: &mut S,
                                                buf: &[u8])
                                                -> Result<(), Error> {
        debug!("authenticated buf = {:?}", buf);
        match buf[0] {
            msg::CHANNEL_OPEN => {
                try!(self.server_handle_channel_open(config, server, buf));
                Ok(())
            },
            msg::CHANNEL_EXTENDED_DATA |
            msg::CHANNEL_DATA => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());

                let ext = if buf[0] == msg::CHANNEL_DATA {
                    None
                } else {
                    Some(try!(r.read_u32()))
                };

                let data =
                    if let Some(channel) = self.channels.get_mut(&channel_num) {
                        let data = try!(r.read_string());
                        // Ignore extra data.
                        // https://tools.ietf.org/html/rfc4254#section-5.2
                        if data.len() as u32 <= channel.sender_window_size {
                            channel.sender_window_size -= data.len() as u32;
                        }
                        data
                    } else {
                        return Err(Error::WrongChannel)
                    };
                {
                    let buf = ChannelBuf {
                        session: self,
                        wants_reply: false,
                    };
                    if let Some(ext) = ext {
                        try!(server.extended_data(channel_num, ext, &data, buf));
                    } else {
                        try!(server.data(channel_num, &data, buf));
                    }
                }
                
                if let Some(channel) = self.channels.get_mut(&channel_num) {
                    // debug!("{:?} / {:?}", channel.sender_window_size, config.window_size);
                    if channel.sender_window_size < config.window_size / 2 {
                        super::super::adjust_window_size(&mut self.write,
                                                         config.window_size,
                                                         channel)
                    }
                }
                Ok(())
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                let amount = try!(r.read_u32());
                if let Some(channel) = self.channels.get_mut(&channel_num) {
                    channel.recipient_window_size += amount;
                    Ok(())
                } else {
                    Err(Error::WrongChannel)
                }
            }
            msg::CHANNEL_REQUEST => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                let req_type = try!(r.read_string());
                let wants_reply = try!(r.read_byte());
                let buf = ChannelBuf {
                    session: self,
                    wants_reply: wants_reply != 0,
                };
                match req_type {
                    b"exec" => {
                        let req = try!(r.read_string());
                        try!(server.exec(channel_num, req, buf));
                    }
                    b"pty-req" => {
                        unimplemented!()
                    }
                    b"x11-req" => {
                        unimplemented!()
                    }
                    b"shell" => {
                        unimplemented!()
                    }
                    b"subsystem" => {
                        unimplemented!()
                    }
                    b"xon-xoff" => {
                        unimplemented!()
                    }
                    b"exit-status" => {
                        unimplemented!()
                    }
                    b"exit-signal" => {
                        unimplemented!()
                    }
                    x => {
                        debug!("{:?}, line {:?} req_type = {:?}", file!(), line!(), std::str::from_utf8(x))
                    }
                }
                Ok(())
            }
            msg::CHANNEL_EOF |
            msg::CHANNEL_CLOSE => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                self.channels.remove(&channel_num);
                Ok(())
            }
            m => {
                debug!("unknown message received: {:?}", m);
                Ok(())
            }
        }
    }


    pub fn server_read_auth_request<S: Server>(&mut self,
                                               server: &S,
                                               buf: &[u8],
                                               buffer: &mut CryptoBuf,
                                               mut auth_request: AuthRequest)
                                               -> Result<(), Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let name = try!(r.read_string());
        let name = try!(std::str::from_utf8(name));
        let service_name = try!(r.read_string());
        let method = try!(r.read_string());
        debug!("name: {:?} {:?} {:?}",
               name, std::str::from_utf8(service_name),
               std::str::from_utf8(method));

        if service_name == b"ssh-connection" {

            if method == b"password" {

                try!(r.read_byte());
                let password = try!(r.read_string());
                let password = try!(std::str::from_utf8(password));
                let method = Method::Password {
                    user: name,
                    password: password,
                };
                match server.auth(auth_request.methods, &method) {
                    Auth::Success => {
                        server_auth_request_success(&mut self.write);
                        self.state = Some(EncryptedState::Authenticated);
                    },
                    Auth::Reject { remaining_methods, partial_success } => {
                        auth_request.methods = remaining_methods;
                        auth_request.partial_success = partial_success;
                        self.reject_auth_request(auth_request);
                    }
                }
                
            } else if method == b"publickey" {

                let is_real = try!(r.read_byte());
                let pubkey_algo = try!(r.read_string());
                let pubkey_key = try!(r.read_string());
                let pubkey = try!(key::PublicKey::parse(pubkey_algo, pubkey_key));
                debug!("is_real = {:?}", is_real);

                if is_real != 0 {

                    let pos0 = r.position;
                    // Check that the user is still authorized (the client may have changed user since we accepted).
                    let method = Method::PublicKey {
                        user: name,
                        pubkey: pubkey.clone()
                    };

                    match server.auth(auth_request.methods, &method) {
                        Auth::Success => {
                            let signature = try!(r.read_string());
                            let mut s = signature.reader(0);
                            // let algo_ =
                            try!(s.read_string());
                            let sig = try!(s.read_string());
                            
                            buffer.clear();
                            buffer.extend_ssh_string(self.session_id.as_bytes());
                            buffer.extend(&buf[0..pos0]);
                            // Verify signature.
                            if pubkey.verify_detached(buffer.as_slice(), sig) {
                                debug!("signature verified");
                                server_auth_request_success(&mut self.write);
                                self.state = Some(EncryptedState::Authenticated);
                            } else {
                                debug!("wrong signature");
                                self.reject_auth_request(auth_request);
                            }
                        }
                        _ => {
                            debug!("rejected");
                            self.reject_auth_request(auth_request)
                        }
                    }

                } else {

                    let method = Method::PublicKey {
                        user: name,
                        pubkey: pubkey
                    };

                    match server.auth(auth_request.methods, &method) {
                        Auth::Success => {
                            // Public key ?
                            auth_request.public_key.extend(pubkey_key);
                            auth_request.public_key_algorithm.extend(pubkey_algo);
                            server_send_pk_ok(&mut self.write, &mut auth_request);
                            self.state = Some(EncryptedState::WaitingAuthRequest(auth_request))
                        }
                        Auth::Reject { remaining_methods, partial_success } => {
                            auth_request.methods = remaining_methods;
                            auth_request.partial_success = partial_success;
                            self.reject_auth_request(auth_request);
                        }
                    }
                }
            } else {
                // Other methods of the base specification are insecure or optional.
                self.reject_auth_request(auth_request);
            }
            Ok(())
        } else {
            // Unknown service
            Err(Error::Inconsistent)
        }
    }
    

    fn reject_auth_request(&mut self, auth_request:AuthRequest) {
        debug!("rejecting {:?}", auth_request);
        push_packet!(self.write, {
            self.write.push(msg::USERAUTH_FAILURE);
            self.write.extend_list(auth_request.methods);
            self.write.push(if auth_request.partial_success { 1 } else { 0 });
        });
        debug!("packet pushed");
        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
    }

    fn server_handle_channel_open<S: Server>(&mut self,
                                             config: &super::Config,
                                             server: &mut S,
                                             buf: &[u8])
                                             -> Result<(), Error> {
        
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let mut r = buf.reader(1);
        let typ = try!(r.read_string());
        let sender = try!(r.read_u32());
        let window = try!(r.read_u32());
        let maxpacket = try!(r.read_u32());

        let mut sender_channel: u32 = 1;
        while self.channels.contains_key(&sender_channel) || sender_channel == 0 {
            sender_channel = thread_rng().gen()
        }
        let channel = ChannelParameters {
            recipient_channel: sender,
            sender_channel: sender_channel, /* "sender" is the local end, i.e. we're the sender, the remote is the recipient. */
            recipient_window_size: window,
            sender_window_size: config.window_size,
            recipient_maximum_packet_size: maxpacket,
            sender_maximum_packet_size: config.maximum_packet_size,
            confirmed: true
        };
        debug!("waiting channel open: {:?}", channel);
        // Write the response immediately, so that we're ready when the stream becomes writable.
        server.new_channel(sender_channel);
        server_confirm_channel_open(&mut self.write, &channel, config);
        //
        let sender_channel = channel.sender_channel;
        self.channels.insert(sender_channel, channel);
        self.state = Some(EncryptedState::Authenticated);
        Ok(())
    }
}


fn server_accept_service(banner: Option<&str>,
                         methods: auth::M,
                         buffer: &mut CryptoBuf)
                         -> AuthRequest {

    push_packet!(buffer, {
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
    });
    
    if let Some(ref banner) = banner {
        push_packet!(buffer, {
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");
        })
    }

    AuthRequest {
        methods: methods,
        partial_success: false, // not used immediately anway.
        public_key: CryptoBuf::new(),
        public_key_algorithm: CryptoBuf::new(),
        sent_pk_ok: false,
        public_key_is_ok: false,
    }
}


fn server_auth_request_success(buffer: &mut CryptoBuf) {

    push_packet!(buffer,{
        buffer.push(msg::USERAUTH_SUCCESS);
    })
}

fn server_send_pk_ok(buffer: &mut CryptoBuf,
                         auth_request: &mut AuthRequest) {
    push_packet!(buffer, {
        buffer.push(msg::USERAUTH_PK_OK);
        buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
        buffer.extend_ssh_string(auth_request.public_key.as_slice());
    });
    auth_request.sent_pk_ok = true;
}

fn server_confirm_channel_open(buffer: &mut CryptoBuf,
                               channel: &ChannelParameters,
                               config: &super::Config) {

    push_packet!(buffer, {
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel); // remote channel number.
        buffer.push_u32_be(channel.sender_channel); // our channel number.
        buffer.push_u32_be(config.window_size);
        buffer.push_u32_be(config.maximum_packet_size);
    });
}
