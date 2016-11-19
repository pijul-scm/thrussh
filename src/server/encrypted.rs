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
use std;
use byteorder::{ByteOrder, BigEndian};

use super::*;
use super::super::*;
use session::*;
use msg;
use encoding::{Encoding, Reader};
use auth::*;
use key::Verify;
use negociation;
use negociation::Select;
use auth;

impl Session {
    #[doc(hidden)]
    /// Returns false iff a request was rejected.
    pub fn server_read_encrypted<S: Handler>(&mut self,
                                             server: &mut S,
                                             buf: &[u8],
                                             buffer: &mut CryptoVec)
                                             -> Result<bool, Error> {
        debug!("read_encrypted");
        // Either this packet is a KEXINIT, in which case we start a key re-exchange.
        if buf[0] == msg::KEXINIT {
            // Now, if we're encrypted:
            if let Some(ref mut enc) = self.0.encrypted {

                // If we're not currently rekeying, but buf is a rekey request
                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                    let kexinit = KexInit::received_rekey(
                        exchange,
                        try!(negociation::Server::read_kex(buf, &self.0.config.as_ref().preferred)),
                        &enc.session_id
                    );
                    self.0.kex = Some(try!(kexinit.server_parse(self.0.config.as_ref(),
                                                                &mut self.0.cipher,
                                                                buf,
                                                                &mut self.0.write_buffer)));
                }
                return Ok(true);
            }
        }
        // If we've successfully read a packet.
        // debug!("state = {:?}, buf = {:?}", self.0.state, buf);
        let mut is_authenticated = false;
        if let Some(ref mut enc) = self.0.encrypted {
            let state = std::mem::replace(&mut enc.state, None);
            debug!("state = {:?} {:?} {:?}", state, buf[0], msg::SERVICE_REQUEST);
            match state {
                Some(EncryptedState::WaitingServiceRequest) if buf[0] == msg::SERVICE_REQUEST => {

                    let mut r = buf.reader(1);
                    let request = try!(r.read_string());
                    debug!("request: {:?}", std::str::from_utf8(request));
                    if request == b"ssh-userauth" {

                        let auth_request = server_accept_service(self.0
                                                                     .config
                                                                     .as_ref()
                                                                     .auth_banner,
                                                                 self.0.config.as_ref().methods,
                                                                 &mut enc.write);
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));

                    } else {

                        enc.state = Some(EncryptedState::WaitingServiceRequest)
                    }
                }
                Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                    if buf[0] == msg::USERAUTH_REQUEST {
                        return enc.server_read_auth_request(server,
                                                            buf,
                                                            buffer,
                                                            &mut self.0.auth_user,
                                                            auth_request);
                    } else if buf[0] == msg::USERAUTH_INFO_RESPONSE {
                        return enc.read_userauth_info_response(server, &self.0.auth_user, auth_request, buf)
                    } else {
                        // Wrong request
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    }
                }
                Some(EncryptedState::Authenticated) => {
                    is_authenticated = true;
                    enc.state = Some(EncryptedState::Authenticated)
                }
                state => {
                    enc.state = state;
                }
            }
        }
        if is_authenticated {
            try!(self.server_read_authenticated(server, buf))
        }
        Ok(true)
    }

    fn server_read_authenticated<S: Handler>(&mut self,
                                             server: &mut S,
                                             buf: &[u8])
                                             -> Result<(), Error> {
        debug!("authenticated buf = {:?}", buf);
        match buf[0] {
            msg::CHANNEL_OPEN => {
                try!(self.server_handle_channel_open(server, buf));
                Ok(())
            }
            msg::CHANNEL_CLOSE => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                if let Some(ref mut enc) = self.0.encrypted {
                    enc.channels.remove(&channel_num);
                }
                server.channel_close(channel_num, self)
            }
            msg::CHANNEL_EOF => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                server.channel_eof(channel_num, self)
            }
            msg::CHANNEL_EXTENDED_DATA |
            msg::CHANNEL_DATA => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());

                let ext = if buf[0] == msg::CHANNEL_DATA {
                    None
                } else {
                    Some(try!(r.read_u32()))
                };
                let data = if let Some(ref mut enc) = self.0.encrypted {

                    let data = try!(r.read_string());
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        // Ignore extra data.
                        // https://tools.ietf.org/html/rfc4254#section-5.2
                        if data.len() as u32 <= channel.sender_window_size {
                            channel.sender_window_size -= data.len() as u32;
                        }
                    } else {
                        return Err(Error::WrongChannel);
                    }
                    let window_size = self.0.config.window_size;
                    enc.adjust_window_size(channel_num, data, window_size);
                    data

                } else {
                    unreachable!()
                };
                {
                    if let Some(ext) = ext {
                        try!(server.extended_data(channel_num, ext, &data, self));
                    } else {
                        try!(server.data(channel_num, &data, self));
                    }
                }
                Ok(())
            }

            msg::CHANNEL_WINDOW_ADJUST => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                let amount = try!(r.read_u32());
                if let Some(ref mut enc) = self.0.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.recipient_window_size += amount;
                    } else {
                        return Err(Error::WrongChannel);
                    }
                }
                try!(server.window_adjusted(channel_num, self));
                Ok(())
            }

            msg::CHANNEL_REQUEST => {
                let mut r = buf.reader(1);
                let channel_num = try!(r.read_u32());
                let req_type = try!(r.read_string());
                let wants_reply = try!(r.read_byte());
                if let Some(ref mut enc) = self.0.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.wants_reply = wants_reply != 0;
                    }
                }
                match req_type {
                    b"pty-req" => {
                        let term = try!(std::str::from_utf8(try!(r.read_string())));
                        let col_width = try!(r.read_u32());
                        let row_height = try!(r.read_u32());
                        let pix_width = try!(r.read_u32());
                        let pix_height = try!(r.read_u32());
                        let mut modes = [(Pty::TTY_OP_END, 0); 130];
                        let mut i = 0;
                        {
                            let mode_string = try!(r.read_string());
                            while 5 * i < mode_string.len() {
                                let code = mode_string[5 * i];
                                if code == 0 {
                                    break;
                                }
                                let num = BigEndian::read_u32(&mode_string[5 * i + 1..]);
                                debug!("code = {:?}", code);
                                if let Some(code) = Pty::from_u8(code) {
                                    modes[i] = (code, num);
                                } else {
                                    info!("pty-req: unknown pty code {:?}", code);
                                }
                                i += 1
                            }
                        }
                        try!(server.pty_request(channel_num,
                                                term,
                                                col_width,
                                                row_height,
                                                pix_width,
                                                pix_height,
                                                &modes[0..i],
                                                self));
                    }
                    b"x11-req" => {
                        let single_connection = try!(r.read_byte()) != 0;
                        let x11_auth_protocol = try!(std::str::from_utf8(try!(r.read_string())));
                        let x11_auth_cookie = try!(std::str::from_utf8(try!(r.read_string())));
                        let x11_screen_number = try!(r.read_u32());
                        try!(server.x11_request(channel_num,
                                                single_connection,
                                                x11_auth_protocol,
                                                x11_auth_cookie,
                                                x11_screen_number,
                                                self));
                    }
                    b"env" => {
                        let env_variable = try!(std::str::from_utf8(try!(r.read_string())));
                        let env_value = try!(std::str::from_utf8(try!(r.read_string())));
                        try!(server.env_request(channel_num, env_variable, env_value, self));
                    }
                    b"shell" => {
                        try!(server.shell_request(channel_num, self));
                    }
                    b"exec" => {
                        let req = try!(r.read_string());
                        try!(server.exec_request(channel_num, req, self));
                    }
                    b"subsystem" => {
                        let name = try!(std::str::from_utf8(try!(r.read_string())));
                        try!(server.subsystem_request(channel_num, name, self));
                    }
                    b"window_change" => {
                        let col_width = try!(r.read_u32());
                        let row_height = try!(r.read_u32());
                        let pix_width = try!(r.read_u32());
                        let pix_height = try!(r.read_u32());
                        try!(server.window_change_request(channel_num,
                                                          col_width,
                                                          row_height,
                                                          pix_width,
                                                          pix_height,
                                                          self));
                    }
                    b"signal" => {
                        try!(r.read_byte()); // should be 0.
                        let signal_name = try!(Sig::from_name(try!(r.read_string())));
                        try!(server.signal(channel_num, signal_name, self));
                    }
                    x => {
                        debug!("{:?}, line {:?} req_type = {:?}",
                               file!(),
                               line!(),
                               std::str::from_utf8(x));
                        if let Some(ref mut enc) = self.0.encrypted {
                            push_packet!(enc.write, {
                                enc.write.push(msg::CHANNEL_FAILURE);
                            });
                        }
                    }
                }
                Ok(())
            }
            msg::GLOBAL_REQUEST => {
                let mut r = buf.reader(1);
                let req_type = try!(r.read_string());
                self.0.wants_reply = try!(r.read_byte()) != 0;
                match req_type {
                    b"tcpip-forward" => {
                        let address = try!(std::str::from_utf8(try!(r.read_string())));
                        let port = try!(r.read_u32());
                        let result = server.tcpip_forward(address, port, self);
                        if self.0.wants_reply {
                            if let Some(ref mut enc) = self.0.encrypted {
                                if result.is_ok() {
                                    push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                                } else {
                                    push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                                }
                            }
                        }
                        result
                    }
                    b"cancel-tcpip-forward" => {
                        let address = try!(std::str::from_utf8(try!(r.read_string())));
                        let port = try!(r.read_u32());
                        let result = server.cancel_tcpip_forward(address, port, self);
                        if self.0.wants_reply {
                            if let Some(ref mut enc) = self.0.encrypted {
                                if result.is_ok() {
                                    push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                                } else {
                                    push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                                }
                            }
                        }
                        result
                    }
                    _ => {
                        if let Some(ref mut enc) = self.0.encrypted {
                            push_packet!(enc.write, {
                                enc.write.push(msg::REQUEST_FAILURE);
                            });
                        }
                        Ok(())
                    }
                }
            }
            m => {
                debug!("unknown message received: {:?}", m);
                Ok(())
            }
        }
    }

    fn server_handle_channel_open<S: Handler>(&mut self,
                                              server: &mut S,
                                              buf: &[u8])
                                              -> Result<(), Error> {

        // https://tools.ietf.org/html/rfc4254#section-5.1
        let mut r = buf.reader(1);
        let typ = try!(r.read_string());
        let sender = try!(r.read_u32());
        let window = try!(r.read_u32());
        let maxpacket = try!(r.read_u32());

        let sender_channel = if let Some(ref mut enc) = self.0.encrypted {
            enc.new_channel_id()
        } else {
            unreachable!()
        };


        match typ {
            b"session" => {
                server.channel_open_session(sender_channel, self);
            }
            b"x11" => {
                let a = try!(std::str::from_utf8(try!(r.read_string())));
                let b = try!(r.read_u32());
                server.channel_open_x11(sender_channel, a, b, self);
            }
            b"direct-tcpip" => {
                let a = try!(std::str::from_utf8(try!(r.read_string())));
                let b = try!(r.read_u32());
                let c = try!(std::str::from_utf8(try!(r.read_string())));
                let d = try!(r.read_u32());
                server.channel_open_direct_tcpip(sender_channel, a, b, c, d, self);
            }
            t => {
                debug!("unknown channel type: {:?}", t);
                if let Some(ref mut enc) = self.0.encrypted {
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                        enc.write.push_u32_be(sender);
                        enc.write.push_u32_be(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                        enc.write.extend_ssh_string(b"Unknown channel type");
                        enc.write.extend_ssh_string(b"en");
                    });
                }
                return Ok(());
            }
        }
        let channel = Channel {
            recipient_channel: sender,

            // "sender" is the local end, i.e. we're the sender, the remote is the recipient.
            sender_channel: sender_channel,

            recipient_window_size: window,
            sender_window_size: self.0.config.window_size,
            recipient_maximum_packet_size: maxpacket,
            sender_maximum_packet_size: self.0.config.maximum_packet_size,
            confirmed: true,
            wants_reply: false,
        };
        debug!("waiting channel open: {:?}", channel);
        // Write the response immediately, so that we're ready when the stream becomes writable.
        if let Some(ref mut enc) = self.0.encrypted {
            server_confirm_channel_open(&mut enc.write, &channel, self.0.config.as_ref());
            //
            let sender_channel = channel.sender_channel;
            enc.channels.insert(sender_channel, channel);
            enc.state = Some(EncryptedState::Authenticated);
        }
        Ok(())
    }
}


impl Encrypted {
    /// Returns false iff the request was rejected.
    pub fn server_read_auth_request<S: Handler>(&mut self,
                                                server: &mut S,
                                                buf: &[u8],
                                                buffer: &mut CryptoVec,
                                                auth_user: &mut String,
                                                mut auth_request: AuthRequest)
                                                -> Result<bool, Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let user = try!(r.read_string());
        let user = try!(std::str::from_utf8(user));
        let service_name = try!(r.read_string());
        let method = try!(r.read_string());
        debug!("name: {:?} {:?} {:?}",
               user,
               std::str::from_utf8(service_name),
               std::str::from_utf8(method));

        if service_name == b"ssh-connection" {

            if method == b"password" {

                auth_user.clear();
                auth_user.push_str(user);

                try!(r.read_byte());
                let password = try!(r.read_string());
                let password = try!(std::str::from_utf8(password));

                if server.auth_password(user, password) {
                    server_auth_request_success(&mut self.write);
                    self.state = Some(EncryptedState::Authenticated);
                    Ok(true)
                } else {

                    auth_user.clear();
                    auth_request.methods = auth_request.methods - auth::PASSWORD;
                    auth_request.partial_success = false;
                    self.reject_auth_request(auth_request);
                    Ok(false)
                }

            } else if method == b"publickey" {

                let is_real = try!(r.read_byte());
                let pubkey_algo = try!(r.read_string());
                let pubkey_key = try!(r.read_string());
                match key::PublicKey::parse(pubkey_algo, pubkey_key) {
                    Ok(pubkey) => {
                        debug!("is_real = {:?}", is_real);

                        if is_real != 0 {

                            let pos0 = r.position;
                            if let Some(CurrentRequest::PublicKey { ref key, ref algo, sent_pk_ok }) = auth_request.current {
                                if (sent_pk_ok && user == auth_user) || (auth_user.len() == 0 && server.auth_publickey(user, &pubkey)) {

                                    let signature = try!(r.read_string());
                                    let mut s = signature.reader(0);
                                    // let algo_ =
                                    try!(s.read_string());
                                    let sig = try!(s.read_string());

                                    buffer.clear();
                                    buffer.extend_ssh_string(self.session_id.as_ref());
                                    buffer.extend(&buf[0..pos0]);
                                    // Verify signature.
                                    if pubkey.verify_detached(&buffer, sig) {
                                        debug!("signature verified");
                                        server_auth_request_success(&mut self.write);
                                        self.state = Some(EncryptedState::Authenticated);
                                        return Ok(true)
                                    }
                                }
                            }
                            debug!("rejected");
                            auth_user.clear();
                            self.reject_auth_request(auth_request);
                            Ok(false)

                        } else {

                            if server.auth_publickey(user, &pubkey) {

                                auth_user.clear();
                                auth_user.push_str(user);

                                let mut public_key = CryptoVec::new();
                                public_key.extend(pubkey_key);

                                let mut algo = CryptoVec::new();
                                algo.extend(pubkey_algo);

                                push_packet!(buffer, {
                                    buffer.push(msg::USERAUTH_PK_OK);
                                    buffer.extend_ssh_string(&pubkey_algo);
                                    buffer.extend_ssh_string(&pubkey_key);
                                });

                                auth_request.current = Some(CurrentRequest::PublicKey {
                                    key: public_key,
                                    algo: algo,
                                    sent_pk_ok: true,
                                });

                                self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                Ok(true)
                            } else {
                                auth_request.methods -= auth::PUBLICKEY;
                                auth_request.partial_success = false;
                                auth_user.clear();
                                self.reject_auth_request(auth_request);
                                Ok(false)
                            }
                        }
                    }
                    Err(Error::UnknownKey) => {
                        self.reject_auth_request(auth_request);
                        Ok(false)
                    }
                    Err(e) => return Err(e),
                }
                // Other methods of the base specification are insecure or optional.
            } else if method == b"keyboard-interactive" {

                let language_tag = try!(r.read_string());
                let submethods = try!(std::str::from_utf8(try!(r.read_string())));
                debug!("{:?}", submethods);
                let success = try!(userauth_info_request(server, user, submethods, &mut self.write, None));

                if success {
                    self.state = Some(EncryptedState::Authenticated);
                    Ok(true)
                } else {
                    auth_request.current = Some(CurrentRequest::KeyboardInteractive { submethods: submethods.to_string() });
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                    Ok(false)
                }
            } else {
                let count = auth_request.rejection_count;
                self.reject_auth_request(auth_request);
                Ok(count <= 1)
            }
        } else {
            // Unknown service
            Err(Error::Inconsistent)
        }
    }

    fn read_userauth_info_response<S:Handler>(&mut self, server: &mut S, user: &str, auth_request: AuthRequest, b: &[u8]) -> Result<bool, Error> {
        let succ =
            if let Some(CurrentRequest::KeyboardInteractive{ ref submethods }) = auth_request.current {

                let mut r = b.reader(1);
                let n = try!(r.read_u32());
                let response = Response {
                    pos: r,
                    n: n
                };
                try!(userauth_info_request(server, user, submethods, &mut self.write, Some(response)))
            } else {
                false
            };
        if succ {
            self.state = Some(EncryptedState::Authenticated);
        } else {
            self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
        }
        Ok(succ)
    }

    fn reject_auth_request(&mut self, mut auth_request: AuthRequest) {
        debug!("rejecting {:?}", auth_request);
        push_packet!(self.write, {
            self.write.push(msg::USERAUTH_FAILURE);
            self.write.extend_list(auth_request.methods);
            self.write.push(if auth_request.partial_success { 1 } else { 0 });
        });
        auth_request.current = None;
        auth_request.rejection_count += 1;
        debug!("packet pushed");
        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
    }
}

fn userauth_info_request<S:Handler>(server: &mut S, user: &str, submethods: &str, write: &mut CryptoVec, response: Option<Response>) -> Result<bool, Error> {
    let mut success = false;
    let l0 = write.len();
    push_packet!(write, {
        write.push(msg::USERAUTH_INFO_REQUEST);
        let (n, l) = {
            let mut ki = KeyboardInteractive::new(write);
            success = server.auth_keyboard_interactive(
                user, submethods, &mut ki, response
            );
            (ki.n, ki.l)
        };
        use byteorder::{BigEndian, ByteOrder};
        BigEndian::write_u32(&mut write[l..], n);
    });
    if success {
        write.resize(l0);
        server_auth_request_success(write);
    }
    Ok(success)
}

fn server_accept_service(banner: Option<&str>,
                         methods: auth::MethodSet,
                         buffer: &mut CryptoVec)
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
        current: None,
        rejection_count: 0,
    }
}


fn server_auth_request_success(buffer: &mut CryptoVec) {

    push_packet!(buffer, {
        buffer.push(msg::USERAUTH_SUCCESS);
    })
}

/*fn server_send_pk_ok(buffer: &mut CryptoVec, auth_request: &mut AuthRequest) {
}*/

fn server_confirm_channel_open(buffer: &mut CryptoVec, channel: &Channel, config: &super::Config) {

    push_packet!(buffer, {
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel); // remote channel number.
        buffer.push_u32_be(channel.sender_channel); // our channel number.
        buffer.push_u32_be(config.window_size);
        buffer.push_u32_be(config.maximum_packet_size);
    });
}
