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
use super::super::*;
use super::*;
use msg;
use encoding::{Encoding, Reader};
use auth::*;
use key::Verify;
use negotiation;
use negotiation::Select;
use futures::{Async, Future};
use futures;
use futures::Poll;

impl Session {
    #[doc(hidden)]
    /// Returns false iff a request was rejected.
    pub fn server_read_encrypted<H: Handler>
        (mut self,
         handler: H,
         buf: &[u8])
         -> Result<PendingFuture<H>, HandlerError<H::Error>> {

            debug!("read_encrypted");
            // Either this packet is a KEXINIT, in which case we start a key re-exchange.

            let mut enc = self.0.encrypted.take().unwrap();
            if buf[0] == msg::KEXINIT {
                // If we're not currently rekeying, but buf is a rekey request
                if let Some(exchange) = enc.exchange.take() {
                    let kexinit = KexInit::received_rekey(
                        exchange,
                        try!(negotiation::Server::read_kex(buf, &self.0.config.as_ref().preferred)),
                        &enc.session_id
                    );
                    self.0.kex = Some(try!(kexinit.server_parse(self.0.config.as_ref(),
                                                                &self.0.rng,
                                                                &mut self.0.cipher,
                                                                buf,
                                                                &mut self.0.write_buffer)));
                }
                self.0.encrypted = Some(enc);
                return Ok(PendingFuture::Ok { handler: handler, session: self });
            }
            // If we've successfully read a packet.
            // debug!("state = {:?}, buf = {:?}", self.0.state, buf);
            let mut is_authenticated = false;
            let state = enc.state.take();
            debug!("state = {:?} {:?} {:?}",
                   state,
                   buf[0],
                   msg::SERVICE_REQUEST);
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
                        let auth_request =
                            try!(enc.server_read_auth_request(handler,
                                                              buf,
                                                              &mut self.0.auth_user,
                                                              auth_request));
                        self.0.encrypted = Some(enc);
                        return Ok(PendingFuture::ReadAuthRequest {
                            session: self,
                            auth_request: auth_request
                        })
                    } else if buf[0] == msg::USERAUTH_INFO_RESPONSE {
                        let auth_request = try!(enc.read_userauth_info_response(handler,
                                                                                &mut self.0.auth_user,
                                                                                auth_request,
                                                                                buf));
                        self.0.encrypted = Some(enc);
                        return Ok(PendingFuture::ReadAuthRequest {
                            session: self,
                            auth_request: auth_request
                        })
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
            self.0.encrypted = Some(enc);
            if is_authenticated {
                let auth = self.server_read_authenticated(handler, buf).unwrap();
                Ok(PendingFuture::Authenticated(auth))
            } else {
                Ok(PendingFuture::Ok { handler: handler, session: self })
            }
        }

    fn server_read_authenticated<H: Handler>
        (mut self,
         handler: H,
         buf: &[u8])
         -> Result<Authenticated<H>, HandlerError<H::Error>> {
            debug!("authenticated buf = {:?}", buf);
            match buf[0] {
                msg::CHANNEL_OPEN => {
                    Ok(Authenticated::FutureUnit(try!(self.server_handle_channel_open(handler, buf))))
                }
                msg::CHANNEL_CLOSE => {
                    let mut r = buf.reader(1);
                    let channel_num = ChannelId(try!(r.read_u32()));
                    if let Some(ref mut enc) = self.0.encrypted {
                        enc.channels.remove(&channel_num);
                    }
                    debug!("handler.channel_close {:?}", channel_num);
                    Ok(Authenticated::future_unit(handler.channel_close(channel_num, self)))
                }
                msg::CHANNEL_EOF => {
                    let mut r = buf.reader(1);
                    let channel_num = ChannelId(try!(r.read_u32()));
                    debug!("handler.channel_eof {:?}", channel_num);
                    Ok(Authenticated::future_unit(handler.channel_eof(channel_num, self)))
                }
                msg::CHANNEL_EXTENDED_DATA |
                msg::CHANNEL_DATA => {
                    let mut r = buf.reader(1);
                    let channel_num = ChannelId(try!(r.read_u32()));

                    let ext = if buf[0] == msg::CHANNEL_DATA {
                        None
                    } else {
                        Some(try!(r.read_u32()))
                    };
                    debug!("handler.data {:?} {:?}", ext, channel_num);
                    let data = if let Some(ref mut enc) = self.0.encrypted {

                        let data = try!(r.read_string());
                        if let Some(channel) = enc.channels.get_mut(&channel_num) {
                            // Ignore extra data.
                            // https://tools.ietf.org/html/rfc4254#section-5.2
                            if data.len() as u32 <= channel.sender_window_size {
                                channel.sender_window_size -= data.len() as u32;
                            }
                        } else {
                            return Err(HandlerError::Error(Error::WrongChannel));
                        }
                        let window_size = self.0.config.window_size;
                        enc.adjust_window_size(channel_num, data, window_size);
                        data

                    } else {
                        unreachable!()
                    };
                    if let Some(ext) = ext {
                        Ok(Authenticated::future_unit(
                            handler.extended_data(channel_num, ext, &data, self))
                        )
                    } else {
                        Ok(Authenticated::future_unit(handler.data(channel_num, &data, self)))
                    }
                }

                msg::CHANNEL_WINDOW_ADJUST => {
                    let mut r = buf.reader(1);
                    let channel_num = ChannelId(try!(r.read_u32()));
                    let amount = try!(r.read_u32());
                    if let Some(ref mut enc) = self.0.encrypted {
                        if let Some(channel) = enc.channels.get_mut(&channel_num) {
                            channel.recipient_window_size += amount;
                        } else {
                            return Err(HandlerError::Error(Error::WrongChannel));
                        }
                    }
                    debug!("handler.window_adjusted {:?}", channel_num);
                    Ok(Authenticated::future_unit(handler.window_adjusted(channel_num, self)))
                }

                msg::CHANNEL_REQUEST => {
                    let mut r = buf.reader(1);
                    let channel_num = ChannelId(try!(r.read_u32()));
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
                            debug!("handler.pty_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(handler.pty_request(channel_num,
                                                                             term,
                                                                             col_width,
                                                                             row_height,
                                                                             pix_width,
                                                                             pix_height,
                                                                             &modes[0..i],
                                                                             self)))
                        }
                        b"x11-req" => {
                            let single_connection = try!(r.read_byte()) != 0;
                            let x11_auth_protocol = try!(std::str::from_utf8(try!(r.read_string())));
                            let x11_auth_cookie = try!(std::str::from_utf8(try!(r.read_string())));
                            let x11_screen_number = try!(r.read_u32());
                            debug!("handler.x11_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(handler.x11_request(channel_num,
                                                                             single_connection,
                                                                             x11_auth_protocol,
                                                                             x11_auth_cookie,
                                                                             x11_screen_number,
                                                                             self)))
                        }
                        b"env" => {
                            let env_variable = try!(std::str::from_utf8(try!(r.read_string())));
                            let env_value = try!(std::str::from_utf8(try!(r.read_string())));
                            debug!("handler.env_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(
                                handler.env_request(channel_num, env_variable, env_value, self)
                            ))
                        }
                        b"shell" => {
                            debug!("handler.shell_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(handler.shell_request(channel_num, self)))
                        }
                        b"exec" => {
                            let req = try!(r.read_string());
                            debug!("handler.exec_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(handler.exec_request(channel_num, req, self)))
                        }
                        b"subsystem" => {
                            let name = try!(std::str::from_utf8(try!(r.read_string())));
                            debug!("handler.subsystem_request {:?}", channel_num);
                            Ok(Authenticated::future_unit(
                                handler.subsystem_request(channel_num, name, self)
                            ))
                        }
                        b"window_change" => {
                            let col_width = try!(r.read_u32());
                            let row_height = try!(r.read_u32());
                            let pix_width = try!(r.read_u32());
                            let pix_height = try!(r.read_u32());
                            debug!("handler.window_change {:?}", channel_num);
                            Ok(Authenticated::future_unit(handler.window_change_request(channel_num,
                                                                                       col_width,
                                                                                       row_height,
                                                                                       pix_width,
                                                                                       pix_height,
                                                                                       self)))
                        }
                        b"signal" => {
                            try!(r.read_byte()); // should be 0.
                            let signal_name = try!(Sig::from_name(try!(r.read_string())));
                            debug!("handler.signal {:?} {:?}", channel_num, signal_name);
                            Ok(Authenticated::future_unit(
                                handler.signal(channel_num, signal_name, self)
                            ))
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
                            Ok(Authenticated::FutureUnit(FutureUnit::Done(futures::done(Ok((handler, self))))))
                        }
                    }
                }
                msg::GLOBAL_REQUEST => {
                    let mut r = buf.reader(1);
                    let req_type = try!(r.read_string());
                    self.0.wants_reply = try!(r.read_byte()) != 0;
                    match req_type {
                        b"tcpip-forward" => {
                            let address = try!(std::str::from_utf8(try!(r.read_string())));
                            let port = try!(r.read_u32());
                            debug!("handler.tcpip_forward {:?} {:?}", address, port);
                            Ok(Authenticated::Forward(Forward {
                                forward: handler.tcpip_forward(address, port, self),
                            }))
                        }
                        b"cancel-tcpip-forward" => {
                            let address = try!(std::str::from_utf8(try!(r.read_string())));
                            let port = try!(r.read_u32());
                            debug!("handler.cancel_tcpip_forward {:?} {:?}", address, port);
                            Ok(Authenticated::Forward(Forward {
                                forward: handler.cancel_tcpip_forward(address, port, self),
                            }))
                        }
                        _ => {
                            if let Some(ref mut enc) = self.0.encrypted {
                                push_packet!(enc.write, {
                                    enc.write.push(msg::REQUEST_FAILURE);
                                });
                            }
                            Ok(Authenticated::FutureUnit(FutureUnit::Done(futures::done(Ok((handler, self))))))
                        }
                    }
                }
                m => {
                    debug!("unknown message received: {:?}", m);
                    Ok(Authenticated::FutureUnit(FutureUnit::Done(futures::done(Ok((handler, self))))))
                }
            }
        }

    fn server_handle_channel_open<H: Handler>
        (mut self,
         handler: H,
         buf: &[u8])
         -> Result<FutureUnit<H>, HandlerError<H::Error>> {

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
            Ok(match typ {
                b"session" => {
                    self.confirm_channel_open(channel);
                    FutureUnit::H(handler.channel_open_session(sender_channel, self))
                }
                b"x11" => {
                    self.confirm_channel_open(channel);
                    let a = try!(std::str::from_utf8(try!(r.read_string())));
                    let b = try!(r.read_u32());
                    FutureUnit::H(handler.channel_open_x11(sender_channel, a, b, self))
                }
                b"direct-tcpip" => {
                    self.confirm_channel_open(channel);
                    let a = try!(std::str::from_utf8(try!(r.read_string())));
                    let b = try!(r.read_u32());
                    let c = try!(std::str::from_utf8(try!(r.read_string())));
                    let d = try!(r.read_u32());
                    FutureUnit::H(handler.channel_open_direct_tcpip(sender_channel, a, b, c, d, self))
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
                    FutureUnit::Done(futures::done(Ok((handler, self))))
                }
            })
        }
    fn confirm_channel_open(&mut self, channel: Channel) {
        if let Some(ref mut enc) = self.0.encrypted {
            server_confirm_channel_open(&mut enc.write, &channel, self.0.config.as_ref());
            enc.channels.insert(channel.sender_channel, channel);
            enc.state = Some(EncryptedState::Authenticated);
        }
    }
}

pub enum Authenticated<H: Handler> {
    FutureUnit(FutureUnit<H>),
    Forward(Forward<H>),
}

impl<H: Handler> Authenticated<H> {
    pub fn poll(&mut self) -> Poll<(H, Session), HandlerError<H::Error>> {
        match *self {
            Authenticated::FutureUnit(ref mut a) => a.poll(),
            Authenticated::Forward(ref mut a) => a.poll(),
        }
    }
}

impl<H: Handler> Authenticated<H> {
    fn future_unit(h: H::FutureUnit) -> Self {
        Authenticated::FutureUnit(FutureUnit::H(h))
    }
}

pub enum FutureUnit<H: Handler> {
    H(H::FutureUnit),
    Done(futures::Done<(H, Session), HandlerError<H::Error>>),
}
impl<H: Handler> Future for FutureUnit<H> {
    type Item = (H, Session);
    type Error = HandlerError<H::Error>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            FutureUnit::H(ref mut a) => a.poll().map_err(HandlerError::Handler),
            FutureUnit::Done(ref mut a) => a.poll(),
        }
    }
}

pub struct Forward<H: Handler> {
    forward: H::FutureBool,
}

impl<H: Handler> Forward<H> {
    pub fn poll(&mut self) -> Poll<(H, Session), HandlerError<H::Error>> {
        let (handler, mut session, result) = try_ready!(self.forward.poll().map_err(HandlerError::Handler));
        if let Some(ref mut enc) = session.0.encrypted {
            if result {
                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
            } else {
                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
            }
        }
        Ok(Async::Ready((handler, session)))
    }
}

pub enum ReadAuthRequest<H: Handler> {
    Req {
        future: FutureAuth<H>,
        auth_request: Option<AuthRequest>,
    },
    Reject(Option<H>),
    Accept(Option<H>),
    UnsupportedMethod(Option<H>),
}

pub enum FutureAuth<H: Handler> {
    Password(H::FutureAuth),
    Pubkey {
        validate: ValidatePubkey<H>,
        sig: Vec<u8>,
        init: Vec<u8>,
        key: key::PublicKey,
    },
    PubkeyProbe {
        probe: H::FutureAuth,
        pubkey_algo: Vec<u8>,
        pubkey_key: Vec<u8>,
        key: key::PublicKey,
    },
    KeyboardInteractive { ki: H::FutureAuth },
}

pub enum ValidatePubkey<H: Handler> {
    Valid(Option<H>),
    Future(H::FutureAuth),
    Invalid(Option<H>),
}

impl<H: Handler> ReadAuthRequest<H> {
    pub fn poll(&mut self,
                enc: &mut Encrypted,
                auth_user: &mut String,
                buffer: &mut CryptoVec)
                -> Poll<(H, Auth), HandlerError<H::Error>> {
        match *self {
            ReadAuthRequest::Req { ref mut future, ref mut auth_request } => {
                match *future {
                    FutureAuth::Password(ref mut fut) => {
                        debug!("ReadAuthRequest.poll(): Password");
                        let (handler, auth) = try_ready!(fut.poll().map_err(HandlerError::Handler));
                        if let Auth::Accept = auth {
                            server_auth_request_success(&mut enc.write);
                            enc.state = Some(EncryptedState::Authenticated);
                            Ok(Async::Ready((handler, Auth::Accept)))
                        } else {
                            auth_user.clear();
                            let mut auth_request = auth_request.take().unwrap();
                            auth_request.methods = auth_request.methods - PASSWORD;
                            auth_request.partial_success = false;
                            enc.reject_auth_request(auth_request);
                            Ok(Async::Ready((handler, Auth::Reject)))
                        }
                    }
                    FutureAuth::Pubkey { ref mut validate, ref sig, ref init, ref key } => {
                        debug!("ReadAuthRequest.poll(): Pubkey");
                        let (handler, is_valid) = match *validate {
                            ValidatePubkey::Valid(ref mut h) => (h.take().unwrap(), true),
                            ValidatePubkey::Future(ref mut h) => {
                                let (handler, auth) = try_ready!(h.poll().map_err(HandlerError::Handler));
                                (handler, auth == Auth::Accept)
                            }
                            ValidatePubkey::Invalid(ref mut h) => (h.take().unwrap(), false),
                        };
                        if is_valid {
                            buffer.clear();
                            buffer.extend_ssh_string(enc.session_id.as_ref());
                            buffer.extend(init);
                            // Verify signature.
                            if key.verify_detached(buffer, sig) {
                                debug!("signature verified");
                                server_auth_request_success(&mut enc.write);
                                enc.state = Some(EncryptedState::Authenticated);
                                return Ok(Async::Ready((handler, Auth::Accept)));
                            }
                        }
                        Ok(Async::Ready((handler, Auth::Reject)))
                    }
                    FutureAuth::PubkeyProbe { ref mut probe,
                                              ref pubkey_algo,
                                              ref pubkey_key,
                                              .. } => {
                        debug!("ReadAuthRequest.poll(): PubkeyProbe");
                        let (handler, auth) = try_ready!(probe.poll().map_err(HandlerError::Handler));
                        if let Auth::Accept = auth {

                            let mut public_key = CryptoVec::new();
                            public_key.extend(pubkey_key);

                            let mut algo = CryptoVec::new();
                            algo.extend(pubkey_algo);

                            push_packet!(enc.write, {
                                enc.write.push(msg::USERAUTH_PK_OK);
                                enc.write.extend_ssh_string(&pubkey_algo);
                                enc.write.extend_ssh_string(&pubkey_key);
                            });

                            let mut auth_request = auth_request.take().unwrap();
                            auth_request.current = Some(CurrentRequest::PublicKey {
                                key: public_key,
                                algo: algo,
                                sent_pk_ok: true,
                            });

                            enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                            Ok(Async::Ready((handler, Auth::Accept)))
                        } else {
                            let mut auth_request = auth_request.take().unwrap();
                            auth_request.methods -= PUBLICKEY;
                            auth_request.partial_success = false;
                            auth_user.clear();
                            enc.reject_auth_request(auth_request);
                            Ok(Async::Ready((handler, Auth::Reject)))
                        }
                    }
                    FutureAuth::KeyboardInteractive { ref mut ki } => {

                        match try_ready!(ki.poll().map_err(HandlerError::Handler)) {
                            (handler, Auth::Accept) => {
                                server_auth_request_success(&mut enc.write);
                                enc.state = Some(EncryptedState::Authenticated);
                                Ok(Async::Ready((handler, Auth::Accept)))
                            }
                            (_, Auth::UnsupportedMethod) => unreachable!(),
                            (handler, Auth::Reject) => {
                                let mut auth_request = auth_request.take().unwrap();
                                auth_request.methods -= KEYBOARD_INTERACTIVE;
                                auth_request.partial_success = false;
                                auth_user.clear();
                                enc.reject_auth_request(auth_request);
                                Ok(Async::Ready((handler, Auth::Reject)))
                            }
                            (handler, Auth::Partial { name, instructions, prompts }) => {

                                push_packet!(enc.write, {
                                    enc.write.push(msg::USERAUTH_INFO_REQUEST);
                                    enc.write.extend_ssh_string(name.as_bytes());
                                    enc.write.extend_ssh_string(instructions.as_bytes());
                                    enc.write.extend_ssh_string(b""); // lang, should be empty
                                    enc.write.push_u32_be(prompts.len() as u32);
                                    for &(ref a, b) in prompts.iter() {
                                        enc.write.extend_ssh_string(a.as_bytes());
                                        enc.write.push(if b { 1 } else { 0 });
                                    }
                                });
                                let auth_request = auth_request.take().unwrap();
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                Ok(Async::Ready((handler, Auth::Partial {
                                    name: name,
                                    instructions: instructions,
                                    prompts: prompts,
                                })))
                            }
                        }

                    }
                }

            }
            ReadAuthRequest::Reject(ref mut h) => Ok(Async::Ready((h.take().unwrap(), Auth::Reject))),
            ReadAuthRequest::UnsupportedMethod(ref mut h) => Ok(Async::Ready((h.take().unwrap(), Auth::UnsupportedMethod))),
            ReadAuthRequest::Accept(ref mut h) => Ok(Async::Ready((h.take().unwrap(), Auth::Accept))),
        }
    }
}

impl Encrypted {
    /// Returns false iff the request was rejected.
    fn server_read_auth_request<H: Handler>
        (&mut self,
         handler: H,
         buf: &[u8],
         auth_user: &mut String,
         mut auth_request: AuthRequest)
         -> Result<ReadAuthRequest<H>, HandlerError<H::Error>> {

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

                    Ok(ReadAuthRequest::Req {
                        future: FutureAuth::Password(handler.auth_password(user, password)),
                        auth_request: Some(auth_request),
                    })

                } else if method == b"publickey" {

                    let is_real = try!(r.read_byte());
                    let pubkey_algo = try!(r.read_string());
                    let pubkey_key = try!(r.read_string());
                    match key::PublicKey::parse(pubkey_algo, pubkey_key) {
                        Ok(pubkey) => {
                            debug!("is_real = {:?}", is_real);

                            if is_real != 0 {

                                let pos0 = r.position;
                                let sent_pk_ok =
                                    if let Some(CurrentRequest::PublicKey { sent_pk_ok, .. }) =
                                    auth_request.current {
                                        sent_pk_ok
                                    } else {
                                        false
                                    };

                                let signature = try!(r.read_string());
                                let mut s = signature.reader(0);
                                // let algo_ =
                                try!(s.read_string());
                                let sig = try!(s.read_string());
                                let init = &buf[0..pos0];

                                let validate = if sent_pk_ok && user == auth_user {
                                    ValidatePubkey::Valid(Some(handler))
                                } else if auth_user.len() == 0 {
                                    auth_user.clear();
                                    auth_user.push_str(user);
                                    ValidatePubkey::Future(handler.auth_publickey(user, &pubkey))
                                } else {
                                    ValidatePubkey::Invalid(Some(handler))
                                };

                                Ok(ReadAuthRequest::Req {
                                    future: FutureAuth::Pubkey {
                                        validate: validate,
                                        sig: sig.to_vec(),
                                        init: init.to_vec(),
                                        key: pubkey,
                                    },
                                    auth_request: Some(auth_request),
                                })

                            } else {
                                auth_user.clear();
                                auth_user.push_str(user);

                                Ok(ReadAuthRequest::Req {
                                    future: FutureAuth::PubkeyProbe {
                                        probe: handler.auth_publickey(user, &pubkey),
                                        pubkey_algo: pubkey_algo.to_vec(),
                                        pubkey_key: pubkey_key.to_vec(),
                                        key: pubkey,
                                    },
                                    auth_request: Some(auth_request),
                                })
                            }
                        }
                        Err(Error::UnknownKey) => {
                            self.reject_auth_request(auth_request);
                            Ok(ReadAuthRequest::Reject(Some(handler)))
                        }
                        Err(e) => return Err(HandlerError::Error(e)),
                    }
                    // Other methods of the base specification are insecure or optional.
                } else if method == b"keyboard-interactive" {

                    auth_user.clear();
                    auth_user.push_str(user);
                    let _ = try!(r.read_string()); // language_tag, deprecated.
                    let submethods = try!(std::str::from_utf8(try!(r.read_string())));
                    debug!("{:?}", submethods);
                    auth_request.current = Some(CurrentRequest::KeyboardInteractive {
                        submethods: submethods.to_string(),
                    });
                    Ok(ReadAuthRequest::Req {
                        future: FutureAuth::KeyboardInteractive {
                            ki: handler.auth_keyboard_interactive(user, submethods, None),
                        },
                        auth_request: Some(auth_request),
                    })

                } else {
                    self.reject_auth_request(auth_request);
                    Ok(ReadAuthRequest::UnsupportedMethod(Some(handler)))
                }
            } else {
                // Unknown service
                Err(HandlerError::Error(Error::Inconsistent))
            }
        }

    fn read_userauth_info_response<H: Handler>
        (&mut self,
         handler: H,
         user: &mut String,
         auth_request: AuthRequest,
         b: &[u8])
         -> Result<ReadAuthRequest<H>, HandlerError<H::Error>> {

            let ki = if let Some(CurrentRequest::KeyboardInteractive { ref submethods }) =
                auth_request.current {
                    let mut r = b.reader(1);
                    let n = try!(r.read_u32());
                    let response = Response { pos: r, n: n };
                    handler.auth_keyboard_interactive(user, submethods, Some(response))
                } else {
                    return Ok(ReadAuthRequest::Reject(Some(handler)));
                };

            Ok(ReadAuthRequest::Req {
            future: FutureAuth::KeyboardInteractive { ki: ki },
            auth_request: Some(auth_request),
        })
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





fn server_accept_service(banner: Option<&str>,
                         methods: MethodSet,
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

fn server_confirm_channel_open(buffer: &mut CryptoVec, channel: &Channel, config: &Config) {

    push_packet!(buffer, {
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel); // remote channel number.
        buffer.push_u32_be(channel.sender_channel.0); // our channel number.
        buffer.push_u32_be(config.window_size);
        buffer.push_u32_be(config.maximum_packet_size);
    });
}
