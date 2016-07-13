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
use super::super::*;
use std::io::Write;
use super::super::msg;
use super::super::auth::AuthRequest;
use super::super::negociation;
use super::super::cipher::CipherT;
use state::*;
use sshbuffer::{SSHBuffer,SSHBuffers};
use key::PubKey;
use negociation::Named;

const SSH_CONNECTION:&'static [u8] = b"ssh-connection";

impl Encrypted<&'static ()> {
    pub fn client_send_signature(&mut self,
                                 write_buffer: &mut SSHBuffer,
                                 auth_request: AuthRequest,
                                 method: &Option<auth::Method<key::Algorithm>>,
                                 buffer: &mut CryptoBuf,
                                 buffer2: &mut CryptoBuf) {

        match method {
            &Some(auth::Method::PublicKey { ref user, ref pubkey }) => {

                buffer.clear();
                
                buffer.extend_ssh_string(self.session_id.as_bytes());
                let i0 = buffer.len();

                buffer.push(msg::USERAUTH_REQUEST);
                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(SSH_CONNECTION);

                buffer.extend_ssh_string(b"publickey");
                buffer.push(1); // This is a probe
                buffer.extend_ssh_string(pubkey.name().as_bytes());
                
                pubkey.push_to(buffer);

                // Extend with signature.
                debug!("========== signing");
                buffer2.clear();
                pubkey.add_signature(buffer2, buffer.as_slice());
                buffer.extend(buffer2.as_slice());

                // Send
                self.cipher.write(&(buffer.as_slice())[i0..], write_buffer); // Skip the session id.

                self.state = Some(EncryptedState::AuthRequestAnswer(auth_request));
            },
            _ => { }
        }
    }

    pub fn client_waiting_auth_request(&mut self,
                                       write_buffer: &mut SSHBuffer,
                                       auth_request: AuthRequest,
                                       auth_method: &Option<auth::Method<key::Algorithm>>,
                                       buffer: &mut CryptoBuf) {
        // The server is waiting for our USERAUTH_REQUEST.
        buffer.clear();
        buffer.push(msg::USERAUTH_REQUEST);
        let method_ok = match *auth_method {
            Some(auth::Method::Password { ref user, ref password }) => {

                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(b"ssh-connection");
                buffer.extend_ssh_string(b"password");
                buffer.push(1);
                buffer.extend_ssh_string(password.as_bytes());
                true
            }
            Some(auth::Method::PublicKey { ref user, ref pubkey }) => {
                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(b"ssh-connection");
                buffer.extend_ssh_string(b"publickey");
                buffer.push(0); // This is a probe
                buffer.extend_ssh_string(pubkey.name().as_bytes());
                pubkey.push_to(buffer);
                true
            }
            _ => false,
        };
        if method_ok {
            debug!("method ok");
            self.cipher.write(buffer.as_slice(), write_buffer);
            self.state = Some(EncryptedState::AuthRequestAnswer(auth_request));
        } else {
            // In this case, the caller should call set_method() to
            // supply an alternative authentication method (possibly
            // requiring user input).
            debug!("method not ok: {:?}", auth_method);
            self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
        }
    }

    pub fn client_write_rekey<W: Write>(&mut self,
                                        stream: &mut W,
                                        buffers: &mut SSHBuffers,
                                        rekey: Kex<&'static ()>,
                                        config: &super::Config,
                                        buffer: &mut CryptoBuf)
                                        -> Result<(), Error> {

        debug!("rekeying, {:?}", rekey);
        match rekey {
            Kex::KexInit(mut kexinit) => {

                if !kexinit.sent {
                    buffer.clear();
                    negociation::write_kex(&config.preferred, buffer);
                    kexinit.exchange.client_kex_init.extend(buffer.as_slice());

                    self.cipher.write(buffer.as_slice(), &mut buffers.write);

                    try!(buffers.write_all(stream));
                    kexinit.sent = true;
                }
                if let Some(names) = kexinit.algo {
                    self.rekey = Some(Kex::KexDh(KexDh {
                        exchange: kexinit.exchange,
                        names: names,
                        key: super::UNIT,
                        session_id: kexinit.session_id,
                    }))
                } else {
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            }
            Kex::KexDh(kexdh) => {
                try!(self.client_write_kexdh(buffer, &mut buffers.write, kexdh));
                try!(buffers.write_all(stream));
            }
            Kex::NewKeys(mut newkeys) => {
                debug!("newkeys {:?}", newkeys);
                if !newkeys.sent {
                    self.cipher.write(&[msg::NEWKEYS], &mut buffers.write);
                    try!(buffers.write_all(stream));
                    newkeys.sent = true;
                }
                if !newkeys.received {
                    self.rekey = Some(Kex::NewKeys(newkeys))
                } else {
                    debug!("changing keys!");
                    self.exchange = Some(newkeys.exchange);
                    self.kex = newkeys.kex;
                    self.cipher = newkeys.cipher;
                    buffers.read.bytes = 0;
                    buffers.write.bytes = 0;
                }
            }
            state => self.rekey = Some(state),
        }
        Ok(())
    }

    pub fn client_write_kexdh(&mut self,
                              buffer: &mut CryptoBuf,
                              write_buffer: &mut SSHBuffer,
                              mut kexdh: KexDh<&()>)
                              -> Result<(), Error> {
        buffer.clear();
        let kex = try!(super::super::kex::Algorithm::client_dh(kexdh.names.kex,
                                                               &mut kexdh.exchange,
                                                               buffer));

        self.cipher.write(buffer.as_slice(), write_buffer);
        
        self.rekey = Some(Kex::KexDhDone(KexDhDone {
            exchange: kexdh.exchange,
            kex: kex,
            key: super::UNIT,
            names: kexdh.names,
            session_id: kexdh.session_id,
        }));
        Ok(())
    }
}
