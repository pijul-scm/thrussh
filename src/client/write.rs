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
use rand;
use rand::Rng;
use super::super::negociation;
use super::super::cipher::CipherT;


impl Encrypted {
    pub fn client_send_signature(&mut self,
                                 write_buffer: &mut SSHBuffer,
                                 auth_request: AuthRequest,
                                 config: &super::Config,
                                 buffer: &mut CryptoBuf,
                                 buffer2: &mut CryptoBuf)
                                 -> Result<(), Error> {

        buffer.clear();

        buffer.extend_ssh_string(self.session_id.as_bytes());
        let i0 = buffer.len();

        buffer.push(msg::USERAUTH_REQUEST);
        buffer.extend_ssh_string(b"pe");
        buffer.extend_ssh_string(b"ssh-connection");

        buffer.extend_ssh_string(b"publickey");
        buffer.push(1); // This is a probe
        buffer.extend_ssh_string(config.keys[0].name().as_bytes());
        config.keys[0].public_host_key.extend_pubkey(buffer);

        // Extend with signature.
        debug!("========== signing");
        buffer2.clear();
        config.keys[0].add_signature(buffer2, buffer.as_slice());
        buffer.extend(buffer2.as_slice());

        // Send
        self.cipher.write(&(buffer.as_slice())[i0..], write_buffer); // Skip the session id.

        self.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
        Ok(())
    }

    pub fn client_waiting_auth_request(&mut self,
                                       write_buffer: &mut SSHBuffer,
                                       auth_request: AuthRequest,
                                       auth_method: &Option<auth::Method>,
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
            Some(auth::Method::Pubkey { ref user, ref pubkey, .. }) => {
                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(b"ssh-connection");
                buffer.extend_ssh_string(b"publickey");
                buffer.push(0); // This is a probe
                buffer.extend_ssh_string(pubkey.name().as_bytes());
                pubkey.extend_pubkey(buffer);
                true
            }
            _ => false,
        };
        if method_ok {
            debug!("method ok");
            self.cipher.write(buffer.as_slice(), write_buffer);
            self.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
        } else {
            // In this case, the caller should call set_method() to
            // supply an alternative authentication method (possibly
            // requiring user input).
            debug!("method not ok: {:?}", auth_method);
            self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
        }
    }

    pub fn client_waiting_channel_open(&mut self,
                                       write_buffer: &mut SSHBuffer,
                                       config: &super::Config,
                                       buffer: &mut CryptoBuf)
                                       -> Result<(), Error> {
        // The server is waiting for our CHANNEL_OPEN.
        let mut sender_channel = 0;
        while self.channels.contains_key(&sender_channel) || sender_channel == 0 {
            sender_channel = rand::thread_rng().gen()
        }
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN);
        buffer.extend_ssh_string(b"channel name");
        buffer.push_u32_be(sender_channel); // sender channel id.
        buffer.push_u32_be(config.window_size); // window.
        buffer.push_u32_be(config.maxpacket); // max packet size.
        // Send
        self.cipher.write(buffer.as_slice(), write_buffer);

        self.state = Some(EncryptedState::ChannelOpenConfirmation(ChannelParameters {
            recipient_channel: 0,
            sender_channel: sender_channel,
            sender_window_size: config.window_size,
            recipient_window_size: 0,
            sender_maximum_packet_size: config.maxpacket,
            recipient_maximum_packet_size: 0,
        }));
        Ok(())
    }
    pub fn client_write_rekey<W: Write>(&mut self,
                                        stream: &mut W,
                                        buffers: &mut SSHBuffers,
                                        rekey: Kex,
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
                              mut kexdh: KexDh)
                              -> Result<(), Error> {
        buffer.clear();
        let kex = try!(super::super::kex::Algorithm::client_dh(kexdh.names.kex,
                                                               &mut kexdh.exchange,
                                                               buffer));

        self.cipher.write(buffer.as_slice(), write_buffer);

        self.rekey = Some(Kex::KexDhDone(KexDhDone {
            exchange: kexdh.exchange,
            kex: kex,
            names: kexdh.names,
            session_id: kexdh.session_id,
        }));
        Ok(())
    }
}
