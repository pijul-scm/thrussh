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
use super::super::msg;
use super::super::kex;
use super::*;
use super::super::*;
use super::super::negociation;
use super::super::cipher::CipherT;
use state::*;
use auth::*;
use sshbuffer::{SSHBuffer};
use key::PubKey;
use byteorder::{ByteOrder, BigEndian};



pub fn server_accept_service(banner: Option<&str>,
                             methods: auth::Methods,
                             buffer: &mut CryptoBuf)
                             -> AuthRequest {
    let i0 = buffer.len();
    buffer.extend(b"\0\0\0\0");
    buffer.push(msg::SERVICE_ACCEPT);
    buffer.extend_ssh_string(b"ssh-userauth");
    let i1 = buffer.len();
    {
        let buf = buffer.as_mut_slice();
        BigEndian::write_u32(&mut buf[i0..], (i1-i0-4) as u32)
    }
    
    if let Some(ref banner) = banner {
        
        buffer.extend(b"\0\0\0\0");
        buffer.push(msg::USERAUTH_BANNER);
        buffer.extend_ssh_string(banner.as_bytes());
        buffer.extend_ssh_string(b"");
        let i2 = buffer.len();
        {
            let buf = buffer.as_mut_slice();
            BigEndian::write_u32(&mut buf[i1..], (i2-i1-4) as u32)
        }
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




impl<'k> Encrypted<&'k key::Algorithm> {
    /*
    pub fn server_confirm_channel_open(&mut self,
                                       buffer: &mut CryptoBuf,
                                       channel: &ChannelParameters,
                                       config: &super::Config,
                                       write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel); // remote channel number.
        buffer.push_u32_be(channel.sender_channel); // our channel number.
        buffer.push_u32_be(config.window_size);
        buffer.push_u32_be(config.maximum_packet_size);
    }
     */

    /*
    pub fn server_auth_request_success(&mut self,
                                       buffer: &mut CryptoBuf,
                                       write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_SUCCESS);
        self.cipher.write(buffer.as_slice(), write_buffer);
        self.state = Some(EncryptedState::Authenticated);
    }

    pub fn server_reject_auth_request(&mut self,
                                      buffer: &mut CryptoBuf,
                                      auth_request: AuthRequest,
                                      write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_FAILURE);

        buffer.extend_list(auth_request.methods);
        buffer.push(if auth_request.partial_success { 1 } else { 0 });

        self.cipher.write(buffer.as_slice(), write_buffer);

        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
    }
    pub fn server_send_pk_ok(&mut self,
                             buffer: &mut CryptoBuf,
                             auth_request: &mut AuthRequest,
                             write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_PK_OK);
        buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
        buffer.extend_ssh_string(auth_request.public_key.as_slice());
        self.cipher.write(buffer.as_slice(), write_buffer);
        auth_request.sent_pk_ok = true;
    }
     */
}
