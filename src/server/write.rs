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
use super::super::complete_packet;
use super::super::negociation;
use super::super::cipher::CipherT;
use state::*;
use auth::*;
use sshbuffer::{SSHBuffer};

impl Session {
    #[doc(hidden)]
    pub fn server_cleartext_kex_ecdh_reply(&mut self, kexdhdone: &KexDhDone, hash: &kex::Digest) {
        // ECDH Key exchange.
        // http://tools.ietf.org/html/rfc5656#section-4
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::KEX_ECDH_REPLY);
        kexdhdone.names.key.public_host_key.extend_pubkey(&mut self.buffers.write.buffer);
        // Server ephemeral
        self.buffers.write.buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
        // Hash signature
        kexdhdone.names.key.add_signature(&mut self.buffers.write.buffer, hash.as_bytes());
        //
        complete_packet(&mut self.buffers.write.buffer, 0);
        self.buffers.write.seqn += 1;
    }
    #[doc(hidden)]
    pub fn server_cleartext_send_newkeys(&mut self) {
        // Sending the NEWKEYS packet.
        // https://tools.ietf.org/html/rfc4253#section-7.3
        // buffer.clear();
        let pos = self.buffers.write.buffer.len();
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::NEWKEYS);
        complete_packet(&mut self.buffers.write.buffer, pos);
        self.buffers.write.seqn += 1;
    }
}

impl Encrypted {
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
        self.cipher.write(buffer.as_slice(), write_buffer);
    }

    pub fn server_accept_service(&mut self,
                                 banner: Option<&str>,
                                 methods: auth::Methods,
                                 buffer: &mut CryptoBuf,
                                 write_buffer: &mut SSHBuffer)
                                 -> AuthRequest {
        buffer.clear();
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
        self.cipher.write(buffer.as_slice(), write_buffer);

        if let Some(ref banner) = banner {

            buffer.clear();
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");

            self.cipher.write(buffer.as_slice(), write_buffer);
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

    pub fn server_auth_request_success(&mut self,
                                       buffer: &mut CryptoBuf,
                                       write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_SUCCESS);
        self.cipher.write(buffer.as_slice(), write_buffer);
        self.state = Some(EncryptedState::WaitingConnection);
    }

    pub fn server_reject_auth_request(&mut self,
                                      buffer: &mut CryptoBuf,
                                      auth_request: AuthRequest,
                                      write_buffer: &mut SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_FAILURE);

        buffer.extend_list(auth_request.methods);
        buffer.push(if auth_request.partial_success {
            1
        } else {
            0
        });

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

    pub fn write_kexinit(&mut self,
                         preferred: &negociation::Preferred,
                         kexinit: &mut KexInit,
                         buffer: &mut CryptoBuf,
                         write_buffer: &mut SSHBuffer) {
        buffer.clear();
        negociation::write_kex(preferred, buffer);
        kexinit.exchange.server_kex_init.extend(buffer.as_slice());
        self.cipher.write(buffer.as_slice(), write_buffer);
    }
}
