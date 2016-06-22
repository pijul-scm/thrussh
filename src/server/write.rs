use super::super::msg;
use super::super::kex;
use super::*;
use super::super::{CryptoBuf, KexDhDone, Encrypted, ChannelParameters, complete_packet};
use super::super::auth;

impl ServerSession {

    pub fn cleartext_kex_ecdh_reply(&mut self,
                                    kexdhdone: &KexDhDone,
                                    hash: &kex::Digest) {
        // ECDH Key exchange.
        // http://tools.ietf.org/html/rfc5656#section-4
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::KEX_ECDH_REPLY);
        kexdhdone.key.public_host_key.extend_pubkey(&mut self.buffers.write.buffer);
        // Server ephemeral
        self.buffers.write.buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
        // Hash signature
        kexdhdone.key.add_signature(&mut self.buffers.write.buffer, hash.as_bytes());
        //
        complete_packet(&mut self.buffers.write.buffer, 0);
        self.buffers.write.seqn += 1;
    }
    pub fn cleartext_send_newkeys(&mut self) {
        // Sending the NEWKEYS packet.
        // https://tools.ietf.org/html/rfc4253#section-7.3
        // buffer.clear();
        let pos = self.buffers.write.buffer.len();
        self.buffers.write.buffer.extend(b"\0\0\0\0\0");
        self.buffers.write.buffer.push(msg::NEWKEYS);
        complete_packet(&mut self.buffers.write.buffer, pos);
        self.buffers.write.seqn += 1;
    }

    pub fn accept_service(&mut self,
                          banner: Option<&str>,
                          methods: auth::Methods,
                          enc: &mut Encrypted,
                          buffer: &mut CryptoBuf)
                          -> AuthRequest {
        buffer.clear();
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
        enc.cipher.write_server_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
        self.buffers.write.seqn += 1;

        if let Some(ref banner) = banner {

            buffer.clear();
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");

            enc.cipher
               .write_server_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
            self.buffers.write.seqn += 1;
        }

        AuthRequest {
            methods: methods,
            partial_success: false, // not used immediately anway.
            public_key: CryptoBuf::new(),
            public_key_algorithm: CryptoBuf::new(),
            sent_pk_ok: false,
            public_key_is_ok: false
        }
    }

    pub fn reject_auth_request(&mut self,
                               enc: &mut Encrypted,
                               buffer: &mut CryptoBuf,
                               auth_request: &AuthRequest) {
        buffer.clear();
        buffer.push(msg::USERAUTH_FAILURE);

        buffer.extend_list(auth_request.methods);
        buffer.push(if auth_request.partial_success {
            1
        } else {
            0
        });

        enc.cipher.write_server_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);

        self.buffers.write.seqn += 1;
    }

    pub fn confirm_channel_open(&mut self,
                                enc: &mut Encrypted,
                                buffer: &mut CryptoBuf,
                                channel: ChannelParameters) {
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel);
        buffer.push_u32_be(channel.sender_channel);
        buffer.push_u32_be(channel.initial_window_size);
        buffer.push_u32_be(channel.maximum_packet_size);
        enc.cipher.write_server_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);

        self.buffers.write.seqn += 1;
        enc.channels.insert(channel.sender_channel,
                            channel);
    }

    pub fn send_pk_ok(&mut self,
                      enc: &mut Encrypted,
                      buffer: &mut CryptoBuf,
                      auth_request: &mut AuthRequest) {
        buffer.clear();
        buffer.push(msg::USERAUTH_PK_OK);
        buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
        buffer.extend_ssh_string(auth_request.public_key.as_slice());
        enc.cipher
            .write_server_packet(self.buffers.write.seqn, buffer.as_slice(), &mut self.buffers.write.buffer);
        self.buffers.write.seqn += 1;
        auth_request.sent_pk_ok = true;
    }
    /*
    pub fn flush_channels(&mut self,
                          enc: &mut Encrypted<S, EncryptedState>,
                          // channel_nums: &mut HashSet<u32>,
                          buffer: &mut CryptoBuf) {

        for recip_channel in enc.pending_messages.drain() {

            if let Some(ref mut channel) = enc.channels.get_mut(&recip_channel) {

                if channel.stdout.len() > 0 {
                    buffer.clear();
                    buffer.push(msg::CHANNEL_DATA);
                    buffer.push_u32_be(channel.parameters.recipient_channel);
                    buffer.extend_ssh_string(channel.stdout.as_slice());
                    channel.stdout.clear();

                    enc.cipher.write_server_packet(self.buffers.sent_seqn,
                                                   buffer.as_slice(),
                                                   &mut self.buffers.write_buffer);

                    self.buffers.sent_seqn += 1;
                }
                if channel.stderr.len() > 0 {
                    buffer.clear();
                    buffer.push(msg::CHANNEL_EXTENDED_DATA);
                    buffer.push_u32_be(channel.parameters.recipient_channel);
                    buffer.push_u32_be(SSH_EXTENDED_DATA_STDERR);
                    buffer.extend_ssh_string(channel.stderr.as_slice());
                    channel.stderr.clear();

                    enc.cipher.write_server_packet(self.buffers.sent_seqn,
                                                   buffer.as_slice(),
                                                   &mut self.buffers.write_buffer);

                    self.buffers.sent_seqn += 1;
                }
            }
        }

    }
*/
}
