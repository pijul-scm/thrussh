use super::super::msg;
use super::super::kex;
use super::*;
use super::super::*;
use super::super::complete_packet;
use super::super::negociation;

impl ServerSession {

    pub fn server_cleartext_kex_ecdh_reply(&mut self,
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
                                       write_buffer: &mut super::super::SSHBuffer) {
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel);
        buffer.push_u32_be(channel.sender_channel);
        buffer.push_u32_be(channel.initial_window_size);
        buffer.push_u32_be(channel.maximum_packet_size);
        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
        write_buffer.seqn += 1;
    }

    pub fn server_accept_service(&mut self,
                                 banner: Option<&str>,
                                 methods: auth::Methods,
                                 buffer: &mut CryptoBuf,
                                 write_buffer: &mut super::super::SSHBuffer)
                                 -> AuthRequest {
        buffer.clear();
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
        write_buffer.seqn += 1;

        if let Some(ref banner) = banner {

            buffer.clear();
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");

            self.cipher
               .write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
            write_buffer.seqn += 1;
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

    pub fn server_auth_request_success(&mut self, buffer:&mut CryptoBuf, write_buffer:&mut super::super::SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_SUCCESS);
        self.cipher.write_server_packet(write_buffer.seqn,
                                        buffer.as_slice(),
                                        &mut write_buffer.buffer);
        write_buffer.seqn += 1;
        self.state = Some(EncryptedState::WaitingChannelOpen);
    }

    pub fn server_reject_auth_request(&mut self,
                                      buffer: &mut CryptoBuf,
                                      auth_request: AuthRequest,
                                      write_buffer:&mut super::super::SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_FAILURE);

        buffer.extend_list(auth_request.methods);
        buffer.push(if auth_request.partial_success {
            1
        } else {
            0
        });

        self.cipher.write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);

        write_buffer.seqn += 1;
        self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
    }
    pub fn server_send_pk_ok(&mut self,
                             buffer: &mut CryptoBuf,
                             auth_request: &mut AuthRequest,
                             write_buffer: &mut super::super::SSHBuffer) {
        buffer.clear();
        buffer.push(msg::USERAUTH_PK_OK);
        buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
        buffer.extend_ssh_string(auth_request.public_key.as_slice());
        self.cipher
            .write_server_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
        write_buffer.seqn += 1;
        auth_request.sent_pk_ok = true;
    }



    pub fn server_write_rekey(&mut self, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf, buffers:&mut SSHBuffers, keys:&[key::Algorithm], rekey: Kex) -> Result<(),Error> {
        match rekey {
            Kex::KexInit(mut kexinit) => {
                if !kexinit.sent {
                    debug!("sending kexinit");
                    buffer.clear();
                    negociation::write_kex(keys, buffer);
                    kexinit.exchange.server_kex_init.extend(buffer.as_slice());

                    self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                    buffers.write.seqn += 1;
                    kexinit.sent = true;
                }
                if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                    debug!("rekey ok");
                    self.rekey = Some(Kex::KexDh(KexDh {
                        exchange: kexinit.exchange,
                        kex: kex,
                        key: key,
                        cipher: cipher,
                        mac: mac,
                        follows: follows,
                        session_id: kexinit.session_id,
                    }))
                } else {
                    debug!("still kexinit");
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            },
            Kex::KexDh(kexinit) => {
                // Nothing to do here.
                self.rekey = Some(Kex::KexDh(kexinit))
            },
            Kex::KexDhDone(kexdhdone) => {

                debug!("kexdhdone: {:?}", kexdhdone);

                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                    &kexdhdone.exchange,
                                                                    buffer));

                // http://tools.ietf.org/html/rfc5656#section-4
                buffer.clear();
                buffer.push(msg::KEX_ECDH_REPLY);
                kexdhdone.key.public_host_key.extend_pubkey(buffer);
                // Server ephemeral
                buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
                // Hash signature
                kexdhdone.key.add_signature(buffer, hash.as_bytes());
                //
                self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                buffers.write.seqn += 1;

                
                buffer.clear();
                buffer.push(msg::NEWKEYS);
                self.cipher.write_server_packet(buffers.write.seqn, buffer.as_slice(), &mut buffers.write.buffer);
                buffers.write.seqn += 1;

                debug!("new keys");
                let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                self.rekey = Some(Kex::NewKeys(new_keys));

            },
            Kex::NewKeys(n) => {
                self.rekey = Some(Kex::NewKeys(n));
            }
        }
        Ok(())
    }


}
