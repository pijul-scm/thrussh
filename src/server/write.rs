use super::super::msg;
use super::super::kex;
use super::super::key;
use super::super::negociation;
use super::*;
use super::super::sodium;
use super::super::{Error, CryptoBuf, Kex, KexInit, KexDh, KexDhDone, Encrypted, ChannelParameters, Channel};


use std::collections::HashSet;
use std::io::{Write};
use std;
use byteorder::{ByteOrder, BigEndian, WriteBytesExt};
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

fn complete_packet(buf: &mut CryptoBuf, off: usize) {

    let block_size = 8; // no MAC yet.
    let padding_len = {
        (block_size - ((buf.len() - off) % block_size))
    };
    let padding_len = if padding_len < 4 {
        padding_len + block_size
    } else {
        padding_len
    };
    let mac_len = 0;

    let packet_len = buf.len() - off - 4 + padding_len + mac_len;
    {
        let buf = buf.as_mut_slice();
        BigEndian::write_u32(&mut buf[off..], packet_len as u32);
        buf[off + 4] = padding_len as u8;
    }


    let mut padding = [0; 256];
    sodium::randombytes::into(&mut padding[0..padding_len]);

    buf.extend(&padding[0..padding_len]);

}

impl<T, S: super::Serve<T>> ServerSession<T, S> {

    pub fn cleartext_write_kex_init<W: Write>(&mut self,
                                          keys: &[key::Algorithm],
                                          mut kexinit: KexInit,
                                          stream: &mut W)
                                          -> Result<ServerState<S>, Error> {
        if !kexinit.sent {
            // println!("kexinit");
            self.buffers.write_buffer.extend(b"\0\0\0\0\0");
            negociation::write_kex(&keys, &mut self.buffers.write_buffer);

            {
                let buf = self.buffers.write_buffer.as_slice();
                kexinit.exchange.server_kex_init.extend(&buf[5..]);
            }

            complete_packet(&mut self.buffers.write_buffer, 0);
            self.buffers.sent_seqn += 1;
            try!(self.buffers.write_all(stream));
            kexinit.sent = true;
        }
        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
            Ok(ServerState::Kex(Kex::KexDh(KexDh {
                exchange: kexinit.exchange,
                kex: kex,
                key: key,
                cipher: cipher,
                mac: mac,
                follows: follows,
                session_id: kexinit.session_id,
            })))
        } else {
            Ok(ServerState::Kex(Kex::KexInit(kexinit)))
        }

    }
    pub fn cleartext_kex_ecdh_reply(&mut self,
                                    kexdhdone: &KexDhDone,
                                    hash: &kex::Digest) {
        // ECDH Key exchange.
        // http://tools.ietf.org/html/rfc5656#section-4
        self.buffers.write_buffer.extend(b"\0\0\0\0\0");
        self.buffers.write_buffer.push(msg::KEX_ECDH_REPLY);
        kexdhdone.key.write_pubkey(&mut self.buffers.write_buffer);
        // Server ephemeral
        self.buffers.write_buffer.extend_ssh_string(&kexdhdone.exchange.server_ephemeral);
        // Hash signature
        kexdhdone.key.add_signature(&mut self.buffers.write_buffer, hash.as_bytes());
        //
        complete_packet(&mut self.buffers.write_buffer, 0);
        self.buffers.sent_seqn += 1;
    }
    pub fn cleartext_send_newkeys(&mut self) {
        // Sending the NEWKEYS packet.
        // https://tools.ietf.org/html/rfc4253#section-7.3
        // buffer.clear();
        let pos = self.buffers.write_buffer.len();
        self.buffers.write_buffer.extend(b"\0\0\0\0\0");
        self.buffers.write_buffer.push(msg::NEWKEYS);
        complete_packet(&mut self.buffers.write_buffer, pos);
        self.buffers.sent_seqn += 1;
    }

    pub fn accept_service(&mut self,
                      banner: Option<&str>,
                      methods: auth::Methods,
                      enc: &mut Encrypted<S, super::EncryptedState>,
                      buffer: &mut CryptoBuf)
                      -> AuthRequest {
        buffer.clear();
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
        enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
        self.buffers.sent_seqn += 1;

        if let Some(ref banner) = banner {

            buffer.clear();
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");

            enc.cipher
               .write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
            self.buffers.sent_seqn += 1;
        }

        AuthRequest {
            methods: methods,
            partial_success: false, // not used immediately anway.
            public_key: CryptoBuf::new(),
            public_key_algorithm: CryptoBuf::new(),
            sent_pk_ok: false,
        }
    }

    pub fn reject_auth_request(&mut self,
                               enc: &mut Encrypted<S, super::EncryptedState>,
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

        enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);

        self.buffers.sent_seqn += 1;
    }

    pub fn confirm_channel_open(&mut self,
                                enc: &mut Encrypted<S, super::EncryptedState>,
                            buffer: &mut CryptoBuf,
                            channel: ChannelParameters,
                            server: S) {
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel);
        buffer.push_u32_be(channel.sender_channel);
        buffer.push_u32_be(channel.initial_window_size);
        buffer.push_u32_be(channel.maximum_packet_size);
        enc.cipher.write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);

        self.buffers.sent_seqn += 1;
        let buf_stdout = CryptoBuf::new();
        let buf_stderr = CryptoBuf::new();
        enc.channels.insert(channel.sender_channel,
                            Channel {
                                parameters: channel,
                                stdout: buf_stdout,
                                stderr: buf_stderr,
                                server: server,
                            });
    }

    pub fn send_pk_ok(&mut self,
                      enc: &mut Encrypted<S, super::EncryptedState>,
                  buffer: &mut CryptoBuf,
                  auth_request: &mut AuthRequest) {
        if !auth_request.sent_pk_ok {
            buffer.clear();
            buffer.push(msg::USERAUTH_PK_OK);
            buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
            buffer.extend_ssh_string(auth_request.public_key.as_slice());
            enc.cipher
                .write_server_packet(self.buffers.sent_seqn, buffer.as_slice(), &mut self.buffers.write_buffer);
            self.buffers.sent_seqn += 1;
            auth_request.sent_pk_ok = true;
        }
    }

    pub fn flush_channels(&mut self,
                          enc: &mut Encrypted<S, super::EncryptedState>,
                      channel_nums: &mut HashSet<u32>,
                      buffer: &mut CryptoBuf) {

        for recip_channel in channel_nums.drain() {

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
}
