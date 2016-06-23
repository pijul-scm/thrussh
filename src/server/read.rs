use super::*;
use super::super::*;

use super::super::msg;
use super::super::negociation;
use super::super::encoding::Reader;

use rand::{thread_rng, Rng};
use std;
use std::io::BufRead;
use byteorder::{ByteOrder, BigEndian, ReadBytesExt};


impl ServerSession {

    pub fn server_read_cleartext_kexinit<R: BufRead>(&mut self,
                                                     stream: &mut R,
                                                     mut kexinit: KexInit,
                                                     keys: &[key::Algorithm])
                                                     -> Result<bool, Error> {
        if kexinit.algo.is_none() {
            // read algo from packet.
            if self.buffers.read.len == 0 {
                try!(self.buffers.set_clear_len(stream));
            }
            if try!(self.buffers.read(stream)) {
                {
                    let payload = self.buffers.get_current_payload();
                    kexinit.algo = Some(try!(negociation::read_kex(payload, keys)));
                    kexinit.exchange.client_kex_init.extend(payload);
                }
                self.buffers.read.clear_incr();
                self.state = Some(ServerState::Kex(try!(kexinit.kexinit())));
                Ok(true)
            } else {
                // A complete packet could not be read, we need to read more.
                self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                Ok(false)
            }
        } else {
            self.state = Some(ServerState::Kex(try!(kexinit.kexinit())));
            Ok(true)
        }
    }
    pub fn server_read_cleartext_kexdh<R: BufRead>(&mut self, stream:&mut R, mut kexdh:KexDh, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {

        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }

        if try!(self.buffers.read(stream)) {

            let kex = {
                let payload = self.buffers.get_current_payload();
                debug!("payload = {:?}", payload);
                assert!(payload[0] == msg::KEX_ECDH_INIT);
                kexdh.exchange.client_ephemeral.extend(&payload[5..]);
                try!(kexdh.kex.server_dh(&mut kexdh.exchange, payload))
            };
            self.buffers.read.clear_incr();

            // Then, we fill the write buffer right away, so that we
            // can output it immediately when the time comes.
            let kexdhdone = KexDhDone {
                exchange: kexdh.exchange,
                kex: kex,
                key: kexdh.key,
                cipher: kexdh.cipher,
                mac: kexdh.mac,
                follows: kexdh.follows,
                session_id: kexdh.session_id,
            };

            let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key.public_host_key,
                                                                &kexdhdone.exchange,
                                                                buffer));
            self.server_cleartext_kex_ecdh_reply(&kexdhdone, &hash);
            self.server_cleartext_send_newkeys();

            self.state = Some(ServerState::Kex(Kex::NewKeys(kexdhdone.compute_keys(hash, buffer, buffer2))));
            // self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));

            Ok(true)

        } else {
            // not enough bytes.
            self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
            Ok(false)
        }
    }
    pub fn server_read_cleartext_newkeys<R:BufRead>(&mut self, stream:&mut R, newkeys: NewKeys) -> Result<bool, Error> {
        // We have sent a NEWKEYS packet, and are waiting to receive one. Is it this one?
        if self.buffers.read.len == 0 {
            try!(self.buffers.set_clear_len(stream));
        }
        if try!(self.buffers.read(stream)) {

            let payload_is_newkeys = self.buffers.get_current_payload()[0] == msg::NEWKEYS;
            if payload_is_newkeys {
                // Ok, NEWKEYS received, now encrypted.
                self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                self.buffers.read.clear_incr();
                Ok(true)
            } else {
                Err(Error::NewKeys)
            }
        } else {
            // Not enough bytes
            self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
            Ok(false)
        }
    }
        
}

impl Encrypted {

    pub fn server_read_encrypted<A:Authenticate, S:SSHHandler>(&mut self, config:&Config<A>, server:&mut S,
                                                               buf:&[u8], buffer:&mut CryptoBuf, write_buffer:&mut SSHBuffer) {
        // If we've successfully read a packet.
        debug!("buf = {:?}", buf);
        let state = std::mem::replace(&mut self.state, None);
        match state {
            Some(EncryptedState::WaitingServiceRequest) if buf[0] == msg::SERVICE_REQUEST => {

                let len = BigEndian::read_u32(&buf[1..]) as usize;
                let request = &buf[5..(5 + len)];
                debug!("request: {:?}", std::str::from_utf8(request));
                debug!("decrypted {:?}", buf);
                if request == b"ssh-userauth" {
                    self.state = Some(EncryptedState::ServiceRequest)
                } else {
                    self.state = Some(EncryptedState::WaitingServiceRequest)
                }
            }
            Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                if buf[0] == msg::USERAUTH_REQUEST {

                    self.state = Some(auth_request.read_auth_request(&config.auth, buf))

                } else {
                    // Wrong request
                    self.state = Some(EncryptedState::WaitingAuthRequest(auth_request))
                }
            }

            Some(EncryptedState::WaitingSignature(auth_request)) => {
                debug!("receiving signature, {:?}", buf);
                if buf[0] == msg::USERAUTH_REQUEST {
                    // check signature.
                    self.state = Some(auth_request.verify_signature(buf, self.session_id.as_bytes(), buffer))

                } else {
                    self.state = Some(EncryptedState::RejectAuthRequest(auth_request))
                }
            }
            Some(EncryptedState::WaitingChannelOpen) if buf[0] == msg::CHANNEL_OPEN => {
                // https://tools.ietf.org/html/rfc4254#section-5.1
                let mut r = buf.reader(1);
                let typ = r.read_string().unwrap();
                let sender = r.read_u32().unwrap();
                let window = r.read_u32().unwrap();
                let maxpacket = r.read_u32().unwrap();

                debug!("waiting channel open: type = {:?} sender = {:?} window = {:?} maxpacket = {:?}",
                       String::from_utf8_lossy(typ),
                       sender,
                       window,
                       maxpacket);

                let mut sender_channel: u32 = 1;
                while self.channels.contains_key(&sender_channel) || sender_channel == 0 {
                    sender_channel = thread_rng().gen()
                }
                let channel = ChannelParameters {
                    recipient_channel: sender,
                    sender_channel: sender_channel,
                    initial_window_size: window,
                    maximum_packet_size: maxpacket,
                };

                // Write the response immediately, so that we're ready when the stream becomes writable.
                server.new_channel(&channel);
                self.server_confirm_channel_open(buffer, &channel, write_buffer);
                //
                self.state = Some(EncryptedState::ChannelOpenConfirmation(channel));
            }
            Some(EncryptedState::ChannelOpened(recipient_channel)) => {
                debug!("buf: {:?}", buf);
                if buf[0] == msg::CHANNEL_DATA {

                    let channel_num = BigEndian::read_u32(&buf[1..]);
                    if let Some(ref mut channel) = self.channels.get_mut(&channel_num) {

                        let len = BigEndian::read_u32(&buf[5..]) as usize;
                        let data = &buf[9..9 + len];
                        buffer.clear();

                        let data = {
                            let server_buf = ChannelBuf {
                                buffer:buffer,
                                recipient_channel: channel.recipient_channel,
                                sent_seqn: &mut write_buffer.seqn,
                                write_buffer: &mut write_buffer.buffer,
                                cipher: &mut self.cipher
                            };
                            server.data(&data, server_buf)
                        };

                        if let Ok(()) = data {
                            /*if channel.stdout.len() > 0 || channel.stderr.len() > 0 {
                            enc.pending_messages.insert(channel_num);
                        }*/
                        } else {
                            unimplemented!()
                        }
                    }
                }
                self.state = Some(EncryptedState::ChannelOpened(recipient_channel))
            }
            Some(state) => {
                debug!("buf: {:?}", buf);
                debug!("replacing state: {:?}", state);
                self.state = Some(state)
            },
            None => {}
        }

    }
}
