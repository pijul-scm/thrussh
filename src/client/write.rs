use super::super::*;
use std::io::{Write};
use super::super::msg;
use super::super::auth::{AuthRequest};
use rand;
use rand::Rng;
use super::super::negociation;


impl Encrypted {

    pub fn client_send_signature<W:Write>(&mut self, stream:&mut W, buffers:&mut SSHBuffers, auth_request:AuthRequest, config:&super::Config, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<(),Error> {

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
        println!("========== signing");
        buffer2.clear();
        config.keys[0].add_signature(buffer2, buffer.as_slice());
        buffer.extend(buffer2.as_slice());

        // Send
        self.cipher.write_client_packet(buffers.write.seqn,
                                       &(buffer.as_slice())[i0..], // Skip the session id.
                                       &mut buffers.write.buffer);

        buffers.write.seqn += 1;
        try!(buffers.write_all(stream));

        self.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
        Ok(())
    }

    pub fn client_waiting_auth_request(&mut self, write_buffer:&mut SSHBuffer, auth_request:AuthRequest, auth_method:&Option<auth::Method>, buffer:&mut CryptoBuf) {
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
            },
            Some(auth::Method::Pubkey { ref user, ref pubkey, .. }) => {
                buffer.extend_ssh_string(user.as_bytes());
                buffer.extend_ssh_string(b"ssh-connection");
                buffer.extend_ssh_string(b"publickey");
                buffer.push(0); // This is a probe
                buffer.extend_ssh_string(pubkey.name().as_bytes());
                pubkey.extend_pubkey(buffer);
                true
            },
            _ => {
                false
            }
        };
        if method_ok {
            println!("method ok");
            self.cipher.write_client_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
            write_buffer.seqn += 1;
            self.state = Some(EncryptedState::AuthRequestSuccess(auth_request));
        } else {
            println!("method not ok");
            self.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
        }
    }

    pub fn client_waiting_channel_open<W:Write>(&mut self, stream:&mut W, buffers:&mut SSHBuffers, config:&super::Config, buffer:&mut CryptoBuf) -> Result<(),Error> {
        // The server is waiting for our CHANNEL_OPEN.
        let mut sender_channel = 0;
        while self.channels.contains_key(&sender_channel) || sender_channel == 0 {
            sender_channel = rand::thread_rng().gen()
        }
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN);
        buffer.extend_ssh_string(b"channel name");
        buffer.push_u32_be(sender_channel); // sender channel id.
        buffer.push_u32_be(config.window); // window.
        buffer.push_u32_be(config.maxpacket); // max packet size.
        // Send
        self.cipher.write_client_packet(buffers.write.seqn,
                                       buffer.as_slice(),
                                       &mut buffers.write.buffer);

        buffers.write.seqn += 1;
        try!(buffers.write_all(stream));
        self.state = Some(EncryptedState::ChannelOpenConfirmation(
            ChannelParameters {
                recipient_channel: 0,
                sender_channel: sender_channel,
                initial_window_size: config.window,
                maximum_packet_size: config.maxpacket,
            }
        ));
        Ok(())
    }
    pub fn client_write_rekey<W:Write>(&mut self, stream:&mut W, buffers:&mut SSHBuffers, rekey:Kex, config:&super::Config, buffer:&mut CryptoBuf) -> Result<(),Error> {

        println!("rekeying, {:?}", rekey);
        match rekey {
            Kex::KexInit(mut kexinit) => {

                if !kexinit.sent {
                    buffer.clear();
                    negociation::write_kex(&config.keys, buffer);
                    kexinit.exchange.client_kex_init.extend(buffer.as_slice());

                    self.cipher.write_client_packet(buffers.write.seqn, buffer.as_slice(),
                                                    &mut buffers.write.buffer);
                    
                    buffers.write.seqn += 1;
                    try!(buffers.write_all(stream));
                    kexinit.sent = true;
                }
                if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
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
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            },
            Kex::KexDh(kexdh) => {
                self.client_write_kexdh(buffer, &mut buffers.write, kexdh);
                try!(buffers.write_all(stream));
            },
            Kex::NewKeys(mut newkeys) => {
                println!("newkeys {:?}", newkeys);
                if !newkeys.sent {
                    self.cipher.write_client_packet(buffers.write.seqn, &[msg::NEWKEYS],
                                                    &mut buffers.write.buffer);
                    try!(buffers.write_all(stream));
                    buffers.write.seqn += 1;
                    newkeys.sent = true;
                }
                if !newkeys.received {
                    self.rekey = Some(Kex::NewKeys(newkeys))
                } else {
                    println!("changing keys!");
                    self.exchange = Some(newkeys.exchange);
                    self.kex = newkeys.kex;
                    self.key = newkeys.key;
                    self.cipher = newkeys.cipher;
                    self.mac = newkeys.mac;
                    buffers.read.bytes = 0;
                    buffers.write.bytes = 0;
                }
            },
            state => {
                self.rekey = Some(state)
            }
        }
        Ok(())
    }

    pub fn client_write_kexdh(&mut self, buffer:&mut CryptoBuf, write_buffer:&mut SSHBuffer, mut kexdh:KexDh) {
        buffer.clear();
        let kex = kexdh.kex.client_dh(&mut kexdh.exchange, buffer);
        
        self.cipher.write_client_packet(write_buffer.seqn, buffer.as_slice(), &mut write_buffer.buffer);
        write_buffer.seqn += 1;

        self.rekey = Some(Kex::KexDhDone(KexDhDone {
            exchange: kexdh.exchange,
            kex: kex,
            key: kexdh.key,
            cipher: kexdh.cipher,
            mac: kexdh.mac,
            follows: kexdh.follows,
            session_id: kexdh.session_id,
        }));
    }
}
