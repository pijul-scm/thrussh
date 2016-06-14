use byteorder::{ByteOrder, BigEndian};
use super::{CryptoBuf, Exchange, Error, ServerState, Kex, KexInit, KexDh, KexDhDone, EncryptedState};
use super::encoding::*;
use super::key;
use super::kex;
use super::msg;
use super::negociation;
use std::io::{Write,BufRead};
use std;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64
}

pub struct ClientSession {
    buffers: super::SSHBuffers,
    state: Option<ServerState<()>>
}


impl ClientSession {
    pub fn new() -> Self {
        ClientSession {
            buffers: super::SSHBuffers::new(),
            state: None

        }
    }
    // returns whether a complete packet has been read.
    pub fn read<R: BufRead>(&mut self,
                            config: &Config,
                            stream: &mut R,
                            buffer: &mut CryptoBuf,
                            buffer2: &mut CryptoBuf)
                            -> Result<bool, Error> {
        println!("read");
        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                // We have neither sent nor received the version id.
                let server_id = try!(self.buffers.read_ssh_id(stream));
                println!("server_id = {:?}", server_id);
                if let Some(server_id) = server_id {
                    let mut exchange = Exchange::new();
                    exchange.server_id.extend(server_id);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            Some(ServerState::VersionOk(mut exchange)) => {
                println!("read: {:?}", exchange);
                // Have we received the version id?
                if exchange.server_id.len() == 0 {
                    let server_id = try!(self.buffers.read_ssh_id(stream));
                    println!("server_id = {:?}", server_id);
                    if let Some(server_id) = server_id {
                        exchange.server_id.extend(server_id);
                    } else {
                        self.state = Some(ServerState::VersionOk(exchange));
                        return Ok(false)
                    }
                }

                if exchange.client_id.len() > 0 {
                    self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                        exchange: exchange,
                        algo: None,
                        sent: false,
                        session_id: None,
                    })));
                } else {
                    self.state = Some(ServerState::VersionOk(exchange));
                }
                Ok(true)
            },
            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                // This is a writing state from the client.
                println!("kexdh");
                self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                Ok(true)
            }
            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                // Have we determined the algorithm yet?
                let mut received = false;
                if kexinit.algo.is_none() {
                    // We've sent ECDH_INIT, waiting for ECDH_REPLY
                    if self.buffers.read_len == 0 {
                        try!(self.buffers.set_clear_len(stream));
                    }

                    if try!(self.buffers.read(stream)) {
                        println!("received: {:?}", String::from_utf8_lossy(self.buffers.get_current_payload()));
                        kexinit.algo = Some(try!(negociation::client_read_kex(self.buffers.get_current_payload(), &config.keys)));

                        kexinit.exchange.server_kex_init.extend(self.buffers.get_current_payload());
                        self.buffers.recv_seqn += 1;
                        self.buffers.read_buffer.clear();
                        self.buffers.read_len = 0;
                        
                        received = true;
                    }
                }

                if kexinit.sent {
                    if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                        self.state = Some(ServerState::Kex(Kex::KexDh(KexDh {
                            exchange: kexinit.exchange,
                            kex: kex,
                            key: key,
                            cipher: cipher,
                            mac: mac,
                            follows: follows,
                            session_id: kexinit.session_id,
                        })))
                    } else {
                        self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                    }
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                }
                Ok(received)
            }
            Some(ServerState::Kex(Kex::KexDhDone(mut kexdhdone))) => {

                println!("kexdhdone");


                // We've sent ECDH_INIT, waiting for ECDH_REPLY
                if self.buffers.read_len == 0 {
                    try!(self.buffers.set_clear_len(stream));
                }

                if try!(self.buffers.read(stream)) {

                    let hash = {
                        let payload = self.buffers.get_current_payload();
                        // println!("payload = {:?}", payload);
                        assert!(payload[0] == msg::KEX_ECDH_REPLY);
                        let mut pos = 1;
                        let pubkey_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos += 4;
                        let pubkey = &payload[pos..pos+pubkey_len];
                        pos += pubkey_len;

                        let ephemeral_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos+=4;
                        let server_ephemeral = &payload[pos .. pos+ephemeral_len];
                        kexdhdone.exchange.server_ephemeral.extend(server_ephemeral);
                        pos+=ephemeral_len;

                        let signature_len = BigEndian::read_u32(&payload[pos..]) as usize;
                        pos+=4;
                        let signature = &payload[pos .. pos+signature_len];
                        pos+=signature_len;

                        kexdhdone.kex.compute_shared_secret(&kexdhdone.exchange.server_ephemeral);

                        let pubkey = try!(super::read_public_key(pubkey));
                        let hash = try!(kexdhdone.kex.compute_exchange_hash(&pubkey,
                                                                            &kexdhdone.exchange,
                                                                            buffer));

                        let signature = {
                            let sig_type_len = BigEndian::read_u32(&signature) as usize;
                            let sig_type = &signature[4..4+sig_type_len];
                            let sig_len = BigEndian::read_u32(&signature[4+sig_type_len ..]) as usize;

                            super::sodium::ed25519::Signature::copy_from_slice(&signature[8+sig_type_len .. 8+sig_type_len+sig_len])
                        };

                        let verif = match pubkey {
                            key::PublicKey::Ed25519(ref pubkey) => {
                                super::sodium::ed25519::verify_detached(&signature, hash.as_bytes(), pubkey)
                            }
                        };
                        if !verif {
                            panic!("wrong server signature")
                        }
                        println!("signature = {:?}", signature);
                        hash
                    };
                    let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);

                    self.state = Some(ServerState::Kex(Kex::NewKeys(new_keys)));
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;

                    Ok(true)
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                    Ok(false)
                }

            },
            Some(ServerState::Kex(Kex::NewKeys(new_keys))) => {
                self.state = Some(ServerState::Kex(Kex::NewKeys(new_keys)));
                if self.buffers.read_len == 0 {
                    try!(self.buffers.set_clear_len(stream));
                }
                if try!(self.buffers.read(stream)) {

                    {
                        let payload = self.buffers.get_current_payload();
                        println!("new keys payload = {:?}", payload);
                    }
                    self.buffers.recv_seqn += 1;
                    self.buffers.read_buffer.clear();
                    self.buffers.read_len = 0;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Some(ServerState::Encrypted(_)) => unimplemented!()
        }

    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self,
                           config: &Config,
                           stream: &mut W,
                           buffer: &mut CryptoBuf,
                           buffer2: &mut CryptoBuf)
                           -> Result<bool, Error> {
        println!("write");
        // Finish pending writes, if any.
        if !try!(self.buffers.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true);
        }
        self.buffers.write_buffer.clear();
        self.buffers.write_position = 0;

        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {
                self.buffers.send_ssh_id(stream, config.client_id.as_bytes());
                let mut exchange = Exchange::new();
                exchange.client_id.extend(config.client_id.as_bytes());
                println!("sent!: {:?}", exchange);
                self.state = Some(ServerState::VersionOk(exchange));
                Ok(true)
            },
            Some(ServerState::VersionOk(mut exchange)) => {
                println!("read: {:?}", exchange);
                // Have we received the version id?
                if exchange.client_id.len() == 0 {
                    self.buffers.send_ssh_id(stream, config.client_id.as_bytes());
                    exchange.client_id.extend(config.client_id.as_bytes());
                }

                if exchange.server_id.len() > 0 {
                    self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                        exchange: exchange,
                        algo: None,
                        sent: false,
                        session_id: None,
                    })));
                } else {
                    self.state = Some(ServerState::VersionOk(exchange));
                }
                Ok(true)
            },
            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                self.state = Some(try!(self.buffers.cleartext_write_kex_init(
                    &config.keys,
                    false, // is_server
                    kexinit,
                    stream)));
                Ok(true)
            },
            Some(ServerState::Kex(Kex::KexDh(mut kexdh))) => {

                self.buffers.write_buffer.extend(b"\0\0\0\0\0");

                let kex = try!(kexdh.kex.client_dh(&mut kexdh.exchange, &mut self.buffers.write_buffer));

                super::complete_packet(&mut self.buffers.write_buffer, 0);
                self.buffers.sent_seqn += 1;
                try!(self.buffers.write_all(stream));

                self.state = Some(ServerState::Kex(Kex::KexDhDone(KexDhDone {
                    exchange: kexdh.exchange,
                    kex: kex,
                    key: kexdh.key,
                    cipher: kexdh.cipher,
                    mac: kexdh.mac,
                    follows: kexdh.follows,
                    session_id: kexdh.session_id,
                })));
                Ok(true)

            },
            Some(ServerState::Kex(Kex::KexDhDone(kexdhdone))) => {
                // We're waiting for ECDH_REPLY from server, nothing to write.
                self.state = Some(ServerState::Kex(Kex::KexDhDone(kexdhdone)));
                Ok(true)
            },
            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => {

                debug!("sending NEWKEYS");
                self.buffers.write_buffer.extend(b"\0\0\0\0\0");
                self.buffers.write_buffer.push(msg::NEWKEYS);
                super::complete_packet(&mut self.buffers.write_buffer, 0);
                self.buffers.sent_seqn += 1;
                try!(self.buffers.write_all(stream));
                self.state = Some(ServerState::Encrypted(newkeys.encrypted(EncryptedState::WaitingServiceRequest)));
                Ok(true)

            }
            Some(ServerState::Encrypted(_)) => unimplemented!()
        }
        
    }
}
