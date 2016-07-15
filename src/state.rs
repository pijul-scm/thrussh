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

use std;

use auth;
use negociation;
use kex;
use cipher;
use msg;
use key;
use sodium;
use super::{read_public_key,Error,ChannelParameters,Client};
use cryptobuf::CryptoBuf;
use std::collections::HashMap;
use encoding::Reader;
use Limits;
use sshbuffer::{SSHBuffers};
use byteorder::{BigEndian, ByteOrder};
use cipher::CipherT;
use time;

#[derive(Debug)]
pub enum ServerState<Key> {
    Kex(Kex<Key>),
    Encrypted(Encrypted<Key>), // Session is now encrypted.
}

#[derive(Debug)]
pub struct Encrypted<K> {
    pub exchange: Option<Exchange>, // It's always Some, except when we std::mem::replace it temporarily.
    pub kex: kex::Algorithm,
    pub key: K,
    pub cipher: cipher::CipherPair,
    pub mac: &'static str,
    pub session_id: kex::Digest,
    pub state: Option<EncryptedState>,
    pub rekey: Option<Kex<K>>,
    pub channels: HashMap<u32, ChannelParameters>,
    pub write: CryptoBuf,
    pub write_cursor: usize,
}

impl<K> Encrypted<K> {

    pub fn data(&mut self, channel: u32, extended: Option<u32>, buf: &[u8]) -> Result<usize, Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            debug!("output {:?} {:?}", channel, buf);
            let mut buf = if buf.len() as u32 > channel.recipient_window_size {
                &buf[0 .. channel.recipient_window_size as usize]
            } else {
                buf
            };
            let buf_len = buf.len();

            while buf.len() > 0 && channel.recipient_window_size > 0 {

                // Compute the length we're allowed to send.
                let off = std::cmp::min(buf.len(), channel.recipient_maximum_packet_size as usize);
                let off = std::cmp::min(off, channel.recipient_window_size as usize);

                push_packet!(self.write, {
                    if let Some(ext) = extended {
                        self.write.push(msg::CHANNEL_EXTENDED_DATA);
                        self.write.push_u32_be(channel.recipient_channel);
                        self.write.push_u32_be(ext);
                    } else {
                        self.write.push(msg::CHANNEL_DATA);
                        self.write.push_u32_be(channel.recipient_channel);
                    }
                    self.write.extend_ssh_string(&buf[..off]);
                });
                channel.recipient_window_size -= off as u32;
                buf = &buf[off..]
            }
            Ok(buf_len)
        } else {
            Err(Error::WrongChannel)
        }
    }

    pub fn flush(&mut self, limits:&Limits, buffers: &mut SSHBuffers) -> bool {
        // If there are pending packets (and we've not started to rekey), flush them.
        if self.rekey.is_none() {
            {
                let packets = self.write.as_slice();
                while self.write_cursor < self.write.len() {
                    if buffers.needs_rekeying(limits) {

                        // Resetting those now is incorrect (since
                        // we're resetting before the rekeying), but
                        // since the bytes sent during rekeying will
                        // be counted, the limits are still an upper
                        // bound on the size that can be sent.
                        buffers.write.bytes = 0;
                        buffers.read.bytes = 0;
                        buffers.last_rekey_s = time::precise_time_s();
                        return true

                    } else {
                        // Read a single packet, encrypt and send it.
                        let len = BigEndian::read_u32(&packets[self.write_cursor .. ]) as usize;
                        debug!("flushing len {:?}", len);
                        let packet = &packets [(self.write_cursor+4) .. (self.write_cursor+4+len)];
                        self.cipher.write(packet, &mut buffers.write);
                        self.write_cursor += 4+len
                    }
                }
            }
            if self.write_cursor >= self.write.len() {
                self.write_cursor = 0;
                self.write.clear();
            }
        }
        false
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest,
    WaitingAuthRequest(auth::AuthRequest),
    Authenticated
}


#[derive(Debug)]
pub struct Exchange {
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    pub client_kex_init: Vec<u8>,
    pub server_kex_init: Vec<u8>,
    pub client_ephemeral: Vec<u8>,
    pub server_ephemeral: Vec<u8>,
}

impl Exchange {
    pub fn new() -> Self {
        Exchange {
            client_id: Vec::new(),
            server_id: Vec::new(),
            client_kex_init: Vec::new(),
            server_kex_init: Vec::new(),
            client_ephemeral: Vec::new(),
            server_ephemeral: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Kex<Key> {
    KexInit(KexInit), /* Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively. */
    KexDh(KexDh<Key>), // Algorithms have been determined, the DH algorithm should run.
    KexDhDone(KexDhDone<Key>), // The kex has run.
    NewKeys(NewKeys<Key>), /* The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side. */
}


#[derive(Debug)]
pub struct KexInit {
    pub algo: Option<negociation::Names>,
    pub exchange: Exchange,
    pub session_id: Option<kex::Digest>,
    pub sent: bool,
}


impl KexInit {
    pub fn received_rekey(ex: Exchange, algo: negociation::Names, session_id: &kex::Digest) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: Some(algo),
            sent: false,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }

    pub fn initiate_rekey(ex: Exchange, session_id: &kex::Digest) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: None,
            sent: true,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }
}

#[derive(Debug)]
pub struct KexDh<Key> {
    pub exchange: Exchange,
    pub names: negociation::Names,
    pub key: Key,
    pub session_id: Option<kex::Digest>,
}

#[derive(Debug)]
pub struct KexDhDone<Key> {
    pub exchange: Exchange,
    pub kex: kex::Algorithm,
    pub key: Key,
    pub session_id: Option<kex::Digest>,
    pub names: negociation::Names,
}

impl<Key> KexDhDone<Key> {
    pub fn compute_keys(self,
                    hash: kex::Digest,
                    buffer: &mut CryptoBuf,
                    buffer2: &mut CryptoBuf,
                    is_server: bool)
                    -> Result<NewKeys<Key>, Error> {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = try!(self.kex.compute_keys(&session_id, &hash, buffer, buffer2, &self.names.cipher, is_server));
        Ok(NewKeys {
            exchange: self.exchange,
            names: self.names,
            kex: self.kex,
            key: self.key,
            cipher: c,
            session_id: session_id,
            received: false,
            sent: false,
        })
    }

    pub fn client_compute_exchange_hash<C: Client>(&mut self,
                                                   client: &C,
                                                   payload: &[u8],
                                                   buffer: &mut CryptoBuf)
                                                   -> Result<kex::Digest, Error> {
        assert!(payload[0] == msg::KEX_ECDH_REPLY);
        let mut reader = payload.reader(1);

        let pubkey = try!(reader.read_string()); // server public key.
        let pubkey = try!(read_public_key(pubkey));
        if !client.check_server_key(&pubkey) {
            return Err(Error::UnknownKey);
        }
        let server_ephemeral = try!(reader.read_string());
        self.exchange.server_ephemeral.extend_from_slice(server_ephemeral);
        let signature = try!(reader.read_string());

        try!(self.kex.compute_shared_secret(&self.exchange.server_ephemeral));

        let hash = try!(self.kex.compute_exchange_hash(&pubkey,
                                                       &self.exchange,
                                                       buffer));

        let signature = {
            let mut sig_reader = signature.reader(0);
            let sig_type = try!(sig_reader.read_string());
            assert_eq!(sig_type, b"ssh-ed25519");
            let signature = try!(sig_reader.read_string());
            sodium::ed25519::Signature::copy_from_slice(signature)
        };

        match pubkey {
            key::PublicKey::Ed25519(ref pubkey) => {
                assert!(sodium::ed25519::verify_detached(&signature, hash.as_bytes(), pubkey))
            }
        };
        debug!("signature = {:?}", signature);
        debug!("exchange = {:?}", self.exchange);
        Ok(hash)
    }
}

#[derive(Debug)]
pub struct NewKeys<Key> {
    pub exchange: Exchange,
    pub names: negociation::Names,
    pub kex: kex::Algorithm,
    pub key: Key,
    pub cipher: cipher::CipherPair,
    pub session_id: kex::Digest,
    pub received: bool,
    pub sent: bool,
}

impl<Key> NewKeys<Key> {
    pub fn encrypted(self, state: EncryptedState) -> Encrypted<Key> {
        Encrypted {
            exchange: Some(self.exchange),
            kex: self.kex,
            key: self.key,
            cipher: self.cipher,
            mac: self.names.mac,
            session_id: self.session_id,
            state: Some(state),
            rekey: None,
            channels: HashMap::new(),

            // Extra buffer to put extra packets while handling
            // rekeying (also used to prepare packets before
            // encryption).
            write: CryptoBuf::new(),
            write_cursor: 0,
        }
    }
}
