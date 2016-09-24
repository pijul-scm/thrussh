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
use {Error, Channel, Disconnect};
use cryptovec::CryptoVec;
use std::collections::HashMap;
use Limits;
use sshbuffer::SSHBuffer;
use byteorder::{BigEndian, ByteOrder};
use std::sync::Arc;
use ring::digest;
use encoding::Encoding;
use std::num::Wrapping;

#[derive(Debug)]
pub struct Encrypted {
    pub state: Option<EncryptedState>,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub mac: Option<&'static str>,
    pub session_id: digest::Digest,
    pub rekey: Option<Kex>,
    pub channels: HashMap<u32, Channel>,
    pub last_channel_id: Wrapping<u32>,
    pub wants_reply: bool,
    pub write: CryptoVec,
    pub write_cursor: usize,
    pub last_rekey: std::time::Instant,
}

#[derive(Debug)]
pub struct CommonSession<Config> {
    pub auth_user: String,
    pub config: Arc<Config>,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method<key::Algorithm>>,
    pub write_buffer: SSHBuffer,
    pub kex: Option<Kex>,
    pub cipher: cipher::CipherPair,
    pub wants_reply: bool,
    pub disconnected: bool,
}

impl<C> CommonSession<C> {
    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.mac = newkeys.names.mac;
            self.cipher = newkeys.cipher;
        } else {
            self.encrypted = Some(Encrypted {
                exchange: Some(newkeys.exchange),
                kex: newkeys.kex,
                key: newkeys.key,
                mac: newkeys.names.mac,
                session_id: newkeys.session_id,
                state: Some(state),
                rekey: None,
                channels: HashMap::new(),
                last_channel_id: Wrapping(1),
                wants_reply: false,
                write: CryptoVec::new(),
                write_cursor: 0,
                last_rekey: std::time::Instant::now(),
            });
            self.cipher = newkeys.cipher;
        }
    }

    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.disconnected = true;
        if let Some(ref mut enc) = self.encrypted {
            let i0 = enc.write.len();
            enc.write.push(msg::DISCONNECT);
            enc.write.push_u32_be(reason as u32);
            enc.write.extend_ssh_string(description.as_bytes());
            enc.write.extend_ssh_string(language_tag.as_bytes());
            self.cipher.write(&enc.write[i0..], &mut self.write_buffer);
            enc.write.truncate(i0)
        } else {
            cipher::Clear.disconnect(reason, description, language_tag, &mut self.write_buffer)
        }
    }

    pub fn byte(&mut self, channel: u32, msg: u8) {
        if let Some(ref mut enc) = self.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg);
                    enc.write.push_u32_be(channel.recipient_channel);
                });
            }
        }
    }
}

impl Encrypted {
    pub fn adjust_window_size(&mut self, channel: u32, data: &[u8], target: u32) {
        if let Some(ref mut channel) = self.channels.get_mut(&channel) {
            channel.sender_window_size -= data.len() as u32;
            if channel.sender_window_size < target / 2 {
                push_packet!(self.write, {
                    self.write.push(msg::CHANNEL_WINDOW_ADJUST);
                    self.write.push_u32_be(channel.recipient_channel);
                    self.write.push_u32_be(target - channel.sender_window_size);
                });
                channel.sender_window_size = target;
            }
        }
    }

    pub fn data(&mut self,
                channel: u32,
                extended: Option<u32>,
                buf: &[u8])
                -> Result<usize, Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            debug!("output {:?} {:?}", channel, buf);
            let mut buf = if buf.len() as u32 > channel.recipient_window_size {
                &buf[0..channel.recipient_window_size as usize]
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

    pub fn flush(&mut self,
                 limits: &Limits,
                 cipher: &mut cipher::CipherPair,
                 write_buffer: &mut SSHBuffer)
                 -> bool {
        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {

                let now = std::time::Instant::now();
                let dur = now.duration_since(self.last_rekey);

                if write_buffer.bytes >= limits.rekey_write_limit ||
                   dur >= limits.rekey_time_limit {

                    // Resetting those now is incorrect (since
                    // we're resetting before the rekeying), but
                    // since the bytes sent during rekeying will
                    // be counted, the limits are still an upper
                    // bound on the size that can be sent.
                    write_buffer.bytes = 0;
                    self.last_rekey = now;
                    return true;

                } else {
                    // Read a single packet, selfrypt and send it.
                    let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                    debug!("flushing len {:?}", len);
                    let packet = &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 +
                                                                       len)];
                    cipher.write(packet, write_buffer);
                    self.write_cursor += 4 + len
                }
            }
        }
        if self.write_cursor >= self.write.len() {
            // If all packets have been written, clear.
            self.write_cursor = 0;
            self.write.clear();
        }
        false
    }
    pub fn new_channel_id(&mut self) -> u32 {
        self.last_channel_id += Wrapping(1);
        while self.channels.contains_key(&self.last_channel_id.0) {
            self.last_channel_id += Wrapping(1)
        }
        self.last_channel_id.0
    }
    pub fn new_channel(&mut self, window_size: u32, maxpacket: u32) -> u32 {
        loop {
            self.last_channel_id += Wrapping(1);
            if let std::collections::hash_map::Entry::Vacant(vacant_entry) = self.channels
                .entry(self.last_channel_id.0) {
                vacant_entry.insert(Channel {
                    recipient_channel: 0,
                    sender_channel: self.last_channel_id.0,
                    sender_window_size: window_size,
                    recipient_window_size: 0,
                    sender_maximum_packet_size: maxpacket,
                    recipient_maximum_packet_size: 0,
                    confirmed: false,
                    wants_reply: false,
                });
                return self.last_channel_id.0;
            }
        }
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest,
    WaitingAuthRequest(auth::AuthRequest),
    Authenticated,
}


#[derive(Debug)]
pub struct Exchange {
    pub client_id: CryptoVec,
    pub server_id: CryptoVec,
    pub client_kex_init: CryptoVec,
    pub server_kex_init: CryptoVec,
    pub client_ephemeral: CryptoVec,
    pub server_ephemeral: CryptoVec,
}

impl Exchange {
    pub fn new() -> Self {
        Exchange {
            client_id: CryptoVec::new(),
            server_id: CryptoVec::new(),
            client_kex_init: CryptoVec::new(),
            server_kex_init: CryptoVec::new(),
            client_ephemeral: CryptoVec::new(),
            server_ephemeral: CryptoVec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Kex {
    /// Version number sent. `algo` and `sent` tell wether kexinit has
    /// been received, and sent, respectively.
    KexInit(KexInit),

    /// Algorithms have been determined, the DH algorithm should run.
    KexDh(KexDh),

    /// The kex has run.
    KexDhDone(KexDhDone),

    /// The DH is over, we've sent the NEWKEYS packet, and are waiting
    /// the NEWKEYS from the other side.
    NewKeys(NewKeys),
}


#[derive(Debug)]
pub struct KexInit {
    pub algo: Option<negociation::Names>,
    pub exchange: Exchange,
    pub session_id: Option<digest::Digest>,
    pub sent: bool,
}


impl KexInit {
    pub fn received_rekey(ex: Exchange,
                          algo: negociation::Names,
                          session_id: &digest::Digest)
                          -> Self {
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

    pub fn initiate_rekey(ex: Exchange, session_id: &digest::Digest) -> Self {
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
pub struct KexDh {
    pub exchange: Exchange,
    pub names: negociation::Names,
    pub key: usize,
    pub session_id: Option<digest::Digest>,
}

#[derive(Debug)]
pub struct KexDhDone {
    pub exchange: Exchange,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub session_id: Option<digest::Digest>,
    pub names: negociation::Names,
}

impl KexDhDone {
    pub fn compute_keys(self,
                        hash: digest::Digest,
                        buffer: &mut CryptoVec,
                        buffer2: &mut CryptoVec,
                        is_server: bool)
                        -> Result<NewKeys, Error> {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = try!(self.kex.compute_keys(&session_id,
                                           &hash,
                                           buffer,
                                           buffer2,
                                           self.names.cipher,
                                           is_server));
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
}

#[derive(Debug)]
pub struct NewKeys {
    pub exchange: Exchange,
    pub names: negociation::Names,
    pub kex: kex::Algorithm,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: digest::Digest,
    pub received: bool,
    pub sent: bool,
}
