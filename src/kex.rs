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
use byteorder::{ByteOrder, BigEndian};
use std;

use Error;
use msg;

use cryptovec::CryptoVec;
use session::Exchange;
use key;
use cipher;
use ring::{agreement, digest, rand};
use untrusted;
use encoding::Encoding;

#[doc(hidden)]
pub struct Algorithm {
    local_secret: Option<agreement::EphemeralPrivateKey>,
    local_pubkey: Option<Vec<u8>>,
    shared_secret: Option<Vec<u8>>,
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Algorithm {{ local_secret: [hidden], local_pubkey: {:?}, shared_secret: [hidden] }}",
               self.local_pubkey)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");

impl Algorithm {
    pub fn server_dh(name: Name,
                     exchange: &mut Exchange,
                     payload: &[u8])
                     -> Result<Algorithm, Error> {
        let rng = rand::SystemRandom::new(); // TODO: make a parameter.

        let alg = match name {
            CURVE25519 => &agreement::X25519,
            _ => unreachable!(),
        };

        assert_eq!(payload[0], msg::KEX_ECDH_INIT);
        let client_pubkey = {
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
            untrusted::Input::from(&payload[5..(5 + pubkey_len)])
        };

        let server_secret = try!(agreement::EphemeralPrivateKey::generate(alg, &rng));
        let mut server_pubkey = vec![0; server_secret.public_key_len()];
        try!(server_secret.compute_public_key(&mut server_pubkey[..]));

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey);
        // XXX: There is no assertion that the peer is using the same key exchange algorithm.
        agreement::agree_ephemeral(server_secret, &agreement::X25519, client_pubkey,
                                   Error::Inconsistent/*XXX*/, |shared_secret| {
            Ok(Algorithm {
                local_secret: None,
                local_pubkey: Some(server_pubkey),
                shared_secret: Some(Vec::from(shared_secret)),
            })
        })
    }

    pub fn client_dh(name: Name,
                     client_ephemeral: &mut CryptoVec,
                     buf: &mut CryptoVec)
                     -> Result<Algorithm, Error> {
        let rng = rand::SystemRandom::new(); // TODO: make a parameter.

        let alg = match name {
            CURVE25519 => &agreement::X25519,
            _ => unreachable!(),
        };

        let client_secret = try!(agreement::EphemeralPrivateKey::generate(alg, &rng));


        let mut client_pubkey = vec![0; client_secret.public_key_len()];
        try!(client_secret.compute_public_key(&mut client_pubkey));

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey);


        Ok(Algorithm {
            local_secret: Some(client_secret),
            local_pubkey: Some(client_pubkey),
            shared_secret: None,
        })
    }

    pub fn compute_shared_secret(&mut self, remote_pubkey: &[u8]) -> Result<(), Error> {
        let local_secret = std::mem::replace(&mut self.local_secret, None).unwrap();

        // XXX: There is no assertion that the peer is using the same key exchange algorithm.
        let peer_alg = local_secret.algorithm();

        agreement::agree_ephemeral(local_secret, peer_alg,
                                   untrusted::Input::from(remote_pubkey), Error::Inconsistent/*XXX*/,
                                   |shared_secret| {
            self.shared_secret = Some(Vec::from(shared_secret));
            Ok(())
        })
    }

    pub fn compute_exchange_hash<K: key::PubKey>(&self,
                                                 key: &K,
                                                 exchange: &Exchange,
                                                 buffer: &mut CryptoVec)
                                                 -> Result<digest::Digest, Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);


        key.push_to(buffer);
        debug_assert_eq!(exchange.client_ephemeral.len(), 32);
        buffer.extend_ssh_string(&exchange.client_ephemeral);

        debug_assert_eq!(exchange.server_ephemeral.len(), 32);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared);
        }
        // super::hexdump(buffer);
        let hash = digest::digest(&digest::SHA256, &buffer);
        Ok(hash)
    }


    pub fn compute_keys(&self,
                        session_id: &digest::Digest,
                        exchange_hash: &digest::Digest,
                        buffer: &mut CryptoVec,
                        key: &mut CryptoVec,
                        cipher: cipher::Name,
                        is_server: bool)
                        -> Result<super::cipher::CipherPair, Error> {
        let cipher = match cipher {
            super::cipher::chacha20poly1305::NAME => &super::cipher::chacha20poly1305::CIPHER,
            _ => unreachable!(),
        };

        // https://tools.ietf.org/html/rfc4253#section-7.2
        let mut compute_key = |c, key: &mut CryptoVec, len| {
            buffer.clear();
            key.clear();

            if let Some(ref shared) = self.shared_secret {
                buffer.extend_ssh_mpint(&shared);
            }

            buffer.extend(exchange_hash.as_ref());
            buffer.push(c);
            buffer.extend(session_id.as_ref());
            let hash = digest::digest(&digest::SHA256, &buffer);
            key.extend(hash.as_ref());

            while key.len() < len {
                // extend.
                buffer.clear();
                if let Some(ref shared) = self.shared_secret {
                    buffer.extend_ssh_mpint(&shared);
                }
                buffer.extend(exchange_hash.as_ref());
                buffer.extend(key);
                key.extend(digest::digest(&digest::SHA256, &buffer).as_ref());
            }
        };

        let (local_to_remote, remote_to_local) = if is_server {
            (b'D', b'C')
        } else {
            (b'C', b'D')
        };

        compute_key(local_to_remote, key, cipher.key_len);
        let local_to_remote = (cipher.make_sealing_cipher)(key);

        compute_key(remote_to_local, key, cipher.key_len);
        let remote_to_local = (cipher.make_opening_cipher)(key);

        Ok(super::cipher::CipherPair {
            local_to_remote: local_to_remote,
            remote_to_local: remote_to_local,
        })
    }
}
