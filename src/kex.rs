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

use super::Error;
use super::msg;
use std;

use super::sodium::randombytes;
use super::sodium::sha256;
use super::sodium::curve25519;
use super::cryptobuf::CryptoBuf;
use session::Exchange;
use key;
use cipher;

#[doc(hidden)]
#[derive(Debug,Clone)]
pub enum Digest {
    Sha256(sha256::Digest),
}
impl Digest {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            &Digest::Sha256(ref d) => d.as_bytes(),
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct Curve25519 {
    local_pubkey: curve25519::GroupElement,
    local_secret: curve25519::Scalar,
    remote_pubkey: Option<curve25519::GroupElement>,
    shared_secret: Option<curve25519::GroupElement>,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum Algorithm {
    Curve25519(Curve25519), // "curve25519-sha256@libssh.org"
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str { self.0 }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");

impl Algorithm {
    pub fn server_dh(name: Name,
                     exchange: &mut Exchange,
                     payload: &[u8])
                     -> Result<Algorithm, Error> {

        match name {

            CURVE25519 if payload[0] == msg::KEX_ECDH_INIT => {

                let client_pubkey = {
                    let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
                    curve25519::GroupElement::copy_from_slice(&payload[5..(5 + pubkey_len)])
                };
                let server_secret = {
                    let mut server_secret = [0; curve25519::SCALARBYTES];
                    randombytes::into(&mut server_secret);

                    // https://cr.yp.to/ecdh.html
                    server_secret[0] &= 248;
                    server_secret[31] &= 127;
                    server_secret[31] |= 64;
                    curve25519::Scalar::copy_from_slice(&server_secret)
                };

                let mut server_pubkey = curve25519::GroupElement::new_blank();
                curve25519::scalarmult_base(&mut server_pubkey, &server_secret);

                // fill exchange.
                exchange.server_ephemeral.clear();
                exchange.server_ephemeral.extend(server_pubkey.as_bytes());

                let mut shared_secret = curve25519::GroupElement::new_blank();
                curve25519::scalarmult(&mut shared_secret, &server_secret, &client_pubkey);
                debug!("server shared : {:?}", shared_secret);

                // debug!("shared secret");
                // super::hexdump(shared_secret.as_bytes());

                Ok(Algorithm::Curve25519(Curve25519 {
                    local_pubkey: server_pubkey,
                    local_secret: server_secret,
                    remote_pubkey: Some(client_pubkey),
                    shared_secret: Some(shared_secret),
                }))
            }
            _ => Err(Error::Kex),
        }
    }
    pub fn client_dh(name: Name,
                     client_ephemeral: &mut CryptoBuf,
                     buf: &mut CryptoBuf)
                     -> Result<Algorithm, Error> {

        match name {

            CURVE25519 => {

                let client_secret = {
                    let mut secret = [0; curve25519::SCALARBYTES];
                    randombytes::into(&mut secret);

                    // https://cr.yp.to/ecdh.html
                    secret[0] &= 248;
                    secret[31] &= 127;
                    secret[31] |= 64;
                    curve25519::Scalar::copy_from_slice(&secret)
                };

                let mut client_pubkey = curve25519::GroupElement::new_blank();
                curve25519::scalarmult_base(&mut client_pubkey, &client_secret);

                // fill exchange.
                client_ephemeral.clear();
                client_ephemeral.extend(client_pubkey.as_bytes());


                buf.push(msg::KEX_ECDH_INIT);
                buf.extend_ssh_string(client_pubkey.as_bytes());


                Ok(Algorithm::Curve25519(Curve25519 {
                    local_pubkey: client_pubkey,
                    local_secret: client_secret,
                    remote_pubkey: None,
                    shared_secret: None,
                }))
            }
            _ => Err(Error::Kex),
        }
    }



    pub fn compute_shared_secret(&mut self, remote_pubkey: &[u8]) -> Result<(), Error> {

        match self {
            &mut Algorithm::Curve25519(ref mut kex) => {

                let server_public = curve25519::GroupElement::copy_from_slice(remote_pubkey);
                let mut shared_secret = curve25519::GroupElement::new_blank();
                curve25519::scalarmult(&mut shared_secret, &kex.local_secret, &server_public);

                debug!("client shared : {:?}", shared_secret);

                kex.shared_secret = Some(shared_secret);
                Ok(())
            }
        }

    }

    pub fn compute_exchange_hash<K:key::PubKey>(&self,
                                                key: &K,
                                                exchange: &Exchange,
                                                buffer: &mut CryptoBuf)
                                                -> Result<Digest, Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        match self {
            &Algorithm::Curve25519(ref kex) => {

                debug!("{:?} {:?}",
                       std::str::from_utf8(exchange.client_id.as_slice()),
                       std::str::from_utf8(exchange.server_id.as_slice()));
                buffer.clear();
                buffer.extend_ssh_string(exchange.client_id.as_slice());
                buffer.extend_ssh_string(exchange.server_id.as_slice());
                buffer.extend_ssh_string(exchange.client_kex_init.as_slice());
                buffer.extend_ssh_string(exchange.server_kex_init.as_slice());


                key.push_to(buffer);
                debug!("client_ephemeral: {:?}", exchange.client_ephemeral.as_slice());
                debug_assert_eq!(exchange.client_ephemeral.len(), 32);
                buffer.extend_ssh_string(exchange.client_ephemeral.as_slice());

                debug_assert_eq!(exchange.server_ephemeral.len(), 32);
                buffer.extend_ssh_string(exchange.server_ephemeral.as_slice());

                debug!("shared: {:?}", kex.shared_secret);
                // unimplemented!(); // Should be in wire format.
                if let Some(ref shared) = kex.shared_secret {
                    buffer.extend_ssh_mpint(shared.as_bytes());
                } else {
                    return Err(Error::Kex);
                }
                debug!("buffer len = {:?}", buffer.len());
                debug!("buffer: {:?}", buffer.as_slice());
                // super::hexdump(buffer);
                let mut hash = sha256::Digest::new_blank();
                sha256::hash(&mut hash, buffer.as_slice());
                debug!("hash: {:?}", hash);
                Ok(Digest::Sha256(hash))
            }
            // _ => Err(Error::Kex)
        }
    }


    pub fn compute_keys(&self,
                        session_id: &Digest,
                        exchange_hash: &Digest,
                        buffer: &mut CryptoBuf,
                        key: &mut CryptoBuf,
                        cipher: cipher::Name,
                        is_server: bool)
                        -> Result<super::cipher::CipherPair, Error> {
        match self {
            &Algorithm::Curve25519(ref kex) => {

                // https://tools.ietf.org/html/rfc4253#section-7.2
                let mut compute_key = |c, key: &mut CryptoBuf, len| {

                    buffer.clear();
                    key.clear();

                    if let Some(ref shared) = kex.shared_secret {
                        buffer.extend_ssh_mpint(shared.as_bytes());
                    }

                    buffer.extend(exchange_hash.as_bytes());
                    buffer.push(c);
                    buffer.extend(session_id.as_bytes());
                    let mut hash = sha256::Digest::new_blank();
                    sha256::hash(&mut hash, buffer.as_slice());
                    key.extend(hash.as_bytes());

                    while key.len() < len {
                        // extend.
                        buffer.clear();
                        if let Some(ref shared) = kex.shared_secret {
                            buffer.extend_ssh_mpint(shared.as_bytes());
                        }
                        buffer.extend(exchange_hash.as_bytes());
                        buffer.extend(key.as_slice());
                        let mut hash = sha256::Digest::new_blank();
                        sha256::hash(&mut hash, buffer.as_slice());
                        key.extend(hash.as_bytes())
                    }
                };

                match cipher {
                    super::cipher::CHACHA20POLY1305 => {

                        let client_to_server = {
                            compute_key(b'C', key, super::cipher::key_size(cipher));
                            super::cipher::Cipher::Chacha20Poly1305 (
                                super::cipher::chacha20poly1305::Cipher::init(key.as_slice())
                            )
                        };
                        let server_to_client = {
                            compute_key(b'D', key, super::cipher::key_size(cipher));
                            super::cipher::Cipher::Chacha20Poly1305 (
                                super::cipher::chacha20poly1305::Cipher::init(key.as_slice())
                            )
                        };

                        Ok(if is_server {
                            super::cipher::CipherPair {
                                local_to_remote: server_to_client,
                                remote_to_local: client_to_server,
                            }
                        } else {
                            super::cipher::CipherPair {
                                local_to_remote: client_to_server,
                                remote_to_local: server_to_client,
                            }
                        })
                    }
                    _ => Err(Error::DH),
                }
            }
            // _ => unimplemented!()
        }
    }
}
