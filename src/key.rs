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
use super::{Error};
pub use super::sodium::ed25519;
use cryptobuf::CryptoBuf;

pub const ED25519: &'static str = "ssh-ed25519";

#[derive(Debug,Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
}
#[derive(Debug,Clone)]
pub enum SecretKey {
    Ed25519(ed25519::SecretKey),
}


impl PublicKey {
    pub fn extend_pubkey(&self, buffer: &mut CryptoBuf) {
        match self {
            &PublicKey::Ed25519(ref public_host_key) => {

                buffer.push_u32_be((ED25519.len() + ed25519::PUBLICKEYBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.as_bytes());
                buffer.extend_ssh_string(public_host_key.as_bytes());
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            &PublicKey::Ed25519(_) => "ssh-ed25519",
        }
    }
}


#[derive(Debug,Clone)]
pub struct Algorithm {
    pub public_host_key: PublicKey,
    pub secret_host_key: SecretKey,
}

use std::path::Path;
impl Algorithm {
    pub fn load_keypair_ed25519<P: AsRef<Path>, Q: AsRef<Path>>(public: P,
                                                                secret: Q)
                                                                -> Result<Algorithm, Error> {
        Ok(Algorithm {
            public_host_key: try!(super::load_public_key(public)),
            secret_host_key: try!(super::load_secret_key(secret)),
        })
    }

    pub fn name(&self) -> &'static str {
        self.public_host_key.name()
    }

    pub fn add_signature(&self, buffer: &mut CryptoBuf, hash: &[u8]) {
        match self.secret_host_key {
            SecretKey::Ed25519(ref secret_host_key) => {

                let mut sign = ed25519::Signature::new_blank();
                ed25519::sign_detached(&mut sign, hash, secret_host_key);

                buffer.push_u32_be((ED25519.len() + ed25519::SIGNATUREBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.as_bytes());
                buffer.extend_ssh_string(sign.as_bytes());
            }
        }
    }
}
