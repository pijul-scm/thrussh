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
pub use super::sodium::ed25519;
use cryptobuf::CryptoBuf;
use negociation::Named;

pub const ED25519: &'static str = "ssh-ed25519";

#[derive(Debug,Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
}

#[derive(Debug,Clone)]
pub enum Algorithm {
    Ed25519 { public:ed25519::PublicKey, secret: ed25519::SecretKey }
}

pub trait PubKey {
    fn push_to(&self, buffer:&mut CryptoBuf);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer:&mut CryptoBuf) {
        match self {
            &PublicKey::Ed25519(ref public) => {

                buffer.push_u32_be((ED25519.len() + ed25519::PUBLICKEYBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
        }
    }
}

impl PubKey for Algorithm {
    fn push_to(&self, buffer:&mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519 { ref public, .. } => {

                buffer.push_u32_be((ED25519.len() + ed25519::PUBLICKEYBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
        }
    }
}


impl PublicKey {
    pub fn name(&self) -> &'static str {
        match self {
            &PublicKey::Ed25519(_) => ED25519
        }
    }
}

impl Named for Algorithm {
    fn name(&self) -> &'static str {
        match self {
            &Algorithm::Ed25519 {..} => ED25519
        }
    }
}

impl Algorithm {

    pub fn generate_keypair(t:&str) -> Option<Self> {
        match t {
            ED25519 => {
                if let Some((pk,sk)) = super::sodium::ed25519::generate_keypair() {
                    Some(Algorithm::Ed25519 {
                        public:pk,
                        secret:sk
                    })
                } else {
                    None
                }
            },
            _ => None
        }
    }
    
    pub fn add_signature(&self, buffer: &mut CryptoBuf, hash: &[u8]) {
        match self {
            &Algorithm::Ed25519 { ref secret, .. } => {

                let mut sign = ed25519::Signature::new_blank();
                ed25519::sign_detached(&mut sign, hash, secret);

                buffer.push_u32_be((ED25519.len() + ed25519::SIGNATUREBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.as_bytes());
                buffer.extend_ssh_string(sign.as_bytes());
            }
        }
    }
}
