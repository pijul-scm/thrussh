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
use super::sodium::ed25519;
use cryptobuf::CryptoBuf;
use negociation::Named;
use Error;
use encoding::Reader;
use std;
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str { self.0 }
}
pub const ED25519: Name = Name("ssh-ed25519");

#[doc(hidden)]
pub trait Verify {
    fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

#[derive(Debug,Clone, PartialEq, Eq)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(ed25519::PublicKey),
}

#[doc(hidden)]
impl PublicKey {
    pub fn parse(algo:&[u8], pubkey:&[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                try!(p.read_string());
                Ok(PublicKey::Ed25519(
                    ed25519::PublicKey::copy_from_slice(try!(p.read_string()))
                ))
            }
            _ => Err(Error::UnknownKey),
        }
    }
}

impl Verify for PublicKey {
    fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                let sig = ed25519::Signature::copy_from_slice(sig);
                ed25519::verify_detached(&sig, buffer, public)
            }
        }
    }
}

#[derive(Clone)]
pub enum Algorithm {
    #[doc(hidden)]
    Ed25519 { public:ed25519::PublicKey, secret: ed25519::SecretKey }
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::Ed25519 { ref public, .. } => {
                write!(f, "Ed25519 {{ public: {:?}, secret: (hidden) }}", public)
            }
        }
    }
}
#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer:&mut CryptoBuf);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer:&mut CryptoBuf) {
        match self {
            &PublicKey::Ed25519(ref public) => {

                buffer.push_u32_be((ED25519.0.len() + ed25519::PUBLICKEYBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
        }
    }
}

impl PubKey for Algorithm {
    fn push_to(&self, buffer:&mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519 { ref public, .. } => {

                buffer.push_u32_be((ED25519.0.len() + ed25519::PUBLICKEYBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public.as_bytes());
            }
        }
    }
}


impl Named for PublicKey {
    fn name(&self) -> &'static str {
        match self {
            &PublicKey::Ed25519(_) => ED25519.0
        }
    }
}

impl Named for Algorithm {
    fn name(&self) -> &'static str {
        match self {
            &Algorithm::Ed25519 {..} => ED25519.0
        }
    }
}

impl Algorithm {

    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> PublicKey {
        match self {
            &Algorithm::Ed25519 { ref public, .. } => PublicKey::Ed25519(public.clone())
        }
    }
    
    /// Generate a key pair.
    pub fn generate_keypair(t:Name) -> Option<Self> {
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

    #[doc(hidden)]
    pub fn add_signature(&self, buffer: &mut CryptoBuf, hash: &[u8]) {
        match self {
            &Algorithm::Ed25519 { ref secret, .. } => {

                let mut sign = ed25519::Signature::new_blank();
                ed25519::sign_detached(&mut sign, hash, secret);

                buffer.push_u32_be((ED25519.0.len() + ed25519::SIGNATUREBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(sign.as_bytes());
            }
        }
    }

    #[doc(hidden)]
    pub fn add_self_signature(&self, buffer: &mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519 { ref secret, .. } => {

                let mut sign = ed25519::Signature::new_blank();
                ed25519::sign_detached(&mut sign, buffer.as_slice(), secret);

                buffer.push_u32_be((ED25519.0.len() + ed25519::SIGNATUREBYTES + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(sign.as_bytes());
            }
        }
    }
}
