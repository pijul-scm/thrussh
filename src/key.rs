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
use cryptobuf::CryptoBuf;
use negociation::Named;
use Error;
use encoding::Reader;
use ring::{digest, rand, signature};
use std;
use rustc_serialize::base64::{ToBase64, STANDARD};
use untrusted;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const ED25519: Name = Name("ssh-ed25519");

impl Name {
    /// Base name of the private key file for a key name.
    pub fn identity_file(&self) -> &'static str {
        match *self {
            ED25519 => "id_ed25519",
            _ => unreachable!()
        }
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

#[derive(Debug,Clone, PartialEq, Eq)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(Vec<u8>),
}

impl std::ops::Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            PublicKey::Ed25519(ref k) => k
        }
    }
}

#[doc(hidden)]
impl PublicKey {
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                try!(p.read_string()); // XXX: don't we need to compare this to something or something?
                let key_bytes = try!(p.read_string());
                if key_bytes.len() != 32 /*XXX*/ {
                    return Err(Error::Inconsistent/*XXX*/);
                }
                Ok(PublicKey::Ed25519(Vec::from(key_bytes)))
            }
            _ => Err(Error::UnknownKey),
        }
    }
}

impl PublicKey {
    pub fn fingerprint(&self) -> String {
        match self {
            &PublicKey::Ed25519(ref public) => {
                let digest = digest::digest(&digest::SHA256, &public);
                "SHA256: ".to_string() + &digest.as_ref().to_base64(STANDARD)
            }
        }
    }
}
impl Verify for PublicKey {
    fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                signature::verify(&signature::ED25519,
                                  untrusted::Input::from(public),
                                  untrusted::Input::from(buffer),
                                  untrusted::Input::from(sig)).is_ok()
            }
        }
    }
}

#[derive(Clone)]
pub enum Algorithm {
    // `Arc` is used so that `Algorithm` can be `Clone` given `Ed25519KeyPair`
    // isn't.
    #[doc(hidden)]
    Ed25519(std::sync::Arc<signature::Ed25519KeyPair>),
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Algorithm::Ed25519(ref key_pair) => {
                write!(f, "Ed25519 {{ public: {:?}, secret: (hidden) }}",
                       key_pair.public_key_bytes())
            }
        }
    }
}
#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoBuf);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoBuf) {
        match self {
            &PublicKey::Ed25519(ref public) => {

                buffer.push_u32_be((ED25519.0.len() + public.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public);
            }
        }
    }
}

impl PubKey for Algorithm {
    fn push_to(&self, buffer: &mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519(ref key_pair) => {
                let public = key_pair.public_key_bytes();
                buffer.push_u32_be((ED25519.0.len() + public.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public);
            }
        }
    }
}


impl Named for PublicKey {
    fn name(&self) -> &'static str {
        match self {
            &PublicKey::Ed25519(_) => ED25519.0,
        }
    }
}

impl Named for Algorithm {
    fn name(&self) -> &'static str {
        match self {
            &Algorithm::Ed25519(..) => ED25519.0,
        }
    }
}

impl Algorithm {
    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> PublicKey {
        match self {
            &Algorithm::Ed25519(ref key_pair) =>
                PublicKey::Ed25519(Vec::from(key_pair.public_key_bytes()))
        }
    }

    /// Generate a key pair.
    pub fn generate_keypair(t: Name) -> Option<Self> {
        match t {
            ED25519 => {
                // TODO: take `rng` as a parameter.
                let rng = rand::SystemRandom::new();
                signature::Ed25519KeyPair::generate(&rng)
                    .map(|key_pair| Algorithm::Ed25519(std::sync::Arc::new(key_pair))).ok()
            }
            _ => None,
        }
    }

    #[doc(hidden)]
    pub fn add_signature(&self, buffer: &mut CryptoBuf, hash: &digest::Digest) {
        match self {
            &Algorithm::Ed25519(ref key_pair) => {
                // XXX: Is this right? We use Ed25519 to sign a digest, so that
                // there is an extra level of digesting, to simulate a prehash
                // variant?
                let signature = key_pair.sign(hash.as_ref());
                let signature = signature.as_slice();

                buffer.push_u32_be((ED25519.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(signature);
            }
        }
    }

    #[doc(hidden)]
    pub fn add_self_signature(&self, buffer: &mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519(ref key_pair) => {
                // XXX: Is this right? Above, we do a double hashing, but here
                // we're doing single hashing!
                let signature = key_pair.sign(&buffer);
                let signature = signature.as_slice();

                buffer.push_u32_be((ED25519.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(signature);
            }
        }
    }
}
