use super::negociation::{ Named, Preferred };
use super::CryptoBuf;
pub use super::sodium::ed25519;

#[derive(Debug,Clone)]
pub enum Name {
    Ed25519 // "ssh-ed25519"
}

#[derive(Debug,Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey)
}

#[derive(Debug,Clone)]
pub enum Algorithm {
    Ed25519 {
        public_host_key: ed25519::PublicKey,
        secret_host_key: ed25519::SecretKey
    } // "ssh-ed25519"
}


pub const KEY_ED25519:&'static str = "ssh-ed25519";
pub const KEY_ALGORITHMS: &'static [&'static str;1] = &[
    KEY_ED25519
];

impl Named for Name {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == KEY_ED25519.as_bytes() {
            return Some(Name::Ed25519)
        }
        None
    }
}

impl Preferred for Algorithm {
    fn preferred() -> &'static [&'static str] {
        KEY_ALGORITHMS
    }
}
impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            &Algorithm::Ed25519 { .. } => "ssh-ed25519"
        }
    }

    pub fn write_pubkey(&self, buffer:&mut CryptoBuf) {
        match self {
            &Algorithm::Ed25519 { ref public_host_key, .. } => {

                buffer.push_u32_be(
                    (KEY_ED25519.len()
                     + ed25519::PUBLICKEYBYTES
                     + 8) as u32
                );
                buffer.extend_ssh_string(KEY_ED25519.as_bytes());
                buffer.extend_ssh_string(public_host_key.as_bytes());
            }
        }
    }
    
    pub fn add_signature(&self, buffer: &mut CryptoBuf, hash:&[u8]) {
        match self {
            &Algorithm::Ed25519 { ref secret_host_key, .. } => {

                let mut sign = ed25519::Signature::new_blank();
                ed25519::sign_detached(&mut sign, &hash, secret_host_key);

                buffer.push_u32_be(
                    (KEY_ED25519.len()
                     + ed25519::SIGNATUREBYTES
                     + 8) as u32
                );
                buffer.extend_ssh_string(KEY_ED25519.as_bytes());
                buffer.extend_ssh_string(sign.as_bytes());
            }
        }
    }
}
