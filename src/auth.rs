use std::ops::Sub;

#[derive(Clone,Debug,Copy,PartialEq,Eq)]
pub struct M(u32);
pub const NONE:M = M(1);
pub const PASSWORD:M = M(2);
pub const PUBKEY:M = M(4);
pub const HOSTBASED:M = M(8);

#[derive(Debug)]
pub enum Method<'a> {
    None,
    Password { user:&'a str, password:&'a str },
    Pubkey { user:&'a str, algo: &'a str, pubkey: super::key::PublicKey },
    Hostbased
}
impl<'a> Method<'a> {
    fn num(&self) -> M {
        match self {
            &Method::None => NONE,
            &Method::Password { .. } => PASSWORD,
            &Method::Pubkey { .. } => PUBKEY,
            &Method::Hostbased => HOSTBASED
        }
    }
}
impl super::Bytes for M {
    fn bytes(&self) -> &'static [u8] {
        match *self {
            NONE => b"none",
            PASSWORD => b"password",
            PUBKEY => b"publickey",
            HOSTBASED => b"hostbased",
            _ => unreachable!()
        }
    }
}

// Each group of four bits is one method.
#[derive(Debug,Clone,Copy)]
pub struct Methods {
    list: u32,
    set: u32
}

impl Methods {
    fn new(s:&[M]) -> Methods {
        let mut list:u32 = 0;
        let mut set: u32 = 0;
        let mut shift = 0;
        for &M(i) in s {
            if set & (i) == 0 {
                // If we don't have that method already
                list |= (i as u32) << shift;
                set |= i as u32;
                shift += 4
            }
        }
        Methods { list: list, set: set }
    }
    pub fn all() -> Methods {
        Self::new(&[ PUBKEY, PASSWORD, HOSTBASED ])
    }
}

impl Iterator for Methods {
    type Item = M;
    fn next(&mut self) -> Option<Self::Item> {
        if self.list == 0 {
            None
        } else {
            debug_assert!(self.list & 0xf != 0);
            let mut result = self.list & 0xf;
            self.list >>= 4;

            // while this method is not in the set of allowed methods, pop the list.
            while (self.list != 0) && (result & self.set == 0) {
                result = self.list & 0xf;
                self.list >>= 4;
            }
            if self.list == 0 {
                None
            } else {
                Some(M(result))
            }
        }
    }
}

impl<'a> Sub<&'a Method<'a>> for Methods {
    type Output = Methods;
    fn sub(mut self, m:&Method) -> Self::Output {
        let M(m) = m.num();
        self.set &= !m;
        self
    }
}

#[derive(Debug)]
pub enum Auth {
    Success,
    Reject { remaining_methods:Methods, partial_success:bool },
}

use byteorder::{ByteOrder,BigEndian, ReadBytesExt};
use std;

use super::CryptoBuf;
#[derive(Debug)]
pub struct AuthRequest {
    pub methods: Methods,
    pub partial_success: bool,
    pub public_key: CryptoBuf,
    pub public_key_algorithm: CryptoBuf,
    pub sent_pk_ok: bool
}

use super::sodium;
use super::key;
pub trait Authenticate {
    fn auth(&self, methods:Methods, method:&Method) -> Auth {
        Auth::Reject { remaining_methods: methods - method, partial_success: false }
    }
}

impl AuthRequest {
    
    pub fn auth_request<A:Authenticate>(mut self, config:&super::config::Config<A>, buf:&[u8]) -> super::EncryptedState {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut pos = 1;
        let next = |pos:&mut usize| {
            let name_len = BigEndian::read_u32(&buf[*pos..]) as usize;
            *pos += 4;
            let name = &buf[*pos..(*pos+name_len)];
            *pos += name_len;
            name
        };

        let name = next(&mut pos);
        let name = std::str::from_utf8(name).unwrap();
        let service_name = next(&mut pos);
        let method = next(&mut pos);
        debug!("name: {:?} {:?} {:?}",
               name, std::str::from_utf8(service_name),
               std::str::from_utf8(method));

        if service_name == b"ssh-connection" {

            if method == b"password" {

                // let x = buf[pos];
                // println!("is false? {:?}", x);
                pos+=1;
                let password = next(&mut pos);
                let password = std::str::from_utf8(password).unwrap();
                let method = Method::Password {
                    user: name,
                    password: password
                };
                match config.auth.auth(self.methods, &method) {
                    Auth::Success => {
                        
                        super::EncryptedState::AuthRequestSuccess
                    },
                    Auth::Reject { remaining_methods, partial_success } => {
                        self.methods = remaining_methods;
                        self.partial_success = partial_success;

                        super::EncryptedState::RejectAuthRequest(self)
                    },
                }

            } else if method == b"publickey" {

                // let is_not_probe = buf[pos];
                pos+=1;
                let pubkey_algo = next(&mut pos);
                let pubkey = next(&mut pos);

                let pubkey_ = match pubkey_algo {
                    b"ssh-ed25519" => {
                        let len = BigEndian::read_u32(pubkey) as usize;
                        let publen = BigEndian::read_u32(&pubkey[len+4 .. ]) as usize;
                        key::PublicKey::Ed25519(
                            sodium::ed25519::PublicKey::copy_from_slice(&pubkey[len + 8 .. len+8+publen])
                        )
                    },
                    _ => unimplemented!()
                };
                let method = Method::Pubkey {
                    user: name,
                    algo: std::str::from_utf8(pubkey_algo).unwrap(),
                    pubkey: pubkey_,
                };

                match config.auth.auth(self.methods, &method) {
                    Auth::Success => {
                        

                        // Public key ?
                        self.public_key.extend(pubkey);
                        self.public_key_algorithm.extend(pubkey_algo);

                        super::EncryptedState::WaitingSignature(self)
                        
                    },
                    Auth::Reject { remaining_methods, partial_success } => {

                        self.methods = remaining_methods;
                        self.partial_success = partial_success;

                        super::EncryptedState::RejectAuthRequest(self)
                            
                    },
                }
            } else {
                // Other methods of the base specification are insecure or optional.
                super::EncryptedState::RejectAuthRequest(self)
            }
        } else {
            // Unknown service
            unimplemented!()
        }

    }


    pub fn waiting_signature(self, buf:&[u8], session_id:&[u8], buffer:&mut CryptoBuf) -> super::EncryptedState {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut pos = 1;
        let next = |pos:&mut usize| {
            let name_len = BigEndian::read_u32(&buf[*pos..]) as usize;
            *pos += 4;
            let name = &buf[*pos..(*pos+name_len)];
            *pos += name_len;
            name
        };

        let user_name = next(&mut pos);
        let service_name = next(&mut pos);
        let method = next(&mut pos);
        let is_probe = buf[pos] == 0;
        pos += 1;
        // TODO: check that the user is the same (maybe?)
        if service_name == b"ssh-connection" && method == b"publickey" && !is_probe {

            let algo = next(&mut pos);
            let key = next(&mut pos);
            debug!("key: {:?}", key);
            let pos0 = pos;
            if algo == b"ssh-ed25519" {
                let signature = next(&mut pos);
                let algo_len = BigEndian::read_u32(signature) as usize;
                let algo_ = &signature[4..4+algo_len];
                let sig_len = BigEndian::read_u32(&signature[4+algo_len..]) as usize;
                let sig = &signature[8+algo_len .. 8+algo_len+sig_len];
                // println!("sig: {:?}", sig);
                let sig = sodium::ed25519::Signature::copy_from_slice(
                    sig
                );
                
                let key = {
                    let algo_len = BigEndian::read_u32(key) as usize;
                    // let algo_ = &key[4..4+algo_len];
                    let key_len = BigEndian::read_u32(&key[4+algo_len..]) as usize;
                    &key[8+algo_len .. 8+algo_len + key_len]
                };
                
                let key = sodium::ed25519::PublicKey::copy_from_slice(
                    key
                );
                buffer.clear();
                buffer.extend_ssh_string(session_id);
                buffer.extend(&buf[0..pos0]);
                // println!("message: {:?}", buffer.as_slice());
                // println!("verify:{:?}", sodium::ed25519::verify_detached(&sig, buffer.as_slice(), &key));
                assert!(algo == algo_);
                
                
                // Verify signature.
                if sodium::ed25519::verify_detached(&sig, buffer.as_slice(), &key) {
                    super::EncryptedState::AuthRequestSuccess
                } else {
                    super::EncryptedState::RejectAuthRequest(self)
                }
            } else {
                super::EncryptedState::RejectAuthRequest(self)
            }
        } else {
            super::EncryptedState::RejectAuthRequest(self)
        }
    }
}
