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

use std::ops::Sub;
use super::key;
use super::CryptoBuf;
use super::encoding;

#[derive(Clone,Debug,Copy,PartialEq,Eq)]
pub struct M(u32);
pub const NONE: M = M(1);
pub const PASSWORD: M = M(2);
pub const PUBKEY: M = M(4);
pub const HOSTBASED: M = M(8);

#[derive(Debug)]
pub enum Method<'a> {
    None,
    Password {
        user: &'a str,
        password: &'a str,
    },
    Pubkey {
        user: &'a str,
        pubkey: key::PublicKey,
        seckey: Option<key::SecretKey>,
    },
    Hostbased,
}
impl<'a> Method<'a> {
    fn num(&self) -> M {
        match *self {
            Method::None => NONE,
            Method::Password { .. } => PASSWORD,
            Method::Pubkey { .. } => PUBKEY,
            Method::Hostbased => HOSTBASED,
        }
    }
}
impl encoding::Bytes for M {
    fn bytes(&self) -> &'static [u8] {
        match *self {
            NONE => b"none",
            PASSWORD => b"password",
            PUBKEY => b"publickey",
            HOSTBASED => b"hostbased",
            _ => unreachable!(),
        }
    }
}

// Each group of four bits is one method.
#[derive(Debug,Clone,Copy)]
pub struct Methods {
    list: u32,
    set: u32,
}

impl Methods {
    fn new(s: &[M]) -> Methods {
        let mut list: u32 = 0;
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
        Methods {
            list: list,
            set: set,
        }
    }
    pub fn keep_remaining<'a, I: Iterator<Item = &'a [u8]>>(&mut self, i: I) {
        for name in i {
            let x = match name {
                b"password" => Some(PASSWORD),
                b"publickey" => Some(PUBKEY),
                b"none" => Some(NONE),
                b"hostbased" => Some(HOSTBASED),
                _ => None,
            };
            if let Some(M(i)) = x {
                self.set &= i as u32;
            }
        }
    }
    pub fn all() -> Methods {
        Self::new(&[PUBKEY, PASSWORD, HOSTBASED])
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
            if result == 0 {
                None
            } else {
                Some(M(result))
            }
        }
    }
}

impl Methods {
    pub fn peek(&self) -> Option<M> {
        if self.list == 0 {
            None
        } else {
            let mut result = self.list & 0xf;
            let mut list = self.list;
            list >>= 4;

            // while this method is not in the set of allowed methods, pop the list.
            while (list != 0) && (result & self.set == 0) {
                result = list & 0xf;
                list >>= 4;
            }
            if list == 0 {
                None
            } else {
                Some(M(result))
            }
        }
    }
}

impl<'a> Sub<&'a Method<'a>> for Methods {
    type Output = Methods;
    fn sub(mut self, m: &Method) -> Self::Output {
        let M(m) = m.num();
        self.set &= !m;
        self
    }
}

#[derive(Debug)]
pub enum Auth {
    Success,
    Reject {
        remaining_methods: Methods,
        partial_success: bool,
    },
}

pub trait Authenticate {
    fn auth(&self, methods: Methods, method: &Method) -> Auth {
        Auth::Reject {
            remaining_methods: methods - method,
            partial_success: false,
        }
    }
}

#[derive(Debug)]
pub struct AuthRequest {
    pub methods: Methods,
    pub partial_success: bool,
    pub public_key: CryptoBuf,
    pub public_key_algorithm: CryptoBuf,
    pub public_key_is_ok: bool,
    pub sent_pk_ok: bool,
}
