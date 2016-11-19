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

use encoding;
use cryptovec::CryptoVec;

/// Set of methods, represented by bit flags.
bitflags! {
    pub flags MethodSet: u32 {
        const NONE = 1,
        const PASSWORD = 2,
        const PUBLICKEY = 4,
        const HOSTBASED = 8,
        const KEYBOARD_INTERACTIVE = 16
    }
}

macro_rules! iter {
    ( $y:expr, $x:expr ) => {
        {
            if $y.contains($x) {
                $y.remove($x);
                return Some($x)
            }
        }
    };
}


impl Iterator for MethodSet {
    type Item = MethodSet;
    fn next(&mut self) -> Option<MethodSet> {
        iter!(self, NONE);
        iter!(self, PASSWORD);
        iter!(self, PUBLICKEY);
        iter!(self, HOSTBASED);
        iter!(self, KEYBOARD_INTERACTIVE);
        None
    }
}

#[derive(Debug)]
pub enum Method<K> {
    // None,
    Password {
        password: String,
    },
    PublicKey {
        key: K,
    }, // Hostbased,
}

impl encoding::Bytes for MethodSet {
    fn bytes(&self) -> &'static [u8] {
        match *self {
            NONE => b"none",
            PASSWORD => b"password",
            PUBLICKEY => b"publickey",
            HOSTBASED => b"hostbased",
            KEYBOARD_INTERACTIVE => b"keyboard-interactive",
            _ => b"",
        }
    }
}

impl MethodSet {
    pub fn from_bytes(b: &[u8]) -> Option<MethodSet> {
        match b {
            b"none" => Some(NONE),
            b"password" => Some(PASSWORD),
            b"publickey" => Some(PUBLICKEY),
            b"hostbased" => Some(HOSTBASED),
            b"keyboard-interactive" => Some(KEYBOARD_INTERACTIVE),
            _ => None,
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct AuthRequest {
    pub methods: MethodSet,
    pub partial_success: bool,
    pub current: Option<CurrentRequest>,
    pub rejection_count: usize
}

#[doc(hidden)]
#[derive(Debug)]
pub enum CurrentRequest {
    PublicKey {
        key: CryptoVec,
        algo: CryptoVec,
        sent_pk_ok: bool
    },
    KeyboardInteractive {
        submethods: String
    }
}
