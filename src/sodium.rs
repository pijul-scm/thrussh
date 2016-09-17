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

// Some parts of this module come from sodiumoxide, (c) 2013 Daniel Ashhami, under an MIT licence.

use super::libsodium_sys;
pub fn init() -> bool {
    unsafe { libsodium_sys::sodium_init() != -1 }
}

use super::libc::{size_t, c_void};

extern "C" {
    pub fn sodium_mlock(p: *mut c_void, len: size_t);
    pub fn sodium_munlock(p: *mut c_void, len: size_t);
}


macro_rules! newtype (($newtype:ident, $len:expr) => {
    pub struct $newtype([u8;$len]);
    impl std::fmt::Debug for $newtype {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}({:?})", stringify!($newtype), &self.0[..])
        }
    }
});

macro_rules! new_blank (($newtype:ident, $len:expr) => {
    impl $newtype {
        pub fn new_blank() -> Self {
            $newtype([0;$len])
        }
    }
});
macro_rules! from_slice (($newtype:ident, $len:expr) => (
    impl $newtype {
        pub fn copy_from_slice(s: &[u8]) -> Self {
            debug_assert!(s.len() == $len);
            let mut x = $newtype([0;$len]);
            (&mut x.0).clone_from_slice(s);
            x
        }
    }
));
macro_rules! as_bytes (($newtype:ident) => (
    impl std::ops::Deref for $newtype {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }
));

macro_rules! clone (($newtype:ident) => (
    impl Clone for $newtype {
        fn clone(&self) -> Self {
            Self::copy_from_slice(self)
        }
    }
));

pub mod randombytes {
    use super::super::libsodium_sys;

    pub fn into(buf: &mut [u8]) {
        unsafe {
            libsodium_sys::randombytes_buf(buf.as_mut_ptr(), buf.len());
        }
    }
}


pub mod curve25519 {
    use super::super::libsodium_sys;

    pub const GROUPELEMENTBYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES;
    pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_SCALARBYTES;

    use std;
    newtype!(Scalar, SCALARBYTES);
    from_slice!(Scalar, SCALARBYTES);
    newtype!(GroupElement, GROUPELEMENTBYTES);
    from_slice!(GroupElement, GROUPELEMENTBYTES);
    new_blank!(GroupElement, GROUPELEMENTBYTES);
    as_bytes!(GroupElement);


    pub fn scalarmult(q: &mut GroupElement,
                      &Scalar(ref n): &Scalar,
                      &GroupElement(ref p): &GroupElement) {
        unsafe {
            libsodium_sys::crypto_scalarmult_curve25519(&mut q.0, n, p);
        }
    }

    pub fn scalarmult_base(q: &mut GroupElement, &Scalar(ref n): &Scalar) {
        unsafe {
            libsodium_sys::crypto_scalarmult_curve25519_base(&mut q.0, n);
        }
    }
}

pub mod ed25519 {
    use super::super::libsodium_sys;
    use super::super::libc::c_ulonglong;
    use std;

    pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_sign_ed25519_PUBLICKEYBYTES;
    pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_sign_ed25519_SECRETKEYBYTES;
    pub const SIGNATUREBYTES: usize = libsodium_sys::crypto_sign_ed25519_BYTES;

    #[derive(Debug, PartialEq, Eq)]
    pub struct PublicKey([u8; PUBLICKEYBYTES]);
    impl std::cmp::PartialEq<[u8]> for PublicKey {
        fn eq(&self, x:&[u8]) -> bool {
            &self.0 == x
        }
    }
    // newtype!(PublicKey, PUBLICKEYBYTES);
    as_bytes!(PublicKey);
    from_slice!(PublicKey, PUBLICKEYBYTES);
    clone!(PublicKey);

    newtype!(Signature, SIGNATUREBYTES);
    as_bytes!(Signature);
    from_slice!(Signature, SIGNATUREBYTES);
    clone!(Signature);
    new_blank!(Signature, SIGNATUREBYTES);

    newtype!(SecretKey, SECRETKEYBYTES);
    as_bytes!(SecretKey);
    from_slice!(SecretKey, SECRETKEYBYTES);
    clone!(SecretKey);

    pub fn generate_keypair() -> Option<(PublicKey, SecretKey)> {
        unsafe {
            let mut pk = [0; PUBLICKEYBYTES];
            let mut sk = [0; SECRETKEYBYTES];
            if libsodium_sys::crypto_sign_ed25519_keypair(&mut pk, &mut sk) == 0 {
                Some((PublicKey(pk), SecretKey(sk)))
            } else {
                None
            }
        }
    }

    pub fn sign_detached(signature: &mut Signature, m: &[u8], &SecretKey(ref sk): &SecretKey) {
        unsafe {
            let mut siglen: c_ulonglong = 0;
            libsodium_sys::crypto_sign_ed25519_detached(&mut signature.0,
                                                        &mut siglen,
                                                        m.as_ptr(),
                                                        m.len() as c_ulonglong,
                                                        sk);
            assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
        }
    }

    pub fn verify_detached(signature: &Signature,
                           m: &[u8],
                           &PublicKey(ref pk): &PublicKey)
                           -> bool {
        unsafe {
            let ret = libsodium_sys::crypto_sign_ed25519_verify_detached(&signature.0,
                                                                         m.as_ptr(),
                                                                         m.len() as c_ulonglong,
                                                                         pk);
            ret == 0
        }
    }

}
