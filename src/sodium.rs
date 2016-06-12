// Some parts of this module come from sodiumoxide, (c) 2013 Daniel Ashhami, under an MIT licence.
use super::libsodium_sys;
pub fn init() -> bool {
    unsafe {
        libsodium_sys::sodium_init() != -1
    }
}

pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false
    }
    unsafe {
        libsodium_sys::sodium_memcmp(x.as_ptr(), y.as_ptr(), x.len()) == 0
    }
}
use super::libc::{size_t,c_void};

extern "C" {
    pub fn sodium_mlock(p:*mut c_void, len:size_t);
    pub fn sodium_munlock(p:*mut c_void, len:size_t);
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
    impl $newtype {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] {
            &self.0
        }
    }
));

macro_rules! clone (($newtype:ident) => (
    impl Clone for $newtype {
        fn clone(&self) -> Self {
            Self::copy_from_slice(self.as_bytes())
        }
    }
));


pub mod chacha20 {
    use super::super::libc::{c_ulonglong,c_int};
    use super::super::libsodium_sys;
    pub const KEYBYTES:usize = libsodium_sys::crypto_stream_chacha20_KEYBYTES;
    pub const NONCEBYTES:usize = libsodium_sys::crypto_stream_chacha20_NONCEBYTES;
    use std;
    newtype!(Key,KEYBYTES);
    from_slice!(Key,KEYBYTES);
    newtype!(Nonce,NONCEBYTES);
    from_slice!(Nonce,NONCEBYTES);

    #[cfg(test)]
    pub fn gen_key() -> Key {
        let mut key = Key([0; KEYBYTES]);
        super::randombytes::into(&mut key.0);
        key
    }
    pub fn stream_xor_inplace(m: &mut [u8],
                              &Nonce(ref n): &Nonce,
                              &Key(ref k): &Key) {
        unsafe {
            libsodium_sys::crypto_stream_chacha20_xor(
                m.as_mut_ptr(),
                m.as_ptr(),
                m.len() as c_ulonglong,
                n,
                k);
        }
    }

    extern "C" {
        fn crypto_stream_chacha20_xor_ic(c:*mut u8, m:*mut u8, mlen:c_ulonglong, n:*const u8, ic:u64, k:*const u8) -> c_int;
    }

    pub fn xor_inplace(x:&mut [u8], nonce:&Nonce, ic:u64, key:&Key) {
        unsafe {
            let p = x.as_mut_ptr();
            crypto_stream_chacha20_xor_ic(p, p, x.len() as c_ulonglong, nonce.0.as_ptr(), ic, key.0.as_ptr());
        }
    }
}
pub mod poly1305 {
    use super::super::libsodium_sys;
    use super::super::libc::c_ulonglong;
    pub const KEYBYTES:usize = libsodium_sys::crypto_onetimeauth_poly1305_KEYBYTES;
    pub const TAGBYTES:usize = libsodium_sys::crypto_onetimeauth_poly1305_BYTES;
    use std;

    newtype!(Key,KEYBYTES);
    from_slice!(Key,KEYBYTES);
    new_blank!(Key,KEYBYTES);

    pub struct Tag([u8;TAGBYTES]);
    new_blank!(Tag,TAGBYTES);
    from_slice!(Tag,TAGBYTES);
    as_bytes!(Tag);

    pub fn authenticate(tag:&mut Tag,
                        m: &[u8],
                        k: &Key) {
        unsafe {
            libsodium_sys::crypto_onetimeauth_poly1305(
                &mut tag.0,
                m.as_ptr(),
                m.len() as c_ulonglong,
                &(k.0));
        }
    }
}

pub mod randombytes {
    use super::super::libsodium_sys;

    pub fn into(buf: &mut [u8]) {
        unsafe {
            libsodium_sys::randombytes_buf(buf.as_mut_ptr(), buf.len());
        }
    }
}


pub mod sha256 {
    use super::super::libsodium_sys;
    use super::super::libc::c_ulonglong;
    use std;
    pub const DIGESTBYTES:usize = libsodium_sys::crypto_hash_sha256_BYTES;

    newtype!(Digest, DIGESTBYTES);
    as_bytes!(Digest);
    from_slice!(Digest, DIGESTBYTES);
    clone!(Digest);
    new_blank!(Digest, DIGESTBYTES);

    pub fn hash(digest:&mut Digest, m: &[u8]) {
        unsafe {
            libsodium_sys::crypto_hash_sha256(&mut digest.0, m.as_ptr(), m.len() as c_ulonglong);
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
    impl GroupElement {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] { &self.0 }
    }

    pub fn scalarmult(q: &mut GroupElement,
                      &Scalar(ref n): &Scalar,
                      &GroupElement(ref p): &GroupElement) {
        unsafe {
            libsodium_sys::crypto_scalarmult_curve25519(&mut q.0, n, p);
        }
    }

    pub fn scalarmult_base(q:&mut GroupElement, &Scalar(ref n): &Scalar) {
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
    pub struct PublicKey([u8;PUBLICKEYBYTES]);
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

    
    pub fn sign_detached(signature:&mut Signature, m: &[u8], &SecretKey(ref sk): &SecretKey) {
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

    pub fn verify_detached(signature:&Signature, m: &[u8], &PublicKey(ref pk): &PublicKey) -> bool {
        unsafe {
            let ret = libsodium_sys::crypto_sign_ed25519_verify_detached(
                &signature.0,
                m.as_ptr(),
                m.len() as c_ulonglong,
                pk);
            ret == 0
        }
    }

}
