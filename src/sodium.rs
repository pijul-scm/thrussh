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

macro_rules! newtype_from_slice (($newtype:ident, $len:expr) => {
    pub struct $newtype([u8;$len]);
    impl std::fmt::Debug for $newtype {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}({:?})", stringify!($newtype), &self.0[..])
        }
    }
    from_slice!($newtype,$len);
});
macro_rules! from_slice (($newtype:ident, $len:expr) => (
    impl $newtype {
        pub fn from_slice(s: &[u8]) -> Self {
            debug_assert!(s.len() == $len);
            let mut x = $newtype([0;$len]);
            (&mut x.0).clone_from_slice(s);
            x
        }
    }
));
macro_rules! as_bytes (($newtype:ident) => (
    impl $newtype {
        pub fn as_bytes(self) -> Self {
            &self.0
        }
    }
));





pub mod chacha20 {
    use super::super::libc::{c_ulonglong,c_int};
    use super::super::libsodium_sys;
    pub const KEYBYTES:usize = libsodium_sys::crypto_stream_chacha20_KEYBYTES;
    pub const NONCEBYTES:usize = libsodium_sys::crypto_stream_chacha20_NONCEBYTES;
    use std;
    newtype_from_slice!(Key,KEYBYTES);
    newtype_from_slice!(Nonce,NONCEBYTES);

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

    newtype_from_slice!(Key,KEYBYTES);

    pub struct Tag([u8;TAGBYTES]);
    impl Tag {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] { &self.0 }
    }

    pub fn authenticate(m: &[u8],
                        &Key(ref k): &Key) -> Tag {
        unsafe {
            let mut tag = [0; TAGBYTES];
            libsodium_sys::crypto_onetimeauth_poly1305(
                &mut tag,
                m.as_ptr(),
                m.len() as c_ulonglong,
                k);
            Tag(tag)
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

    pub const DIGESTBYTES:usize = libsodium_sys::crypto_hash_sha256_BYTES;

    #[derive(Clone, Debug)]
    pub struct Digest([u8;DIGESTBYTES]);
    impl Digest {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] { &self.0 }
    }
    pub fn hash(m: &[u8]) -> Digest {
        unsafe {
            let mut h = [0; DIGESTBYTES];
            libsodium_sys::crypto_hash_sha256(&mut h, m.as_ptr(), m.len() as c_ulonglong);
            Digest(h)
        }
    }
}

pub mod curve25519 {
    use super::super::libsodium_sys;

    pub const GROUPELEMENTBYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_BYTES;
    pub const SCALARBYTES: usize = libsodium_sys::crypto_scalarmult_curve25519_SCALARBYTES;

    use std;
    newtype_from_slice!(Scalar, SCALARBYTES);
    newtype_from_slice!(GroupElement, GROUPELEMENTBYTES);
    impl GroupElement {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] { &self.0 }
    }

    pub fn scalarmult(&Scalar(ref n): &Scalar,
                      &GroupElement(ref p): &GroupElement) -> GroupElement {
        let mut q = GroupElement([0; GROUPELEMENTBYTES]);
        unsafe {
            libsodium_sys::crypto_scalarmult_curve25519(&mut q.0, n, p);
        }
        q
    }

    pub fn scalarmult_base(&Scalar(ref n): &Scalar) -> GroupElement {
        let mut q = GroupElement([0; GROUPELEMENTBYTES]);
        unsafe {
            libsodium_sys::crypto_scalarmult_curve25519_base(&mut q.0, n);
        }
        q
    }
}

pub mod ed25519 {
    use super::super::libsodium_sys;
    use super::super::libc::c_ulonglong;
    use std;

    pub const PUBLICKEYBYTES: usize = libsodium_sys::crypto_sign_ed25519_PUBLICKEYBYTES;
    pub const SECRETKEYBYTES: usize = libsodium_sys::crypto_sign_ed25519_SECRETKEYBYTES;
    pub const SIGNATUREBYTES: usize = libsodium_sys::crypto_sign_ed25519_BYTES;


    newtype_from_slice!(PublicKey, PUBLICKEYBYTES);
    impl PublicKey {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] { &self.0 }
    }
    impl Clone for PublicKey {
        fn clone(&self) -> Self {
            Self::from_slice(self.as_bytes())
        }
    }

    pub struct Signature([u8;SIGNATUREBYTES]);
    impl Signature {
        pub fn as_bytes<'a>(&'a self) -> &'a[u8] {
            &self.0
        }
    }
    impl Clone for Signature {
        fn clone(&self) -> Self {
            let mut t = [0;SIGNATUREBYTES];
            t.clone_from_slice(&self.0);
            Signature(t)
        }
    }

    newtype_from_slice!(SecretKey, SECRETKEYBYTES);
    impl Clone for SecretKey {
        fn clone(&self) -> Self {
            let mut t = [0;SECRETKEYBYTES];
            t.clone_from_slice(&self.0);
            SecretKey(t)
        }
    }
    
    pub fn sign_detached(m: &[u8], &SecretKey(ref sk): &SecretKey) -> Signature {
        unsafe {
            let mut sig = [0u8; SIGNATUREBYTES];
            let mut siglen: c_ulonglong = 0;
            libsodium_sys::crypto_sign_ed25519_detached(&mut sig,
                                                        &mut siglen,
                                                        m.as_ptr(),
                                                        m.len() as c_ulonglong,
                                                        sk);
            assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
            Signature(sig)
        }
    }

}
