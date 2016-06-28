use byteorder::{ByteOrder,BigEndian};

use super::negociation::{ Named, Preferred };
use super::{ Error };
use super::msg;
use std;

use super::sodium::randombytes;
use super::sodium::sha256;
use super::sodium::curve25519;
use super::CryptoBuf;


#[derive(Debug,Clone)]
pub enum Digest {
    Sha256(sha256::Digest)
}
impl Digest {
    pub fn as_bytes<'a>(&'a self) -> &'a[u8] {
        match self {
            &Digest::Sha256(ref d) => d.as_bytes()
        }
    }
}

#[derive(Debug)]
pub enum Algorithm {
    Curve25519(Curve25519) // "curve25519-sha256@libssh.org"
}

#[derive(Debug)]
pub enum Name {
    Curve25519 // "curve25519-sha256@libssh.org"
}

const KEX_CURVE25519:&'static str = "curve25519-sha256@libssh.org";

impl Named for Name {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == KEX_CURVE25519.as_bytes() {
            return Some(Name::Curve25519)
        }
        None
    }
}

#[derive(Debug)]
pub struct Curve25519 {
    local_pubkey: curve25519::GroupElement,
    local_secret: curve25519::Scalar,
    remote_pubkey: Option<curve25519::GroupElement>,
    shared_secret: Option<curve25519::GroupElement>,
}

const KEX_ALGORITHMS: &'static [&'static str;1] = &[
    KEX_CURVE25519
];

impl Preferred for Name {
    fn preferred() -> &'static [&'static str] {
        KEX_ALGORITHMS
    }
}


impl Name {
    
    pub fn server_dh(&mut self, exchange:&mut super::Exchange, payload:&[u8]) -> Result<Algorithm,Error> {

        match self {

            &mut Name::Curve25519 if payload[0] == msg::KEX_ECDH_INIT => {

                let client_pubkey = {
                    let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
                    curve25519::GroupElement::copy_from_slice(&payload[5 .. (5+pubkey_len)])
                };
                let server_secret = {
                    let mut server_secret = [0;curve25519::SCALARBYTES];
                    randombytes::into(&mut server_secret);

                    // https://cr.yp.to/ecdh.html
                    server_secret[0] &= 248;
                    server_secret[31] &= 127;
                    server_secret[31] |= 64;
                    curve25519::Scalar::copy_from_slice(&server_secret)
                };

                let mut server_pubkey = curve25519::GroupElement::new_blank();
                curve25519::scalarmult_base(&mut server_pubkey, &server_secret);

                // fill exchange.
                exchange.server_ephemeral.clear();
                exchange.server_ephemeral.extend(server_pubkey.as_bytes());

                let mut shared_secret = curve25519::GroupElement::new_blank();
                curve25519::scalarmult(&mut shared_secret, &server_secret, &client_pubkey);
                println!("server shared : {:?}", shared_secret);

                // debug!("shared secret");
                // super::hexdump(shared_secret.as_bytes());

                Ok(Algorithm::Curve25519(Curve25519 {
                    local_pubkey: server_pubkey,
                    local_secret: server_secret,
                    remote_pubkey: Some(client_pubkey),
                    shared_secret: Some(shared_secret)
                }))
            },
            _ => Err(Error::Kex)
        }
    }
    pub fn client_dh(&mut self, exchange:&mut super::Exchange, buf:&mut CryptoBuf) -> Algorithm {

        match self {

            &mut Name::Curve25519 => {

                let client_secret = {
                    let mut secret = [0;curve25519::SCALARBYTES];
                    randombytes::into(&mut secret);

                    // https://cr.yp.to/ecdh.html
                    secret[0] &= 248;
                    secret[31] &= 127;
                    secret[31] |= 64;
                    curve25519::Scalar::copy_from_slice(&secret)
                };

                let mut client_pubkey = curve25519::GroupElement::new_blank();
                curve25519::scalarmult_base(&mut client_pubkey, &client_secret);
                
                // fill exchange.
                exchange.client_ephemeral.clear();
                exchange.client_ephemeral.extend(client_pubkey.as_bytes());


                buf.push(msg::KEX_ECDH_INIT);
                buf.extend_ssh_string(client_pubkey.as_bytes());


                Algorithm::Curve25519(Curve25519 {
                    local_pubkey: client_pubkey,
                    local_secret: client_secret,
                    remote_pubkey: None,
                    shared_secret: None
                })
            },
            // _ => Err(Error::Kex)
        }
    }
}

impl Algorithm {
    pub fn compute_shared_secret(&mut self, remote_pubkey:&[u8]) -> Result<(), Error> {

        match self {
            &mut Algorithm::Curve25519(ref mut kex) => {

                let server_public = curve25519::GroupElement::copy_from_slice(remote_pubkey);
                let mut shared_secret = curve25519::GroupElement::new_blank();
                curve25519::scalarmult(&mut shared_secret, &kex.local_secret, &server_public);

                println!("client shared : {:?}", shared_secret);

                kex.shared_secret = Some(shared_secret);
                Ok(())
            }
        }

    }

    pub fn compute_exchange_hash(&self,
                                 key:&super::key::PublicKey,
                                 exchange:&super::Exchange,
                                 buffer:&mut super::CryptoBuf) -> Result<Digest,Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        //println!("exchange: {:?}", exchange);
        match self {
            &Algorithm::Curve25519(ref kex) => {

                debug!("{:?} {:?}",
                       std::str::from_utf8(&exchange.client_id),
                       std::str::from_utf8(&exchange.server_id)
                );
                buffer.clear();
                buffer.extend_ssh_string(&exchange.client_id);
                buffer.extend_ssh_string(&exchange.server_id);
                buffer.extend_ssh_string(&exchange.client_kex_init);
                buffer.extend_ssh_string(&exchange.server_kex_init);

                
                key.extend_pubkey(buffer);

                //println!("server_ephemeral: {:?}", server_ephemeral);

                debug_assert!(exchange.client_ephemeral.len() == 32);
                buffer.extend_ssh_string(&exchange.client_ephemeral);

                debug_assert!(exchange.server_ephemeral.len() == 32);
                buffer.extend_ssh_string(&exchange.server_ephemeral);

                //println!("shared: {:?}", kex.shared_secret);
                //unimplemented!(); // Should be in wire format.
                if let Some(ref shared) = kex.shared_secret {
                    buffer.extend_ssh_mpint(shared.as_bytes());
                } else {
                    return Err(Error::Kex)
                }
                // println!("buffer len = {:?}", buffer.len());
                // println!("buffer: {:?}", buffer.as_slice());
                // super::hexdump(buffer);
                let mut hash = sha256::Digest::new_blank();
                sha256::hash(&mut hash, buffer.as_slice());
                // println!("hash: {:?}", hash);
                Ok(Digest::Sha256(hash))
            },
            // _ => Err(Error::Kex)
        }
    }


    pub fn compute_keys(&self, session_id:&Digest,
                        exchange_hash:&Digest,
                        buffer:&mut CryptoBuf,
                        key:&mut CryptoBuf,
                        cipher:&super::cipher::Name) -> super::cipher::Cipher {
        match self {
            &Algorithm::Curve25519(ref kex) => {

                // https://tools.ietf.org/html/rfc4253#section-7.2
                let mut compute_key = |c, key:&mut CryptoBuf, len| {

                    buffer.clear();
                    key.clear();

                    if let Some(ref shared) = kex.shared_secret {
                        buffer.extend_ssh_mpint(shared.as_bytes());
                    }

                    buffer.extend(exchange_hash.as_bytes());
                    buffer.push(c);
                    buffer.extend(session_id.as_bytes());
                    let mut hash = sha256::Digest::new_blank();
                    sha256::hash(&mut hash, buffer.as_slice());
                    key.extend(hash.as_bytes());

                    while key.len() < len {
                        // extend.
                        buffer.clear();
                        if let Some(ref shared) = kex.shared_secret {
                            buffer.extend_ssh_mpint(shared.as_bytes());
                        }
                        buffer.extend(exchange_hash.as_bytes());
                        buffer.extend(
                            key.as_slice()
                        );
                        let mut hash = sha256::Digest::new_blank();
                        sha256::hash(&mut hash, buffer.as_slice());
                        key.extend(hash.as_bytes())
                    }
                };
                
                match cipher {
                    &super::cipher::Name::Chacha20Poly1305 => {

                        super::cipher::Cipher::Chacha20Poly1305 {

                            client_to_server: {
                                compute_key(b'C', key, cipher.key_size());
                                super::cipher::chacha20poly1305::Cipher::init(key.as_slice())
                            },
                            server_to_client: {
                                compute_key(b'D', key, cipher.key_size());
                                super::cipher::chacha20poly1305::Cipher::init(key.as_slice())
                            },
                        }
                    }
                }
            },
            // _ => unimplemented!()
        }
    }
}
