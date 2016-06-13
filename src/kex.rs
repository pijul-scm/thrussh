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
    client_pubkey: curve25519::GroupElement,
    server_pubkey: curve25519::GroupElement,
    server_secret: curve25519::Scalar,
    shared_secret: curve25519::GroupElement,
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
    
    pub fn dh(&mut self, exchange:&mut super::Exchange, payload:&[u8]) -> Result<Algorithm,Error> {

        match self {

            &mut Name::Curve25519 if payload[0] == msg::KEX_ECDH_INIT => {

                let client_pubkey = {
                    let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
                    curve25519::GroupElement::copy_from_slice(&payload[5 .. (5+pubkey_len)])
                };
                let server_secret = {
                    let mut server_secret = [0;curve25519::SCALARBYTES];
                    randombytes::into(&mut server_secret);

                    // https://git.libssh.org/projects/libssh.git/tree/doc/curve25519-sha256@libssh.org.txt
                    //server_secret_[0] &= 248;
                    //server_secret_[31] &= 127;
                    //server_secret_[31] |= 64;
                    curve25519::Scalar::copy_from_slice(&server_secret)
                };

                let mut server_pubkey = curve25519::GroupElement::new_blank();
                curve25519::scalarmult_base(&mut server_pubkey, &server_secret);

                {
                    // fill exchange.
                    let server_ephemeral = server_pubkey.as_bytes().to_vec();
                    exchange.server_ephemeral = Some(server_ephemeral);
                }

                let mut shared_secret = curve25519::GroupElement::new_blank();
                curve25519::scalarmult(&mut shared_secret, &server_secret, &client_pubkey);

                // debug!("shared secret");
                // super::hexdump(shared_secret.as_bytes());

                Ok(Algorithm::Curve25519(Curve25519 {
                    client_pubkey: client_pubkey,
                    server_pubkey: server_pubkey,
                    server_secret: server_secret,
                    shared_secret: shared_secret
                }))
            },
            _ => Err(Error::Kex)
        }
    }
}

impl Algorithm {
    pub fn compute_exchange_hash(&self,
                                 key_algo:&super::key::Algorithm,
                                 exchange:&super::Exchange,
                                 buffer:&mut super::CryptoBuf) -> Result<Digest,Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        //println!("exchange: {:?}", exchange);
        match self {
            &Algorithm::Curve25519(ref kex) => {

                match (&exchange.client_id,
                       &exchange.server_id,
                       &exchange.client_kex_init,
                       &exchange.server_kex_init,
                       // &exchange.server_public_host_key,
                       &exchange.client_ephemeral,
                       &exchange.server_ephemeral) {

                    (&Some(ref client_id),
                     &Some(ref server_id),
                     &Some(ref client_kex_init),
                     &Some(ref server_kex_init),
                     // &Some(ref server_public_host_key),
                     &Some(ref client_ephemeral),
                     &Some(ref server_ephemeral)) => {
                        debug!("{:?} {:?}",
                                 std::str::from_utf8(client_id),
                                 std::str::from_utf8(server_id)
                        );
                        buffer.clear();
                        buffer.extend_ssh_string(client_id);
                        buffer.extend_ssh_string(server_id);
                        buffer.extend_ssh_string(client_kex_init);
                        buffer.extend_ssh_string(server_kex_init);

                        
                        key_algo.write_pubkey(buffer);

                        //println!("client_ephemeral: {:?}", client_ephemeral);
                        //println!("server_ephemeral: {:?}", server_ephemeral);

                        debug_assert!(client_ephemeral.len() == 32);
                        buffer.extend_ssh_string(client_ephemeral);

                        debug_assert!(server_ephemeral.len() == 32);
                        buffer.extend_ssh_string(server_ephemeral);

                        //println!("shared: {:?}", kex.shared_secret);
                        //unimplemented!(); // Should be in wire format.

                        buffer.extend_ssh_mpint(kex.shared_secret.as_bytes());

                        debug!("buffer len = {:?}", buffer.len());
                        // super::hexdump(buffer);
                        let mut hash = sha256::Digest::new_blank();
                        sha256::hash(&mut hash, buffer.as_slice());
                        debug!("hash: {:?}", hash);
                        Ok(Digest::Sha256(hash))
                    },
                    _ => Err(Error::Kex)
                }
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

                    buffer.extend_ssh_mpint(kex.shared_secret.as_bytes());
                    buffer.extend(exchange_hash.as_bytes());
                    buffer.push(c);
                    buffer.extend(session_id.as_bytes());
                    let mut hash = sha256::Digest::new_blank();
                    sha256::hash(&mut hash, buffer.as_slice());
                    key.extend(hash.as_bytes());

                    while key.len() < len {
                        // extend.
                        buffer.clear();
                        buffer.extend_ssh_mpint(kex.shared_secret.as_bytes());
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
                        
                        /* cipher = Some(super::cipher::chacha20poly1305::Cipher {
                            iv_client_to_server: {
                                println!("A");
                                println!("{:?}", NONCEBYTES);
                                compute_key(b'A', NONCEBYTES)
                                //println!("buf {:?} {:?}", key, key.len());
                                //Nonce::from_slice(&key[0..NONCEBYTES]).unwrap()
                            },
                            iv_server_to_client: {
                                println!("B");
                                compute_key(b'B', NONCEBYTES)
                                //Nonce::from_slice(&key[0..NONCEBYTES]).unwrap()
                            },
                            key_client_to_server: {
                                println!("C");
                                compute_key(b'C', KEYBYTES)
                                //Key::from_slice(&key).unwrap()
                            },
                            key_server_to_client: {
                                println!("D");
                                compute_key(b'D', KEYBYTES)
                                //Key::from_slice(&key).unwrap()
                            },
                            integrity_client_to_server: {
                                println!("E");
                                compute_key(b'E', KEYBYTES)
                                //Key::from_slice(&key).unwrap()
                            },
                            integrity_server_to_client: {
                                println!("F");
                                compute_key(b'F', KEYBYTES)
                                //Key::from_slice(&key).unwrap()
                            }
                    })*/
                    }
                }
            },
            // _ => unimplemented!()
        }
    }
}


#[derive(Debug)]
pub struct KexInit {
    pub algo: Option<super::negociation::Names>,
    pub exchange: super::Exchange,
    pub session_id: Option<super::kex::Digest>,
    pub sent: bool
}

impl KexInit {
    pub fn kexinit<T>(self) -> Result<super::ServerState<T>, super::Error> {
        if !self.sent {
            Ok(super::ServerState::KexInit(self))
        } else {
            if let Some((kex,key,cipher,mac,follows)) = self.algo {

                Ok(super::ServerState::KexDh(super::KexDh {
                    exchange:self.exchange,
                    kex:kex, key:key,
                    cipher:cipher, mac:mac, follows:follows,
                    session_id: self.session_id
                }))
            } else {
                Err(super::Error::Kex)
            }
        }
    }
}
