use super::*;
use super::super::*;
use std::io::{Write};
use super::super::msg;
use super::super::auth::{AuthRequest,Method};
use rand;
use rand::Rng;
use super::super::negociation;

impl Encrypted {

    pub fn client_rekey(&mut self, buf:&[u8], rekey:Kex, keys:&[key::Algorithm], buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<bool, Error> {
        match rekey {
            Kex::KexInit(mut kexinit) => {

                if buf[0] == msg::KEXINIT {
                    debug!("received KEXINIT");
                    if kexinit.algo.is_none() {
                        kexinit.algo = Some(try!(negociation::client_read_kex(buf, keys)));
                        kexinit.exchange.server_kex_init.extend(buf);
                    }
                    if kexinit.sent {
                        if let Some((kex, key, cipher, mac, follows)) = kexinit.algo {
                            self.rekey = Some(Kex::KexDh(KexDh {
                                exchange: kexinit.exchange,
                                kex: kex,
                                key: key,
                                cipher: cipher,
                                mac: mac,
                                follows: follows,
                                session_id: kexinit.session_id,
                            }))
                        } else {
                            self.rekey = Some(Kex::KexInit(kexinit));
                        }
                    } else {
                        self.rekey = Some(Kex::KexInit(kexinit));
                    }
                } else {
                    self.rekey = Some(Kex::KexInit(kexinit))
                }
            },
            Kex::KexDhDone(mut kexdhdone) => {
                if buf[0] == msg::KEX_ECDH_REPLY {
                    let hash = try!(kexdhdone.client_compute_exchange_hash(buf, buffer));
                    let new_keys = kexdhdone.compute_keys(hash, buffer, buffer2);
                    self.rekey = Some(Kex::NewKeys(new_keys));
                } else {
                    self.rekey = Some(Kex::KexDhDone(kexdhdone))
                }
            },
            Kex::NewKeys(mut newkeys) => {

                if buf[0] == msg::NEWKEYS {

                    newkeys.received = true;
                    if !newkeys.sent {
                        self.rekey = Some(Kex::NewKeys(newkeys));
                    } else {

                        self.exchange = Some(newkeys.exchange);
                        self.kex = newkeys.kex;
                        self.key = newkeys.key;
                        self.cipher = newkeys.cipher;
                        self.mac = newkeys.mac;
                        return Ok(true)
                    }
                } else {
                    self.rekey = Some(Kex::NewKeys(newkeys));
                }
            },
            state => {
                self.rekey = Some(state);
            }
        }
        Ok(false)
    }
}
