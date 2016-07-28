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
use super::sodium::randombytes;

use super::Error;
use super::key;
use super::kex;
use super::cipher;
use super::msg;
// use super::mac; // unimplemented
// use super::compression; // unimplemented
use cryptobuf::CryptoBuf;
use super::encoding::Reader;

#[derive(Debug)]
pub struct Names {
    pub kex: kex::Name,
    pub key: key::Name,
    pub cipher: cipher::Name,
    pub mac: &'static str,
    pub ignore_guessed: bool,
}

/// Lists of preferred algorithms. This is normally hard-coded into implementations.
#[derive(Debug)]
pub struct Preferred {
    pub kex: &'static [kex::Name],
    pub key: &'static [key::Name],
    pub cipher: &'static [cipher::Name],
    pub mac: &'static [&'static str],
    pub compression: &'static [&'static str],
}

pub const DEFAULT: Preferred = Preferred {
    kex: &[kex::CURVE25519],
    key: &[key::ED25519],
    cipher: &[cipher::CHACHA20POLY1305],
    mac: &["none"],
    compression: &["none"],
};

impl Default for Preferred {
    fn default() -> Preferred {
        DEFAULT
    }
}

pub trait Named {
    fn name(&self) -> &'static str;
}

impl Named for () {
    fn name(&self) -> &'static str {
        ""
    }
}

pub trait Select {
    fn select<S: AsRef<str> + Copy>(a: &[S], b: &[u8]) -> Option<(bool, S)>;

    fn read_kex(buffer: &[u8], pref: &Preferred) -> Result<Names, Error> {
        let mut r = buffer.reader(17);
        let (kex_both_first, kex_algorithm) = if let Some(x) =
                                                     Self::select(pref.kex, try!(r.read_string())) {
            x
        } else {
            return Err(Error::KexInit);
        };

        let (key_both_first, key_algorithm) = if let Some(x) =
                                                     Self::select(pref.key, try!(r.read_string())) {
            x
        } else {
            return Err(Error::KexInit);
        };

        let cipher = Self::select(pref.cipher, try!(r.read_string()));

        try!(r.read_string()); // SERVER_TO_CLIENT
        let mac = Self::select(pref.mac, try!(r.read_string()));

        try!(r.read_string()); // SERVER_TO_CLIENT
        try!(r.read_string()); //
        try!(r.read_string()); //
        try!(r.read_string()); //

        let follows = try!(r.read_byte()) != 0;
        match (cipher, mac, follows) {
            (Some((_, cip)), Some((_, mac)), fol) => {
                Ok(Names {
                    kex: kex_algorithm,
                    key: key_algorithm,
                    cipher: cip,
                    mac: mac,
                    // Ignore the next packet if (1) it follows and (2) it's not the correct guess.
                    ignore_guessed: fol && !(kex_both_first && key_both_first),
                })
            }
            _ => Err(Error::KexInit),
        }
    }
}

pub struct Server;
pub struct Client;

impl Select for Server {
    fn select<S: AsRef<str> + Copy>(server_list: &[S], client_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for c in client_list.split(|&x| x == b',') {
            for &s in server_list {
                if c == s.as_ref().as_bytes() {
                    return Some((both_first_choice, s));
                }
                both_first_choice = false
            }
        }
        None
    }
}

impl Select for Client {
    fn select<S: AsRef<str> + Copy>(client_list: &[S], server_list: &[u8]) -> Option<(bool, S)> {
        let mut both_first_choice = true;
        for &c in client_list {
            for s in server_list.split(|&x| x == b',') {
                if s == c.as_ref().as_bytes() {
                    return Some((both_first_choice, c));
                }
                both_first_choice = false
            }
        }
        None
    }
}


pub fn write_kex(prefs: &Preferred, buf: &mut CryptoBuf) {
    // buf.clear();
    buf.push(msg::KEXINIT);

    let mut cookie = [0; 16];
    randombytes::into(&mut cookie);

    buf.extend(&cookie); // cookie
    buf.extend_list(prefs.kex.iter()); // kex algo

    buf.extend_list(prefs.key.iter());

    buf.extend_list(prefs.cipher.iter()); // cipher client to server
    buf.extend_list(prefs.cipher.iter()); // cipher server to client

    buf.extend_list(prefs.mac.iter()); // mac client to server
    buf.extend_list(prefs.mac.iter()); // mac server to client
    buf.extend_list(prefs.compression.iter()); // compress client to server
    buf.extend_list(prefs.compression.iter()); // compress server to client

    buf.write_empty_list(); // languages client to server
    buf.write_empty_list(); // languagesserver to client

    buf.push(0); // doesn't follow
    buf.extend(&[0, 0, 0, 0]); // reserved
}
