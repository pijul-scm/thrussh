use byteorder::{ByteOrder, BigEndian};
use regex::Regex;
use rustc_serialize::base64::{FromBase64};
use std::path::Path;
use std::fs::File;
use std::io::{Read,BufReader,BufRead};
use std;

use super::key::ed25519::{PublicKey,SecretKey};

#[derive(Debug)]
pub struct Config {
    pub server_id: String,
    pub keys: Vec<super::key::Algorithm>
}

const KEYTYPE_ED25519:&'static [u8] = b"ssh-ed25519";

pub fn read_public_key<P:AsRef<Path>>(p:P) -> Result<PublicKey, super::Error> {

    let pubkey_regex = Regex::new(r"ssh-\S*\s*(?P<key>\S+)\s*").unwrap();
    let mut pubkey = String::new();
    let mut file = File::open(p.as_ref()).unwrap();
    file.read_to_string(&mut pubkey).unwrap();
    let p = pubkey_regex.captures(&pubkey).unwrap().name("key").unwrap().from_base64().unwrap();

    let mut pos = Position { s:&p,position:0 };
    if pos.read_string() == b"ssh-ed25519" {
        let pubkey = pos.read_string();
        Ok(PublicKey::copy_from_slice(pubkey))
    } else {
        Err(super::Error::CouldNotReadKey)
    }
}

pub fn read_secret_key<P:AsRef<Path>>(p:P) -> Result<SecretKey, super::Error> {

    let file = File::open(p.as_ref()).unwrap();
    let file = BufReader::new(file);

    let mut secret = String::new();
    let mut started = false;

    for l in file.lines() {
        let l = try!(l);
        if l == "-----BEGIN OPENSSH PRIVATE KEY-----" {
            started = true
        } else if l == "-----END OPENSSH PRIVATE KEY-----" {
            break
        } else if started {
            secret.push_str(&l)
        }
    }
    let secret = secret.from_base64().unwrap();
    //println!("secret: {:?} {:?}", secret, secret.len());
    //println!("secret: {:?}", std::str::from_utf8(&secret[0..62]));

    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = Position { s:&secret, position:15 };

        let ciphername = position.read_string();
        let kdfname = position.read_string();
        let kdfoptions = position.read_string();
        info!("ciphername: {:?}", std::str::from_utf8(ciphername));
        debug!("kdf: {:?} {:?}",
                 std::str::from_utf8(kdfname),
                 std::str::from_utf8(kdfoptions));

        let nkeys = position.read_u32();
        
        for _ in 0..nkeys {
            let public_string = position.read_string();
            let mut pos = Position { s:public_string, position:0 };
            if pos.read_string() == KEYTYPE_ED25519 {
                // println!("{:?} {:?}", secret, secret.len());
                let public = PublicKey::copy_from_slice(pos.read_string());
                info!("public: {:?}", public);
            }
        }
        info!("there are {} keys in this file", nkeys);
        let secret = position.read_string();
        if kdfname == b"none" {
            let mut position = Position { s: secret, position: 0 };
            let check0 = position.read_u32();
            let check1 = position.read_u32();
            debug!("check0: {:?}", check0);
            debug!("check1: {:?}", check1);
            for _ in 0..nkeys {

                let key_type = position.read_string();
                if key_type == KEYTYPE_ED25519 {
                    let pubkey = position.read_string();
                    debug!("pubkey = {:?}", pubkey);
                    let seckey = position.read_string();
                    let comment = position.read_string();
                    debug!("comment = {:?}", comment);
                    let secret = SecretKey::copy_from_slice(seckey);
                    return Ok(secret)
                } else {
                    info!("unsupported key type {:?}", std::str::from_utf8(key_type));
                }
            }
            Err(super::Error::CouldNotReadKey)
        } else {
            info!("unsupported secret key cipher: {:?}", std::str::from_utf8(kdfname));
            Err(super::Error::CouldNotReadKey)
        }
    } else {
        Err(super::Error::CouldNotReadKey)
    }
}

struct Position<'a> { s:&'a[u8], position: usize }
impl<'a> Position<'a> {
    fn read_string(&mut self) -> &'a[u8] {

        let len = BigEndian::read_u32(&self.s[self.position..]) as usize;
        let result = &self.s[(self.position+4)..(self.position+4+len)];
        self.position += 4+len;
        result
    }
    fn read_u32(&mut self) -> u32 {

        let u = BigEndian::read_u32(&self.s[self.position..]);
        self.position += 4;
        u
    }
}
