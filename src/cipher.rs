use sodiumoxide;
use byteorder::{ByteOrder,BigEndian,WriteBytesExt};

use super::{SSHString, Named,Preferred,Error};
use super::msg;
use std;

use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::onetimeauth::poly1305;
use std::io::{Read,Write};

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305(Option<Chacha20Poly1305>) // "chacha20-poly1305@openssh.com"
}

use libc::{c_longlong, c_int};
extern "C" {
    fn crypto_stream_chacha20_xor_ic(c:*mut u8, m:*mut u8, mlen:c_longlong, n:*const u8, ic:u64, k:*const u8) -> c_int;
}

fn chacha20_xor_inplace(x:&mut [u8], nonce:&chacha20::Nonce, ic:u64, key:&chacha20::Key) -> Result<(),c_int> {
    unsafe {
        let p = x.as_mut_ptr();
        let ret =  crypto_stream_chacha20_xor_ic(p, p, x.len() as c_longlong, nonce.0.as_ptr(), ic, key.0.as_ptr());
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

fn read_chacha20poly1305_packet<'a, R:Read>(key:&[u8], seq:usize, stream:&mut R, buffer:&'a mut Vec<u8>) -> Result<&'a[u8],Error> {

    // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
    buffer.clear();

    // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
    let mut len = [0;4];
    stream.read_exact(&mut len);
    buffer.extend(&len);

    let k1 = &key[32..64];
    let k1 = chacha20::Key::from_slice(k1).unwrap();

    let k2 = &key[0..32];
    let k2 = chacha20::Key::from_slice(k2).unwrap();

    let mut nonce = [0;8];
    BigEndian::write_u32(&mut nonce[4..], seq as u32);
    let nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

    chacha20::stream_xor_inplace(
        &mut len,
        &nonce,
        &k1);

    let packet_length = BigEndian::read_u32(&len) as usize;
    println!("chacha20: packet length: {:?}", &len[..]);

    // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

    buffer.resize(4 + packet_length + poly1305::TAGBYTES, 0);
    try!(stream.read_exact(&mut buffer[4..]));
    let mut poly_key = [0;32];
    chacha20::stream_xor_inplace(
        &mut poly_key,
        &nonce,
        &k2);
    let poly_key = poly1305::Key::from_slice(&poly_key).unwrap();
    let tag = poly1305::authenticate(&buffer[0..4+packet_length], &poly_key);

    println!("read buffer before chacha20: {:?}", &buffer);
    // - Constant-time-compare it with the Poly1305 at the end of the packet (right after the 4+length first bytes).
    if sodiumoxide::utils::memcmp(&tag.0, &buffer[4+packet_length..]) {

        // - If the auth is correct, chacha20-xor the length bytes after the first 4 ones, with ic 1.
        //   (actually, the above doc says "ic = LE encoding of 1", which is different from the libsodium interface).


        chacha20_xor_inplace(&mut buffer[4..(4+packet_length)],
                             &nonce,
                             1,
                             &k2).unwrap();

        let padding = buffer[4] as usize;
        Ok(&buffer[5..(5+packet_length - padding - 1)])

    } else {
        println!("should be {:?}, was {:?}", &tag.0, &buffer[4+packet_length..]);
        Err(Error::PacketAuth)
    }
    
}

fn write_chacha20poly1305_packet<W:Write>(key:&[u8], seq:usize, stream:&mut W,
                                          packet:&[u8], buffer:&mut Vec<u8>) -> Result<(),Error> {

    // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

    // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
    buffer.clear();
    let block_size = 8;
    let padding_len = {
        (block_size - ((5+packet.len()) % block_size))
    };
    let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };

    buffer.write_u32::<BigEndian>((packet.len() + padding_len + 1) as u32);

    let k1 = &key[32..64];
    let k1 = chacha20::Key::from_slice(k1).unwrap();

    let mut nonce = [0;8];
    BigEndian::write_u32(&mut nonce[4..], seq as u32);
    let nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

    chacha20::stream_xor_inplace(
        &mut buffer[0..4],
        &nonce,
        &k1);
    // the first 4 bytes of buffer now contain the encrypted length.
    // - Append the encrypted packet

    // Compute the amount of padding.
    buffer.push(padding_len as u8);

    buffer.extend(packet);

    let mut padding = [0;256];
    sodiumoxide::randombytes::randombytes_into(&mut padding[0..padding_len]);
    buffer.extend(&padding[0..padding_len]);

    let k2 = &key[0..32];
    let k2 = chacha20::Key::from_slice(k2).unwrap();

    chacha20_xor_inplace(&mut buffer[4..],
                         &nonce,
                         1,
                         &k2).unwrap();

    // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

    let mut poly_key = [0;32];
    chacha20::stream_xor_inplace(
        &mut poly_key,
        &nonce,
        &k2);
    let poly_key = poly1305::Key::from_slice(&poly_key).unwrap();

    let tag = poly1305::authenticate(&buffer, &poly_key);

    try!(stream.write(&buffer));
    try!(stream.write(&tag.0));

    Ok(())
}

#[test]
fn write_read() {
    let mut buffer = Vec::new();

    let key = {
        let mut key = Vec::new();
        let k1 = chacha20::gen_key();
        let k2 = chacha20::gen_key();
        key.extend(&k1.0);
        key.extend(&k2.0);
        key
    };

    let plaintext = b"some data";
    let mut seq = 12;
    let mut stream = Vec::new();

    write_chacha20poly1305_packet(&key, seq, &mut stream, plaintext, &mut buffer);
    println!("stream {:?}", stream);

    assert_eq!(
        read_chacha20poly1305_packet(&key, seq, &mut &stream[..], &mut buffer).unwrap(),
        plaintext
    );
}





impl Cipher {


    pub fn read_client_packet<'a, R:Read>(&mut self, seq:&mut usize, stream:&mut R, buffer:&'a mut Vec<u8>) -> Result<&'a[u8],Error> {

        match *self {
            Cipher::Chacha20Poly1305(Some(ref mut chacha)) => {

                let result = read_chacha20poly1305_packet(&chacha.key_client_to_server,
                                                          *seq, stream, buffer);
                *seq += 1;
                result

            },
            _ => unimplemented!()
        }
    }

    pub fn write_server_packet<W:Write>(&mut self, seq:&mut usize, stream:&mut W, packet:&[u8], buffer:&mut Vec<u8>) -> Result<(),Error> {

        match *self {
            Cipher::Chacha20Poly1305(Some(ref mut chacha)) => {
                let result = write_chacha20poly1305_packet(
                    &chacha.key_server_to_client,
                    *seq, stream, packet, buffer
                );
                *seq += 1;
                result
            },
            _ => unimplemented!()
        }

        
    }
}




const CIPHER_CHACHA20_POLY1305:&'static str = "chacha20-poly1305@openssh.com";
const CIPHERS: &'static [&'static str;1] = &[
    CIPHER_CHACHA20_POLY1305
];
impl Named for Cipher {
    fn from_name(name: &[u8]) -> Option<Self> {
        if name == CIPHER_CHACHA20_POLY1305.as_bytes() {
            return Some(Cipher::Chacha20Poly1305(None))
        }
        None
    }
}
impl Preferred for Cipher {
    fn preferred() -> &'static [&'static str] {
        CIPHERS
    }
}

#[derive(Debug)]
pub struct Chacha20Poly1305 {
    pub iv_client_to_server: Vec<u8>,
    pub iv_server_to_client: Vec<u8>,
    pub key_client_to_server: Vec<u8>,
    pub key_server_to_client: Vec<u8>,
    pub integrity_client_to_server: Vec<u8>,
    pub integrity_server_to_client: Vec<u8>,
}

pub fn digest_dump(dd:&[u8]) {
    for i in dd {
        print!("{:02x} ", i);
    }
    println!("");
}
impl Chacha20Poly1305 {
    pub fn dump(&self) {
        println!("A");
        digest_dump(&self.iv_client_to_server);
        println!("B");
        digest_dump(&self.iv_server_to_client);
        println!("C");
        digest_dump(&self.key_client_to_server);
        println!("D");
        digest_dump(&self.key_server_to_client);
        println!("E");
        digest_dump(&self.integrity_client_to_server);
        println!("F");
        digest_dump(&self.integrity_server_to_client);
    }
}
