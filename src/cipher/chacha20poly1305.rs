use sodiumoxide;
use byteorder::{ByteOrder,BigEndian,WriteBytesExt};
use super::super::Error;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::onetimeauth::poly1305;
use std::io::{Read,Write};

#[derive(Debug)]
pub struct Cipher {
    k1:chacha20::Key,
    k2:chacha20::Key
    /*
        let k1 = &key[32..64];
        let k1 = chacha20::Key::from_slice(k1).unwrap();

        let k2 = &key[0..32];
        let k2 = chacha20::Key::from_slice(k2).unwrap();
     */
}

impl Cipher {
    pub fn init(key:&[u8]) -> Cipher {
        Cipher {
            k1: chacha20::Key::from_slice(&key[32..64]).unwrap(),
            k2: chacha20::Key::from_slice(&key[0..32]).unwrap()
        }
    }
}

/*
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
*/

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

impl super::CipherT for Cipher {

    fn read_packet<'a, R:Read>(&self, seq:usize, stream:&mut R, buffer:&'a mut Vec<u8>) -> Result<&'a[u8],Error> {

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
        buffer.clear();

        // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
        let mut len = [0;4];
        try!(stream.read_exact(&mut len));
        buffer.extend(&len);
        
        /*let k1 = &key[32..64];
        let k1 = chacha20::Key::from_slice(k1).unwrap();

        let k2 = &key[0..32];
        let k2 = chacha20::Key::from_slice(k2).unwrap();*/

        let mut nonce = [0;8];
        BigEndian::write_u32(&mut nonce[4..], seq as u32);
        let nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

        chacha20::stream_xor_inplace(
            &mut len,
            &nonce,
            &self.k1);

        let packet_length = BigEndian::read_u32(&len) as usize;
        println!("chacha20: packet length: {:?}", &len[..]);

        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

        buffer.resize(4 + packet_length + poly1305::TAGBYTES, 0);
        try!(stream.read_exact(&mut buffer[4..]));
        let mut poly_key = [0;32];
        chacha20::stream_xor_inplace(
            &mut poly_key,
            &nonce,
            &self.k2);
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
                                 &self.k2).unwrap();

            let padding = buffer[4] as usize;
            Ok(&buffer[5..(5+packet_length - padding - 1)])

        } else {
            println!("should be {:?}, was {:?}", &tag.0, &buffer[4+packet_length..]);
            Err(Error::PacketAuth)
        }
        
    }

    fn write_packet<W:Write>(&self, seq:usize, stream:&mut W,
                                 packet:&[u8], buffer:&mut Vec<u8>) -> Result<(),Error> {

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

        // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
        buffer.clear();
        let block_size = 8;
        let padding_len = {
            (block_size - ((5+packet.len()) % block_size))
        };
        let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };

        try!(buffer.write_u32::<BigEndian>((packet.len() + padding_len + 1) as u32));

        let mut nonce = [0;8];
        BigEndian::write_u32(&mut nonce[4..], seq as u32);
        let nonce = chacha20::Nonce::from_slice(&nonce).unwrap();

        chacha20::stream_xor_inplace(
            &mut buffer[0..4],
            &nonce,
            &self.k1);
        // the first 4 bytes of buffer now contain the encrypted length.
        // - Append the encrypted packet

        // Compute the amount of padding.
        buffer.push(padding_len as u8);

        buffer.extend(packet);

        let mut padding = [0;256];
        sodiumoxide::randombytes::randombytes_into(&mut padding[0..padding_len]);
        buffer.extend(&padding[0..padding_len]);


        chacha20_xor_inplace(&mut buffer[4..],
                             &nonce,
                             1,
                             &self.k2).unwrap();

        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

        let mut poly_key = [0;32];
        chacha20::stream_xor_inplace(
            &mut poly_key,
            &nonce,
            &self.k2);
        let poly_key = poly1305::Key::from_slice(&poly_key).unwrap();

        let tag = poly1305::authenticate(&buffer, &poly_key);

        try!(stream.write(&buffer));
        try!(stream.write(&tag.0));

        Ok(())
    }
}


#[test]
fn write_read() {
    let mut buffer = Vec::new();

    let k1 = chacha20::gen_key();
    let k2 = chacha20::gen_key();
    let key = Cipher {
        k1:k1,
        k2:k2
    };

    let plaintext = b"some data";
    let mut seq = 12;
    let mut stream = Vec::new();

    key.write_packet(seq, &mut stream, plaintext, &mut buffer);
    println!("stream {:?}", stream);

    assert_eq!(
        key.read_packet(seq, &mut &stream[..], &mut buffer).unwrap(),
        plaintext
    );
}

