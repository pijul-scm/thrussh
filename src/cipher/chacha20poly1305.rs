use byteorder::{ByteOrder,BigEndian,WriteBytesExt};
use super::super::Error;
use std::io::{Read, BufRead};

// use sodiumoxide::crypto::onetimeauth::poly1305;
use super::super::sodium;
use sodium::chacha20;
use sodium::poly1305;
use sodium::randombytes;

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
            k1: chacha20::Key::from_slice(&key[32..64]),
            k2: chacha20::Key::from_slice(&key[0..32])
        }
    }
}

use super::super::CryptoBuf;

impl super::CipherT for Cipher {

    fn read_packet<'a, R:BufRead>(&self, seq:usize, stream:&mut R, read_len:&mut usize,
                                  read_buffer:&'a mut CryptoBuf) -> Result<Option<&'a[u8]>,Error> {

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
        let mut nonce = [0;8];
        BigEndian::write_u32(&mut nonce[4..], seq as u32);
        let nonce = chacha20::Nonce::from_slice(&nonce);


        // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
        if *read_len == 0 {
            let mut len = [0;4];
            try!(stream.read_exact(&mut len));
            read_buffer.extend(&len);

            chacha20::stream_xor_inplace(
                &mut len,
                &nonce,
                &self.k1);

            println!("chacha20: packet length: {:?}", &len[..]);

            *read_len = BigEndian::read_u32(&len) as usize + poly1305::TAGBYTES;
        }
        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.
        if try!(super::super::read(stream, read_buffer, *read_len)) {

            println!("read_buffer {:?}", read_buffer);
            // try!(stream.read_exact(&mut buffer[4..]));
            let mut poly_key = [0;32];
            chacha20::stream_xor_inplace(
                &mut poly_key,
                &nonce,
                &self.k2);
            let poly_key = poly1305::Key::from_slice(&poly_key);

            let mut tag = poly1305::Tag::new_blank();

            let read_buffer_slice = read_buffer.as_mut_slice();
            {
                poly1305::authenticate(
                    &mut tag,
                    &read_buffer_slice[0 .. 4 + *read_len - poly1305::TAGBYTES],
                    &poly_key
                );
            }

            println!("computing tag on {:?} with key {:?}",
                     &read_buffer_slice[0 .. 4 + *read_len - poly1305::TAGBYTES],
                     poly_key
            );

            
            // println!("read buffer before chacha20: {:?}", &read_buffer);
            // - Constant-time-compare it with the Poly1305 at the end of the packet (right after the 4+length first bytes).
            if sodium::memcmp(
                tag.as_bytes(),
                &read_buffer_slice[ 4 + *read_len - poly1305::TAGBYTES ..]
            ) {

                // - If the auth is correct, chacha20-xor the length bytes after the first 4 ones, with ic 1.
                //   (actually, the above doc says "ic = LE encoding of 1", which is different from the libsodium interface).

                {
                    chacha20::xor_inplace(&mut read_buffer_slice[4..(4 + *read_len - poly1305::TAGBYTES)],
                                          &nonce,
                                          1,
                                          &self.k2);

                }
                let padding = read_buffer_slice[4] as usize;
                // println!("read packet = {:?}", &read_buffer_slice[5..(5+ *read_len - poly1305::TAGBYTES - padding - 1)]);
                println!("padding len = {:?}", padding);
                Ok(Some(&read_buffer_slice[5..(5+ *read_len - poly1305::TAGBYTES - padding - 1)]))

            } else {
                println!("should be {:?}, was {:?}", tag.as_bytes(), &read_buffer_slice[4 + *read_len - poly1305::TAGBYTES..]);
                Err(Error::PacketAuth)
            }
        } else {
            Ok(None)
        }
    }

    fn write_packet(&self, seq:usize, packet_content:&[u8], buffer:&mut CryptoBuf) {

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

        // - Compute the length, by chacha20-stream-xoring the first 4 bytes with the last 32 bytes of the client key.
        buffer.clear();
        println!("seqnr = {}", seq);
        let block_size = 8;
        let padding_len = {
            (block_size - ((1 + packet_content.len()) % block_size))
        };
        // println!("padding_len {:?} {:?} {:?}", packet_content.len(), padding_len, poly1305::TAGBYTES);
        let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };
        let padding_len = padding_len + 16;

        println!("pushing len: {:?}", packet_content.len() + padding_len + 1);
        buffer.push_u32_be((packet_content.len() + padding_len + 1) as u32);

        let mut nonce = [0;8];
        BigEndian::write_u32(&mut nonce[4..], seq as u32);
        let nonce = chacha20::Nonce::from_slice(&nonce);

        {
            let buffer = buffer.as_mut_slice();
            chacha20::stream_xor_inplace(
                &mut buffer[0..4],
                &nonce,
                &self.k1);
        }
        // the first 4 bytes of buffer now contain the encrypted length.
        // - Append the encrypted packet

        // Compute the amount of padding.
        println!("padding_len {:?}", padding_len);
        buffer.push(padding_len as u8);

        buffer.extend(packet_content);

        println!("buffer before padding: {:?}", buffer.as_slice());

        let mut padding = [0;256];

        randombytes::into(&mut padding[0..padding_len]);
        buffer.extend(&padding[0..padding_len]);

        println!("buffer before encryption: {:?}", buffer.as_slice());

        {
            let buffer = buffer.as_mut_slice();
            chacha20::xor_inplace(&mut buffer[4..],
                                  &nonce,
                                  1,
                                  &self.k2);
        }
        println!("buffer before tag: {:?}", buffer.as_slice());
        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

        let mut poly_key = [0;poly1305::KEYBYTES];
        chacha20::stream_xor_inplace(
            &mut poly_key,
            &nonce,
            &self.k2);
        let poly_key = poly1305::Key::from_slice(&poly_key);

        println!("key: {:?}", poly_key);
        let mut tag = poly1305::Tag::new_blank();
        {
            let buffer = buffer.as_slice();
            poly1305::authenticate(&mut tag, buffer, &poly_key);
        }

        // try!(stream.write(&buffer));
        // try!(stream.write(tag.as_bytes()));

        buffer.extend(tag.as_bytes());

    }
}


#[test]
fn write_read() {
    use super::CipherT;
    use super::super::CryptoBuf;

    let k1 = chacha20::gen_key();
    let k2 = chacha20::gen_key();
    let key = Cipher {
        k1:k1,
        k2:k2
    };

    let plaintext = b"some data";
    let seq = 12;
    let mut stream = CryptoBuf::new();

    key.write_packet(seq, plaintext, &mut stream);

    println!("================ stream {:?}", stream.as_slice());

    let mut stream = stream.as_slice();

    let mut read_len = 0;

    let mut buffer = CryptoBuf::new();
    let packet = key.read_packet(seq, &mut stream, &mut read_len, &mut buffer).unwrap().unwrap();
    println!("{:?}", packet);
    assert_eq!(packet, plaintext);

}

