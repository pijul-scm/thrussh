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
use byteorder::{ByteOrder, BigEndian};
use super::super::Error;
use std::io::BufRead;
use sshbuffer::SSHBuffer;
use ring::{chacha, poly1305};

#[derive(Debug)]
pub struct Key {
    k1: chacha::Key,
    k2: chacha::Key,
}

impl Key {
    pub fn init(key: &[u8]) -> Key {
        Key {
            k1: chacha::key_from_bytes(array_ref![key, 32, 32]),
            k2: chacha::key_from_bytes(array_ref![key, 0, 32]),
        }
    }
}

impl super::OpeningKey for Key {
    fn open<'a>(&self,
                stream: &mut BufRead,
                read_buffer: &'a mut SSHBuffer)
                -> Result<Option<&'a [u8]>, Error> {

        // http://cvsweb.openbsd.org/cgi-bin/cvsweb/
        // src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
        let mut nonce = [0; chacha::NONCE_LEN];
        BigEndian::write_u32(&mut nonce[(chacha::NONCE_LEN - 4)..],
                             read_buffer.seqn as u32);
        let mut counter = chacha::make_counter(&nonce, 0);

        // - Compute the length, by chacha20-stream-xoring the first 4
        // bytes with the last 32 bytes of the client key.
        if read_buffer.len == 0 {
            read_buffer.buffer.clear();
            let mut len = [0; 4];
            try!(stream.read_exact(&mut len));
            read_buffer.buffer.extend(&len);
            chacha::chacha20_xor_in_place(&self.k1, &counter, &mut len);

            read_buffer.len = BigEndian::read_u32(&len) as usize + poly1305::TAG_LEN;
            debug!("buffer len: {:?}", read_buffer.len);
        }
        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.
        if try!(super::read(stream,
                            &mut read_buffer.buffer,
                            read_buffer.len,
                            &mut read_buffer.bytes)) {

            let mut poly_key = [0; poly1305::KEY_LEN];
            chacha::chacha20_xor_in_place(&self.k2, &counter, &mut poly_key);

            if read_buffer.len < 1 + poly1305::TAG_LEN {
                return Err(Error::IndexOutOfBounds);
            }
            try!(poly1305::verify(&poly_key,
                                  &read_buffer.buffer[0..4 + read_buffer.len - poly1305::TAG_LEN],
                                  &read_buffer.buffer[4 + read_buffer.len - poly1305::TAG_LEN..])
                .map_err(|_| Error::PacketAuth));

            // - If the auth is correct, chacha20-xor the length
            // bytes after the first 4 ones, with ic 1.
            // (actually, the above doc says "ic = LE encoding of
            // 1", which is different from the libsodium
            // interface).

            counter[0] = 1;
            chacha::chacha20_xor_in_place(&self.k2,
                                          &counter,
                                          &mut read_buffer.buffer[4..(4 + read_buffer.len -
                                                                      poly1305::TAG_LEN)]);
            let padding = read_buffer.buffer[4] as usize;
            if read_buffer.len < 1 + padding + poly1305::TAG_LEN {
                return Err(Error::IndexOutOfBounds);
            }
            let result = Some(&read_buffer.buffer[5..(4 + read_buffer.len - poly1305::TAG_LEN -
                                                      padding)]);
            read_buffer.seqn += 1;
            read_buffer.len = 0;
            Ok(result)
        } else {
            Ok(None)
        }
    }
}

impl super::SealingKey for Key {
    fn block_size(&self) -> usize { 8 }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    /// Append an encrypted packet with contents `packet_content` at the end of `buffer`.
    fn seal(&self, packet_content: &[u8], buffer: &mut SSHBuffer) {
        // http://cvsweb.openbsd.org/cgi-bin/
        // cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
        let offset = buffer.buffer.len();
        // - Compute the length, by chacha20-stream-xoring the first 4
        // bytes with the last 32 bytes of the client key.

        let block_size = self.block_size();
        let padding_len = if packet_content.len() + 5 <= 16 {
            16 - packet_content.len() - 1
        } else {
            (block_size - ((1 + packet_content.len()) % block_size))
        };
        let padding_len = if padding_len < 4 {
            padding_len + block_size
        } else {
            padding_len
        };

        buffer.buffer.push_u32_be((packet_content.len() + padding_len + 1) as u32);

        let mut nonce = [0; chacha::NONCE_LEN];
        BigEndian::write_u32(&mut nonce[(chacha::NONCE_LEN - 4)..], buffer.seqn as u32);

        let mut counter = chacha::make_counter(&nonce, 0);

        chacha::chacha20_xor_in_place(&self.k1, &counter, &mut buffer.buffer[offset..(offset + 4)]);
        // the first 4 bytes of buffer now contain the encrypted length.
        // - Append the encrypted packet

        // Compute the amount of padding.
        // println!("padding_len {:?}", padding_len);
        buffer.buffer.push(padding_len as u8);

        buffer.buffer.extend(packet_content);

        // println!("buffer before padding: {:?}", &(buffer.as_slice())[offset..]);

        self.fill_padding(buffer.buffer.reserve(padding_len));

        // println!("buffer before encryption: {:?}", &(buffer.as_slice())[offset..]);
        counter[0] = 1;
        chacha::chacha20_xor_in_place(&self.k2, &counter, &mut buffer.buffer[offset + 4..]);

        // println!("buffer before tag: {:?}", &(buffer.as_slice())[offset..]);
        // - Compute the Poly1305 auth on the first (4+length) first bytes of the packet.

        let mut poly_key = [0; poly1305::KEY_LEN];
        counter[0] = 0;
        chacha::chacha20_xor_in_place(&self.k2, &counter, &mut poly_key);
        let mut tag = [0; poly1305::TAG_LEN];
        poly1305::sign(&poly_key, &buffer.buffer[offset..], &mut tag);

        buffer.buffer.extend(&tag);
        buffer.seqn += 1;
    }
}
