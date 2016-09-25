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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use byteorder::{ByteOrder, BigEndian};
use super::super::Error;
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
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: [u8; 4]) -> [u8; 4] {
        let mut packet_length = encrypted_packet_length;
        let mut nonce = [0; chacha::NONCE_LEN];
        BigEndian::write_u32(&mut nonce[(chacha::NONCE_LEN - 4)..], seqn);
        let counter = chacha::make_counter(&nonce, 0);
        chacha::chacha20_xor_in_place(&self.k1, &counter, &mut packet_length);
        packet_length
    }

    fn tag_len(&self) -> usize { poly1305::TAG_LEN }

    fn open(&self, seqn: u32, ciphertext_in_plaintext_out: &mut [u8], tag: &[u8])
            -> Result<(), Error> {
        let tag = array_ref![tag, 0, poly1305::TAG_LEN];

        let mut nonce = [0; chacha::NONCE_LEN];
        BigEndian::write_u32(&mut nonce[(chacha::NONCE_LEN - 4)..], seqn);
        let mut counter = chacha::make_counter(&nonce, 0);

        let mut poly_key = [0; poly1305::KEY_LEN];
        chacha::chacha20_xor_in_place(&self.k2, &counter, &mut poly_key);

        try!(poly1305::verify(&poly_key, ciphertext_in_plaintext_out, tag)
            .map_err(|_| Error::PacketAuth));

        // The first `PACKET_LENGTH_LEN` bytes were encrypted with self.k1 and
        // were already decrypted with decrypt_packet_length.
        counter[0] = 1;
        chacha::chacha20_xor_in_place(&self.k2,
                                      &counter,
                                      &mut ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..]);

        Ok(())
    }
}

impl super::SealingKey for Key {
    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize { poly1305::TAG_LEN }

    /// Append an encrypted packet with contents `packet_content` at the end of `buffer`.
    fn seal(&self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        // http://cvsweb.openbsd.org/cgi-bin/
        // cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

        let mut tag_out = array_mut_ref![tag_out, 0, poly1305::TAG_LEN];

        let mut nonce = [0; chacha::NONCE_LEN];
        BigEndian::write_u32(&mut nonce[(chacha::NONCE_LEN - 4)..], seqn);

        let mut counter = chacha::make_counter(&nonce, 0);

        {
            let (len_in_out, data_and_padding_in_out) =
                plaintext_in_ciphertext_out.split_at_mut(4);

            chacha::chacha20_xor_in_place(&self.k1, &counter, len_in_out);
            // the first 4 bytes of buffer now contain the encrypted length.

            counter[0] = 1;
            chacha::chacha20_xor_in_place(&self.k2, &counter, data_and_padding_in_out);
        }

        let mut poly_key = [0; poly1305::KEY_LEN];
        counter[0] = 0;
        chacha::chacha20_xor_in_place(&self.k2, &counter, &mut poly_key);
        poly1305::sign(&poly_key, plaintext_in_ciphertext_out, &mut tag_out);
    }
}
