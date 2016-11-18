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

use super::super::Error;
use ring::aead;

pub type OpeningKey = aead::chacha20_poly1305_openssh::OpeningKey;
pub type SealingKey = aead::chacha20_poly1305_openssh::SealingKey;

pub const KEY_LEN: usize = aead::chacha20_poly1305_openssh::KEY_LEN;
const TAG_LEN: usize = aead::chacha20_poly1305_openssh::TAG_LEN;

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: 64,
    make_opening_cipher: make_opening_cipher,
    make_sealing_cipher: make_sealing_cipher,
};

pub const NAME: super::Name = super::Name("chacha20-poly1305@openssh.com");

fn make_opening_cipher(key: &[u8]) -> super::OpeningCipher {
    let key = array_ref![key, 0, KEY_LEN];
    super::OpeningCipher::Chacha20Poly1305(OpeningKey::new(key))
}

fn make_sealing_cipher(key: &[u8]) -> super::SealingCipher {
    let key = array_ref![key, 0, KEY_LEN];
    super::SealingCipher::Chacha20Poly1305(SealingKey::new(key))
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(&self,
                             sequence_number: u32,
                             encrypted_packet_length: [u8; 4])
                             -> [u8; 4] {
        <OpeningKey>::decrypt_packet_length(self, sequence_number, encrypted_packet_length)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(&self,
                sequence_number: u32,
                ciphertext_in_plaintext_out: &'a mut [u8],
                tag: &[u8])
                -> Result<&'a [u8], Error> {
        let tag = array_ref![tag, 0, TAG_LEN];
        self.open_in_place(sequence_number, ciphertext_in_plaintext_out, tag)
            .map_err(|_| Error::PacketAuth)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            (block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size))
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// Append an encrypted packet with contents `packet_content` at the end of `buffer`.
    fn seal(&self,
            sequence_number: u32,
            plaintext_in_ciphertext_out: &mut [u8],
            tag_out: &mut [u8]) {

        let tag_out = array_mut_ref![tag_out, 0, TAG_LEN];
        self.seal_in_place(sequence_number, plaintext_in_ciphertext_out, tag_out);
    }
}
