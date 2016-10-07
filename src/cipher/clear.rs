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

use {Error, Disconnect};
use sshbuffer::SSHBuffer;

use msg;
use encoding::Encoding;
use std::num::Wrapping;

#[derive(Debug)]
pub struct Key;

impl super::OpeningKey for Key {
    fn decrypt_packet_length(&self, _seqn: u32, packet_length: [u8; 4]) -> [u8; 4] {
        packet_length
    }

    fn tag_len(&self) -> usize { 0 }

    fn open(&self, _seqn: u32, _ciphertext_in_plaintext_out: &mut [u8], tag: &[u8])
            -> Result<(), Error> {
        debug_assert_eq!(tag.len(), self.tag_len());
        Ok(())
    }
}

impl super::SealingKey for Key {
    fn fill_padding(&self, padding_out: &mut [u8]) {
        // Since the packet is unencrypted anyway, there's no advantage to
        // randomizing the padding, so avoid possibly leaking extra RNG state
        // by padding with zeros.
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize { 0 }

    fn seal(&self, _seqn: u32, _plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        debug_assert_eq!(tag_out.len(), self.tag_len());
    }
}

pub fn disconnect(reason: Disconnect,
                  description: &str,
                  language_tag: &str,
                  buffer: &mut SSHBuffer) {
    // XXX This duplicates the logic of `CipherPair::write()` and
    // `clear::Key::seal()`. TODO: Replace this duplication by using
    // `CipherPair::write()` with `super::CLEAR_PAIR`.

    let payload_len = 13 + description.len() + language_tag.len();

    // Unencrypted packets should be of lengths multiple of 8.
    let block_size = 8;
    let padding_len = block_size - ((5 + payload_len) % block_size);
    let padding_len = if padding_len < 4 {
        padding_len + block_size
    } else {
        padding_len
    };

    let packet_len = payload_len + 1 + padding_len;
    buffer.buffer.push_u32_be(packet_len as u32);
    buffer.buffer.push(padding_len as u8);


    buffer.buffer.push(msg::DISCONNECT);
    buffer.buffer.push_u32_be(reason as u32);
    buffer.buffer.extend_ssh_string(description.as_bytes());
    buffer.buffer.extend_ssh_string(language_tag.as_bytes());

    // Since the packet is unencrypted anyway, there's no advantage to
    // randomizing the padding, so avoid possibly leaking extra RNG state
    // by padding with zeros.
    for padding_byte in buffer.buffer.reserve(padding_len) {
        *padding_byte = 0;
    }

    debug!("write: {:?}", buffer.buffer);
    buffer.seqn += Wrapping(1)
}
