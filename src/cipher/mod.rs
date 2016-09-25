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
use Error;
use std::io::BufRead;
use std;
use cryptovec::CryptoVec;
use sshbuffer::SSHBuffer;

pub mod chacha20poly1305;
pub mod clear;

#[derive(Debug)]
pub enum Cipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::Key),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub const CHACHA20POLY1305: Name = Name("chacha20-poly1305@openssh.com");

pub fn key_size(c: Name) -> usize {
    match c {
        CHACHA20POLY1305 => 64,
        _ => 0,
    }
}

#[derive(Debug)]
pub struct CipherPair {
    pub local_to_remote: Cipher,
    pub remote_to_local: Cipher,
}

pub const CLEAR_PAIR: CipherPair = CipherPair {
    local_to_remote: Cipher::Clear(clear::Key),
    remote_to_local: Cipher::Clear(clear::Key),
};

pub trait OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: [u8; 4]) -> [u8; 4];

    /// Replace the buffer's content with the next deciphered packet from `stream`.
    fn open<'a>(&self,
                stream: &mut BufRead,
                buffer: &'a mut SSHBuffer)
                -> Result<Option<&'a [u8]>, Error>;
}

pub trait SealingKey {
    fn fill_padding(&self, padding_out: &mut [u8]);

    fn tag_len(&self) -> usize;

    fn seal(&self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]);
}

impl<'a> Cipher {
    fn as_opening_key(&'a self) -> &'a OpeningKey {
        match *self {
            Cipher::Clear(ref key) => key,
            Cipher::Chacha20Poly1305(ref key) => key,
        }
    }

    fn as_sealing_key(&'a self) -> &'a SealingKey {
        match *self {
            Cipher::Clear(ref key) => key,
            Cipher::Chacha20Poly1305(ref key) => key,
        }
    }
}

/// Fills the read buffer, and returns whether a complete message has been read.
fn read(stream: &mut BufRead,
        read_buffer: &mut CryptoVec,
        read_len: usize,
        bytes_read: &mut usize)
        -> Result<bool, Error> {
    // This loop consumes something or returns, it cannot loop forever.
    loop {
        let consumed_len = match stream.fill_buf() {
            Ok(buf) => {
                if read_buffer.len() + buf.len() < read_len + 4 {

                    read_buffer.extend(buf);
                    buf.len()

                } else {
                    let consumed_len = read_len + 4 - read_buffer.len();
                    read_buffer.extend(&buf[0..consumed_len]);
                    consumed_len
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(false);
                } else {
                    return Err(Error::IO(e));
                }
            }
        };
        stream.consume(consumed_len);
        *bytes_read += consumed_len;
        if read_buffer.len() >= 4 + read_len {
            return Ok(true);
        }
    }
}


impl CipherPair {
    pub fn read<'a>(&self, stream: &mut BufRead, buffer: &'a mut SSHBuffer)
                    -> Result<Option<&'a [u8]>, Error> {
        self.remote_to_local.as_opening_key().open(stream, buffer)
    }

    pub fn write(&self, payload: &[u8], buffer: &mut SSHBuffer) {
        // https://tools.ietf.org/html/rfc4253#section-6
        //
        // The variables `payload`, `packet_length` and `padding_length` refer
        // to the protocol fields of the same names.

        // Pad to "a multiple of the cipher block size or 8, whichever is
        // larger". Currently no block ciphers are supported so there is no
        // block size to be larger than 8.
        let block_size = MINIMUM_BLOCK_SIZE_FOR_PADDING;
        let unpadded_len = PACKET_LENGTH_LEN + PADDING_LENGTH_LEN + payload.len();
        let mut padding_length = match unpadded_len % block_size {
            0 => 0,
            n => block_size - n,
        };
        // RFC 4253 says "There MUST be at least four bytes of padding."
        if padding_length < 4 {
            padding_length += block_size;
        };
        debug_assert_eq!((unpadded_len + padding_length) % block_size, 0);

        let packet_length = PADDING_LENGTH_LEN + payload.len() + padding_length;

        let offset = buffer.buffer.len();
        let key = self.remote_to_local.as_sealing_key();

        assert!(packet_length <= std::u32::MAX as usize); // XXX: Is this really always true?
        buffer.buffer.push_u32_be(packet_length as u32);

        assert!(padding_length <= std::u8::MAX as usize);
        buffer.buffer.push(padding_length as u8);
        buffer.buffer.extend(payload);
        key.fill_padding(buffer.buffer.reserve(padding_length));
        buffer.buffer.reserve(key.tag_len());

        let (plaintext, tag) = buffer.buffer[offset..]
                                     .split_at_mut(PACKET_LENGTH_LEN + packet_length);

        assert!(buffer.seqn <= std::u32::MAX as usize); // XXX: Is this really always true?
        key.seal(buffer.seqn as u32, plaintext, tag);

        // XXX: Can't this overflow `usize` and also make the `u32' cast truncate?
        buffer.seqn += 1;
    }
}

// RFC 4253 makes reference to "the cipher block size or 8, whichever is
// larger" when specifying how the padding works. This is the "8" in "or 8".
const MINIMUM_BLOCK_SIZE_FOR_PADDING: usize = 8;

const PACKET_LENGTH_LEN: usize = 4;

const PADDING_LENGTH_LEN: usize = 1;
