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
use Error;
use std::io::BufRead;
use std;
use cryptovec::CryptoVec;
use sshbuffer::SSHBuffer;
use std::num::Wrapping;

pub mod chacha20poly1305;
pub mod clear;



pub struct Cipher {
    pub name: Name,
    pub key_len: usize,
    pub make_opening_cipher: fn(key: &[u8]) -> OpeningCipher,
    pub make_sealing_cipher: fn(key: &[u8]) -> SealingCipher,
}

pub enum OpeningCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::OpeningKey),
}

impl<'a> OpeningCipher {
    fn as_opening_key(&'a self) -> &'a OpeningKey {
        match *self {
            OpeningCipher::Clear(ref key) => key,
            OpeningCipher::Chacha20Poly1305(ref key) => key,
        }
    }
}

pub enum SealingCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::SealingKey),
}

impl<'a> SealingCipher {
    fn as_sealing_key(&'a self) -> &'a SealingKey {
        match *self {
            SealingCipher::Clear(ref key) => key,
            SealingCipher::Chacha20Poly1305(ref key) => key,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub struct CipherPair {
    pub local_to_remote: SealingCipher,
    pub remote_to_local: OpeningCipher,
}

impl std::fmt::Debug for CipherPair {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Ok(()) // TODO?
    }
}

pub const CLEAR_PAIR: CipherPair = CipherPair {
    local_to_remote: SealingCipher::Clear(clear::Key),
    remote_to_local: OpeningCipher::Clear(clear::Key),
};

pub trait OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: [u8; 4]) -> [u8; 4];

    fn tag_len(&self) -> usize;

    fn open<'a>(&self,
                seqn: u32,
                ciphertext_in_plaintext_out: &'a mut [u8],
                tag: &[u8])
                -> Result<&'a [u8], Error>;
}

pub trait SealingKey {
    fn padding_length(&self, plaintext: &[u8]) -> usize;

    fn fill_padding(&self, padding_out: &mut [u8]);

    fn tag_len(&self) -> usize;

    fn seal(&self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]);
}

/// Fills the read buffer, and returns whether a complete message has been read.
fn read(stream: &mut BufRead,
        read_buffer: &mut CryptoVec,
        read_len: usize,
        bytes_read: &mut usize)
        -> Result<(), Error> {
    // This loop consumes something or returns, it cannot loop forever.
    debug!("read: {:?}", read_len);
    loop {
        let consumed_len = {
            let buf = try!(stream.fill_buf());
            if read_buffer.len() + buf.len() < read_len + 4 {
                read_buffer.extend(buf);
                buf.len()
            } else {
                let consumed_len = read_len + 4 - read_buffer.len();
                read_buffer.extend(&buf[0..consumed_len]);
                consumed_len
            }
        };
        stream.consume(consumed_len);
        *bytes_read += consumed_len;
        if read_buffer.len() >= 4 + read_len {
            return Ok(());
        }
    }
}


impl CipherPair {
    pub fn read<'a>(&self,
                    stream: &mut BufRead,
                    buffer: &'a mut SSHBuffer)
                    -> Result<Option<&'a [u8]>, Error> {

        debug!("cipherpair::read {:?}", buffer.len);
        let key = self.remote_to_local.as_opening_key();

        let seqn = buffer.seqn.0;

        if buffer.len == 0 {
            buffer.buffer.clear();
            let mut len = [0; 4];
            try!(stream.read_exact(&mut len));
            debug!("len = {:?}", len);
            buffer.buffer.extend(&len);
            let len = key.decrypt_packet_length(seqn, len);
            buffer.len = BigEndian::read_u32(&len) as usize + key.tag_len();
        }
        debug!("buffer len: {:?} {:?}", buffer.len, key.tag_len());

        try!(read(stream, &mut buffer.buffer, buffer.len, &mut buffer.bytes));
        use std::ops::Deref;
        {
            let a: &[u8] = buffer.buffer.deref();
            debug!("buffer: {:?}", a);
        }
        let ciphertext_len = buffer.buffer.len() - key.tag_len();
        let (ciphertext, tag) = buffer.buffer.split_at_mut(ciphertext_len);
        let plaintext = try!(key.open(seqn, ciphertext, tag));

        debug!("clear: {:?}", plaintext);
        let padding_length = plaintext[0] as usize;
        let plaintext_end = try!(plaintext.len()
            .checked_sub(padding_length)
            .ok_or(Error::IndexOutOfBounds));
        debug!("padding length {:?} {:?}", padding_length, plaintext);
        let result = Some(&plaintext[1..plaintext_end]);

        // Sequence numbers are on 32 bits and wrap.
        // https://tools.ietf.org/html/rfc4253#section-6.4
        buffer.seqn += Wrapping(1);
        buffer.len = 0;
        Ok(result)
    }

    pub fn write(&self, payload: &[u8], buffer: &mut SSHBuffer) {
        // https://tools.ietf.org/html/rfc4253#section-6
        //
        // The variables `payload`, `packet_length` and `padding_length` refer
        // to the protocol fields of the same names.

        let key = self.local_to_remote.as_sealing_key();

        let padding_length = key.padding_length(payload);
        let packet_length = PADDING_LENGTH_LEN + payload.len() + padding_length;
        let offset = buffer.buffer.len();

        // Maximum packet length:
        // https://tools.ietf.org/html/rfc4253#section-6.1
        assert!(packet_length <= std::u32::MAX as usize);
        buffer.buffer.push_u32_be(packet_length as u32);

        assert!(padding_length <= std::u8::MAX as usize);
        buffer.buffer.push(padding_length as u8);
        buffer.buffer.extend(payload);
        key.fill_padding(buffer.buffer.reserve(padding_length));
        buffer.buffer.reserve(key.tag_len());

        {
            let (plaintext, tag) = buffer.buffer[offset..]
                .split_at_mut(PACKET_LENGTH_LEN + packet_length);

            key.seal(buffer.seqn.0, plaintext, tag);
            debug!("write sealed: {:?}", plaintext);
        }

        // Sequence numbers are on 32 bits and wrap.
        // https://tools.ietf.org/html/rfc4253#section-6.4
        buffer.seqn += Wrapping(1);
    }
}


pub const PACKET_LENGTH_LEN: usize = 4;

const MINIMUM_PACKET_LEN: usize = 16;

const PADDING_LENGTH_LEN: usize = 1;
