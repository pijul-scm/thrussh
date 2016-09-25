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
    Clear(clear::Cipher),
    Chacha20Poly1305(chacha20poly1305::Cipher),
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
    local_to_remote: Cipher::Clear(clear::Cipher),
    remote_to_local: Cipher::Clear(clear::Cipher),
};

pub trait CipherT {
    /// Replace the buffer's content with the next deciphered packet from `stream`.
    fn read<'a>(&self,
                stream: &mut BufRead,
                buffer: &'a mut SSHBuffer)
                -> Result<Option<&'a [u8]>, Error>;
    /// Extend the buffer with the encrypted packet.
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer);
}


impl<'a> Cipher {
    fn key(&'a self) -> &'a CipherT {
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
        self.remote_to_local.key().read(stream, buffer)
    }

    pub fn write(&self, packet: &[u8], buffer: &mut SSHBuffer) {
        self.local_to_remote.key().write(packet, buffer)
    }
}
