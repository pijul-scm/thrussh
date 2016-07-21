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
use std::io::{Read, BufRead};
use std;
use cryptobuf::CryptoBuf;
use sshbuffer::SSHBuffer;
use rand::{thread_rng, Rng};
pub mod chacha20poly1305;
use msg;

#[derive(Debug)]
pub enum Cipher {
    Clear,
    Chacha20Poly1305(chacha20poly1305::Cipher),
}

#[doc(hidden)]
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
    local_to_remote: Cipher::Clear,
    remote_to_local: Cipher::Clear,
};

pub trait CipherT {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error>;
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer);
}


impl CipherT for Cipher {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error> {

        match *self {
            Cipher::Clear => Clear.read(stream, buffer),
            Cipher::Chacha20Poly1305(ref cipher) => cipher.read(stream, buffer),
        }
    }
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer) {

        match *self {
            Cipher::Clear => Clear.write(packet, buffer),
            Cipher::Chacha20Poly1305(ref cipher) => cipher.write(packet, buffer),
        }
    }
}

pub struct Clear;

impl CipherT for Clear {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error> {

        debug!("clear buffer: {:?}", buffer);
        if buffer.len == 0 {

            // setting the length
            buffer.buffer.clear();
            buffer.buffer.extend(b"\0\0\0\0");
            try!(stream.read_exact(buffer.buffer.as_mut_slice()));
            buffer.len = buffer.buffer.read_u32_be(0) as usize;
            debug!("clear buffer len: {:?}", buffer.len);
        }
        if try!(read(stream, &mut buffer.buffer, buffer.len, &mut buffer.bytes)) {

            let padding_length = buffer.buffer[4] as usize;
            let buf = buffer.buffer.as_slice();
            let result = &buf[5..(4 + buffer.len - padding_length)];
            buffer.len = 0;
            buffer.seqn += 1;
            Ok(Some(result))

        } else {

            Ok(None)

        }
    }

    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer) {

        // Unencrypted packets should be of lengths multiple of 8.
        let block_size = 8;
        let padding_len = block_size - ((5 + packet.len()) % block_size);
        let padding_len = if padding_len < 4 {
            padding_len + block_size
        } else {
            padding_len
        };

        let packet_len = packet.len() + 1 + padding_len;
        buffer.buffer.push_u32_be(packet_len as u32);
        buffer.buffer.push(padding_len as u8);
        buffer.buffer.extend(packet);
        thread_rng().fill_bytes(buffer.buffer.reserve(padding_len));
        debug!("write: {:?}", buffer.buffer.as_slice());
        buffer.seqn += 1;
    }
}

impl Clear {
    pub fn disconnect(&self,
                      reason: Disconnect,
                      description: &str,
                      language_tag: &str,
                      buffer: &mut SSHBuffer) {

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


        thread_rng().fill_bytes(buffer.buffer.reserve(padding_len));
        debug!("write: {:?}", buffer.buffer.as_slice());
        buffer.seqn += 1;
    }
}



/// Fills the read buffer, and returns whether a complete message has been read.
fn read<R: BufRead>(stream: &mut R,
                    read_buffer: &mut CryptoBuf,
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


impl CipherT for CipherPair {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error> {

        self.remote_to_local.read(stream, buffer)
    }
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer) {

        self.local_to_remote.write(packet, buffer)

    }
}
