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

use std;
use super::*;
use std::io::{BufRead};
use cryptobuf::CryptoBuf;
use time;

#[derive(Debug)]
pub struct SSHBuffers {
    pub read: SSHBuffer,
    pub write: SSHBuffer,
    pub last_rekey_s: f64,
}

#[derive(Debug)]
pub struct SSHBuffer {
    pub buffer: CryptoBuf,
    pub len: usize, // next packet length.
    pub bytes: usize,
    pub seqn: usize,
}
impl SSHBuffer {
    pub fn new() -> Self {
        SSHBuffer {
            buffer: CryptoBuf::new(),
            len: 0,
            bytes: 0,
            seqn: 0,
        }
    }
    pub fn read_ssh_id<'a, R: BufRead>(&'a mut self,
                                       stream: &'a mut R)
                                       -> Result<Option<&'a [u8]>, Error> {
        let i = {
            let buf = try!(stream.fill_buf());
            let mut i = 0;
            while i < buf.len() - 1 {
                if &buf[i..i + 2] == b"\r\n" {
                    break;
                }
                i += 1
            }
            if buf.len() <= 8 || i >= buf.len() - 1 {
                // Not enough bytes. Don't consume, wait until we have more bytes. The buffer is larger than 255 anyway.
                return Ok(None);
            }
            if &buf[0..8] == b"SSH-2.0-" {
                self.buffer.clear();
                self.bytes += i + 2;
                self.buffer.extend(&buf[0..i + 2]);
                i

            } else {
                return Err(Error::Version);
            }
        };
        stream.consume(i + 2);
        Ok(Some(&self.buffer.as_slice()[0..i]))
    }
    pub fn send_ssh_id(&mut self, id: &[u8]) {
        self.buffer.extend(id);
        self.buffer.push(b'\r');
        self.buffer.push(b'\n');
    }
}
impl SSHBuffers {
    pub fn new() -> Self {
        SSHBuffers {
            read: SSHBuffer::new(),
            write: SSHBuffer::new(),
            last_rekey_s: time::precise_time_s(),
        }
    }
    // Returns true iff the write buffer has been completely written.
    pub fn write_all<W: std::io::Write>(&mut self, stream: &mut W) -> Result<bool, Error> {
        debug!("write_all, self = {:?}", self.write.buffer.as_slice());
        while self.write.len < self.write.buffer.len() {
            match self.write.buffer.write_all_from(self.write.len, stream) {
                Ok(s) => {
                    debug!("written {:?} bytes", s);
                    self.write.len += s;
                    self.write.bytes += s;
                    try!(stream.flush());
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(false); // need more bytes
                    } else {
                        return Err(Error::IO(e));
                    }
                }
            }
        }
        self.write.buffer.clear();
        self.write.len = 0;
        Ok(true)
    }
    pub fn set_clear_len<R: BufRead>(&mut self, stream: &mut R) -> Result<(), Error> {
        if self.read.len == 0 {
            // Packet lengths are always multiples of 8, so is a StreamBuf.
            // Therefore, this can never block.
            self.read.buffer.clear();
            try!(self.read.buffer.read(4, stream));

            self.read.len = self.read.buffer.read_u32_be(0) as usize;
        }
        Ok(())
    }

    pub fn get_current_payload(&mut self) -> &[u8] {
        let packet_length = self.read.buffer.read_u32_be(0) as usize;
        let padding_length = self.read.buffer[4] as usize;

        let buf = self.read.buffer.as_slice();

        &buf[5..(4 + packet_length - padding_length)]
    }

    /// Fills the read buffer, and returns whether a complete message has been read.
    ///
    /// It would be tempting to return either a slice of `stream`, or a
    /// slice of `read_buffer`, but except for a very small number of
    /// messages, we need double buffering anyway to decrypt in place on
    /// `read_buffer`.
    pub fn read<R: BufRead>(&mut self, stream: &mut R) -> Result<bool, Error> {
        // This loop consumes something or returns, it cannot loop forever.
        loop {
            let consumed_len = match stream.fill_buf() {
                Ok(buf) => {
                    if self.read.buffer.len() + buf.len() < self.read.len + 4 {

                        self.read.buffer.extend(buf);
                        buf.len()

                    } else {
                        let consumed_len = self.read.len + 4 - self.read.buffer.len();
                        self.read.buffer.extend(&buf[0..consumed_len]);
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
            self.read.bytes += consumed_len;
            if self.read.buffer.len() >= 4 + self.read.len {
                self.read.len = 0;
                self.read.seqn += 1;
                return Ok(true);
            }
        }
    }
}
