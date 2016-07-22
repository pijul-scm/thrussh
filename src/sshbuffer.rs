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
use std::io::BufRead;

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
            while i < buf.len() {
                match (buf.get(i), buf.get(i + 1)) {
                    (Some(&u), Some(&v)) if u == b'\r' && v == b'\n' => break,
                    _ => {}
                }
                i += 1
            }
            if buf.len() <= 8 {
                // Not enough bytes. Don't consume, wait until we have more bytes.
                return Ok(None);
            } else if i >= buf.len() - 1 {
                return Err(Error::Version);
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
        Ok(Some(&self.buffer[0..i]))
    }
    pub fn send_ssh_id(&mut self, id: &[u8]) {
        self.buffer.extend(id);
        self.buffer.push(b'\r');
        self.buffer.push(b'\n');
    }

    /// Returns true iff the write buffer has been completely written.
    pub fn write_all<W: std::io::Write>(&mut self, stream: &mut W) -> Result<bool, Error> {
        // debug!("write_all, self = {:?}", &self.buffer);
        while self.len < self.buffer.len() {
            match self.buffer.write_all_from(self.len, stream) {
                Ok(s) => {
                    debug!("written {:?} bytes", s);
                    self.len += s;
                    self.bytes += s;
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
        self.buffer.clear();
        self.len = 0;
        Ok(true)
    }
}
