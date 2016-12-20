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

use std::io::Write;
use super::*;
use std::num::Wrapping;

#[derive(Debug)]
pub struct SSHBuffer {
    pub buffer: CryptoVec,
    pub len: usize, // next packet length.
    pub bytes: usize,

    pub len_bytes: [u8;4],
    pub read_len_bytes: usize,

    // Sequence numbers are on 32 bits and wrap.
    // https://tools.ietf.org/html/rfc4253#section-6.4
    pub seqn: Wrapping<u32>,
}

impl SSHBuffer {
    pub fn new() -> Self {
        SSHBuffer {
            buffer: CryptoVec::new(),
            len: 0,
            bytes: 0,
            len_bytes: [0;4],
            read_len_bytes: 0,
            seqn: Wrapping(0),
        }
    }


    pub fn send_ssh_id(&mut self, id: &[u8]) {
        self.buffer.extend(id);
        self.buffer.push(b'\r');
        self.buffer.push(b'\n');
    }

    /// Returns true iff the write buffer has been completely written.
    pub fn write_all<W:Write>(&mut self, mut stream: W) -> Result<bool, Error> {
        while self.len < self.buffer.len() {
            let s = try!(self.buffer.write_all_from(self.len, &mut stream));
            debug!("write_all: written {} bytes", s);
            self.len += s;
            self.bytes += s;
            try!(stream.flush());
        }
        self.buffer.clear();
        self.len = 0;
        Ok(true)
    }
}
