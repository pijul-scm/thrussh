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
use super::Error;
use super::cryptobuf::CryptoBuf;
use super::key;
use negociation::Named;

pub trait Bytes {
    fn bytes(&self) -> &[u8];
}

impl<A:AsRef<str>> Bytes for A {
    fn bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}
impl<'b> Bytes for &'b key::Algorithm {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}
impl CryptoBuf {
    pub fn extend_ssh_string(&mut self, s: &[u8]) {
        self.push_u32_be(s.len() as u32);
        self.extend(s);
    }
    pub fn extend_ssh_mpint(&mut self, s: &[u8]) {
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1
        }
        if s[i] & 0x80 != 0 {

            self.push_u32_be((s.len() - i + 1) as u32);
            self.push(0)

        } else {

            self.push_u32_be((s.len() - i) as u32);

        }
        self.extend(&s[i..]);
    }

    
    pub fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I) {
        let len0 = self.len();
        self.extend(&[0, 0, 0, 0]);
        let mut first = true;
        for i in list {
            if !first {
                self.push(b',')
            } else {
                first = false;
            }
            self.extend(i.bytes())
        }
        let len = (self.len() - len0 - 4) as u32;

        let buf = self.as_mut_slice();
        BigEndian::write_u32(&mut buf[len0..], len);
    }

    pub fn write_empty_list(&mut self) {
        self.extend(&[0, 0, 0, 0]);
    }
}

pub trait Reader {
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a>;
}

impl Reader for CryptoBuf {
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a> {
        Position {
            s: self.as_slice(),
            position: starting_at,
        }
    }
}

impl Reader for [u8] {
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a> {
        Position {
            s: self,
            position: starting_at,
        }
    }
}

pub struct Position<'a> {
    s: &'a [u8],
    pub position: usize,
}
impl<'a> Position<'a> {
    pub fn read_string(&mut self) -> Result<&'a [u8], Error> {

        let len = BigEndian::read_u32(&self.s[self.position..]) as usize;
        if self.position + 4 + len <= self.s.len() {
            let result = &self.s[(self.position + 4)..(self.position + 4 + len)];
            self.position += 4 + len;
            Ok(result)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        if self.position + 4 <= self.s.len() {
            let u = BigEndian::read_u32(&self.s[self.position..]);
            self.position += 4;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    pub fn read_byte(&mut self) -> Result<u8, Error> {
        if self.position + 1 <= self.s.len() {
            let u = self.s[self.position];
            self.position += 1;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
}
