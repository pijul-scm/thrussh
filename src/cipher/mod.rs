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
use super::Error;
use std::io::BufRead;
use sshbuffer::{SSHBuffer};

pub mod chacha20poly1305;

#[derive(Debug)]
pub enum Cipher {
    Chacha20Poly1305(chacha20poly1305::Cipher),
}

pub fn key_size(c: &str) -> usize {
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

pub trait CipherT {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error>;
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer);
}

pub const CHACHA20POLY1305: &'static str = "chacha20-poly1305@openssh.com";

impl CipherT for Cipher {
    fn read<'a, R: BufRead>(&self,
                            stream: &mut R,
                            buffer: &'a mut SSHBuffer)
                            -> Result<Option<&'a [u8]>, Error> {

        match *self {
            Cipher::Chacha20Poly1305(ref cipher) => cipher.read(stream, buffer),
        }
    }
    fn write(&self, packet: &[u8], buffer: &mut SSHBuffer) {

        match *self {
            Cipher::Chacha20Poly1305(ref cipher) => cipher.write(packet, buffer),
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
