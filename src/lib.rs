extern crate libc;
extern crate libsodium_sys;
#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate regex; // for config.
extern crate time;

use byteorder::{ByteOrder,BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{ Read, Write, BufRead };
use std::sync::{Once, ONCE_INIT};


mod sodium;
mod cryptobuf;
pub use cryptobuf::CryptoBuf;

pub mod config;

static SODIUM_INIT: Once = ONCE_INIT;
#[derive(Debug)]
pub enum Error {
    CouldNotReadKey,
    KexInit,
    Version,
    Kex,
    DH,
    PacketAuth,
    NewKeys,
    Inconsistent,
    IO(std::io::Error)
}

impl From<std::io::Error> for Error {
    fn from(e:std::io::Error) -> Error {
        Error::IO(e)
    }
}

mod negociation;
use negociation::*;
mod msg;
mod kex;

mod cipher;
pub mod key;

mod mac;
use mac::*;


mod compression;


#[derive(Debug)]
pub struct ServerSession<'a> {
    keys:&'a[key::Algorithm],
    server_id: &'a str,
    recv_seqn: usize,
    sent_seqn: usize,

    read_buffer: CryptoBuf,
    read_len: usize, // next packet length.
    write_buffer: CryptoBuf,
    write_position: usize, // first position of non-written suffix.

    read_bytes:usize,
    written_bytes:usize,
    last_kex_time:u64,
    
    state: Option<ServerState>
}

#[derive(Debug)]
pub enum ServerState {
    VersionOk(Exchange), // Version number received.
    KexInit(KexInit), // Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively.
    KexDh(KexDh), // Algorithms have been determined, the DH algorithm should run.
    KexDhDone(KexDhDone), // The kex has run.
    NewKeys(Encrypted), // The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side.
    Encrypted(Encrypted) // Session is now encrypted.
}

#[derive(Debug)]
pub struct KexInit {
    algo: Option<Names>,
    exchange: Exchange,
    session_id: Option<kex::Digest>,
    sent: bool
}

#[derive(Debug)]
pub struct KexDh {
    exchange: Exchange,
    kex: kex::Name,
    key: key::Algorithm,
    cipher: cipher::Name,
    mac: Mac,
    session_id: Option<kex::Digest>,
    follows: bool
}

#[derive(Debug)]
pub struct KexDhDone {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Name,
    mac: Mac,
    session_id: Option<kex::Digest>,
    follows: bool
}


#[derive(Debug)]
pub struct Encrypted {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
}


#[derive(Debug)]
pub struct Exchange {
    client_id:Option<Vec<u8>>,
    server_id:Option<Vec<u8>>,
    client_kex_init:Option<Vec<u8>>,
    server_kex_init:Option<Vec<u8>>,
    client_ephemeral:Option<Vec<u8>>,
    server_ephemeral:Option<Vec<u8>>
}

impl Exchange {
    fn new() -> Self {
        Exchange { client_id: None,
                   server_id: None,
                   client_kex_init: None,
                   server_kex_init: None,
                   client_ephemeral: None,
                   server_ephemeral: None }
    }
}


fn complete_packet(buf:&mut CryptoBuf, off:usize) {

    let block_size = 8; // no MAC yet.
    let padding_len = {
        (block_size - ((buf.len() - off) % block_size))
    };
    let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };
    let mac_len = 0;

    let packet_len = buf.len() - off - 4 + padding_len + mac_len;
    {
        let buf = buf.as_mut_slice();
        BigEndian::write_u32(&mut buf[off..], packet_len as u32);
        buf[off + 4] = padding_len as u8;
    }


    let mut padding = [0;256];
    sodium::randombytes::into(&mut padding[0..padding_len]);

    buf.extend(&padding[0..padding_len]);

}

impl CryptoBuf {
    fn extend_ssh_string(&mut self, s:&[u8]) {
        self.push_u32_be(s.len() as u32);
        self.extend(s);
    }
    fn extend_ssh_mpint(&mut self, s:&[u8]) {
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i+=1
        }
        if s[i] & 0x80 != 0 {

            self.push_u32_be((s.len() - i + 1) as u32);
            self.push(0)

        } else {

            self.push_u32_be((s.len() - i) as u32);

        }
        self.extend(&s[i..]);
    }
}


pub fn hexdump(x:&CryptoBuf) {
    let x = x.as_slice();
    let mut buf = Vec::new();
    let mut i = 0;
    while i < x.len() {
        if i%16 == 0 {
            print!("{:04}: ", i)
        }
        print!("{:02x} ", x[i]);
        if x[i] >= 0x20 && x[i]<= 0x7e {
            buf.push(x[i]);
        } else {
            buf.push(b'.');
        }
        if i % 16 == 15 || i == x.len() -1 {
            while i%16 != 15 {
                print!("   ");
                i += 1
            }
            println!(" {}", std::str::from_utf8(&buf).unwrap());
            buf.clear();
        }
        i += 1
    }
}

fn read<R:BufRead>(stream:&mut R, read_buffer:&mut CryptoBuf, read_len:usize) -> Result<bool, Error> {
    // This loop consumes something or returns, it cannot loop forever.
    loop {
        let consumed_len = match stream.fill_buf() {
            Ok(buf) => {
                println!("read {:?}", buf);
                if read_buffer.len() + buf.len() < read_len + 4 {

                    read_buffer.extend(buf);
                    buf.len()

                } else {
                    let consumed_len = read_len + 4 - read_buffer.len();
                    read_buffer.extend(&buf[0..consumed_len]);
                    consumed_len
                }
            },
            Err(e) => {
                println!("error :{:?}", e);
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    println!("would block");
                    return Ok(false)
                } else {
                    return Err(Error::IO(e))
                }
            }
        };
        stream.consume(consumed_len);
        if read_buffer.len() >= 4 + read_len {
            return Ok(true)
        }
    }
}


impl<'a> ServerSession<'a> {

    pub fn new(server_id:&'a str, keys: &'a [key::Algorithm]) -> Self {
        SODIUM_INIT.call_once(|| { sodium::init(); });
        ServerSession {
            keys:keys,
            server_id: server_id,
            recv_seqn: 0,
            sent_seqn: 0,
            read_len: 0,
            read_buffer: CryptoBuf::new(),
            write_buffer: CryptoBuf::new(),

            read_bytes: 0,
            written_bytes: 0,
            last_kex_time: time::precise_time_ns(),
            
            write_position: 0,
            state: None
        }
    }

    fn set_clear_len<R:BufRead>(&mut self, stream:&mut R) -> Result<(),Error> {
        debug_assert!(self.read_len == 0);
        // Packet lengths are always multiples of 8, so is a StreamBuf.
        // Therefore, this can never block.
        self.read_buffer.clear();
        try!(self.read_buffer.read(4, stream));

        self.read_len = self.read_buffer.read_u32_be(0) as usize;
        println!("clear_len: {:?}", self.read_len);
        Ok(())
    }
    
    fn get_current_payload<'b>(&'b mut self) -> &'b[u8] {
        let packet_length = self.read_buffer.read_u32_be(0) as usize;
        let padding_length = self.read_buffer[4] as usize;

        let buf = self.read_buffer.as_slice();
        let payload = {
            &buf[ 5 .. (4 + packet_length - padding_length) ]
        };
        println!("payload : {:?} {:?} {:?}", payload.len(), padding_length, packet_length);
        payload
    }

    // returns whether a complete packet has been read.
    pub fn read<R:BufRead>(&mut self, stream:&mut R) -> Result<bool, Error> {
        let state = std::mem::replace(&mut self.state, None);
        println!("state: {:?}", state);
        match state {
            None => {

                let (len, result) = {
                    let buf = try!(stream.fill_buf());
                    let mut i = 0;
                    while i < buf.len()-1 {
                        if &buf[i..i+2] == b"\r\n" {
                            break
                        }
                        i+=1
                    }

                    if buf.len() <= 8 || i >= buf.len() - 1 {
                        // Not enough bytes. Don't consume, wait until we have more bytes. The buffer is larger than 255 anyway.
                        return Ok(false)
                    }

                    (buf.len(),
                     if &buf[0..8] == b"SSH-2.0-" {

                         let mut exchange = Exchange::new();
                         exchange.client_id = Some((&buf[ 0 .. i ]).to_vec());
                         println!("{:?}", std::str::from_utf8(&buf[ 0 .. i ]));
                         self.state = Some(ServerState::VersionOk(exchange));
                         Ok(true)
                     } else {
                         Err(Error::Version)
                     })
                };
                stream.consume(len);
                result

            },
            Some(ServerState::KexInit(mut kexinit)) => {

                let algo = if kexinit.algo.is_none() {
                    
                    if self.read_len == 0 {
                        try!(self.set_clear_len(stream));
                    }

                    if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                        self.recv_seqn += 1;
                        
                        let kex = {
                            let payload = self.get_current_payload();
                            kexinit.exchange.client_kex_init = Some(payload.to_vec());
                            read_kex(payload, self.keys).unwrap()
                        };
                        self.read_buffer.clear();
                        self.read_len = 0;
                        
                        Some(kex)

                    } else {
                        // A complete packet could not be read, we need to read more.
                        self.state = Some(ServerState::KexInit(kexinit));
                        return Ok(false)
                    }
                } else {
                    kexinit.algo
                };
                println!("sent: {:?}", kexinit.sent);
                if !kexinit.sent {
                    kexinit.algo = algo;
                    self.state = Some(ServerState::KexInit(kexinit));
                    Ok(true)
                } else {
                    if let Some((kex,key,cipher,mac,follows)) = algo {
                        self.state = Some(ServerState::KexDh(KexDh {
                            exchange:kexinit.exchange,
                            kex:kex, key:key,
                            cipher:cipher, mac:mac, follows:follows,
                            session_id: kexinit.session_id
                        }));
                        Ok(true)
                    } else {
                        Err(Error::Kex)
                    }
                }
            },
            Some(ServerState::KexDh(mut kexdh)) => {


                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }

                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    self.recv_seqn += 1;
                    let kex = {
                        let payload = self.get_current_payload();
                        assert!(payload[0] == msg::KEX_ECDH_INIT);
                        kexdh.exchange.client_ephemeral = Some((&payload[5..]).to_vec());
                        try!(kexdh.kex.dh(&mut kexdh.exchange, payload))
                    };
                    self.state = Some(
                        ServerState::KexDhDone(KexDhDone {
                            exchange:kexdh.exchange,
                            kex:kex,
                            key:kexdh.key,
                            cipher:kexdh.cipher, mac:kexdh.mac, follows:kexdh.follows,
                            session_id: kexdh.session_id
                        }));

                    self.read_buffer.clear();
                    self.read_len = 0;
                    
                    Ok(true)

                } else {
                    // not enough bytes.
                    self.state = Some(ServerState::KexDh(kexdh));
                    Ok(false)
                }
            },
            Some(ServerState::NewKeys(mut newkeys)) => {

                // We are waiting for the NEWKEYS packet.
                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }
                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    self.recv_seqn += 1;

                    let payload_is_newkeys = self.get_current_payload()[0] == msg::NEWKEYS;
                    if payload_is_newkeys {
                        self.state = Some(
                            ServerState::Encrypted(
                                Encrypted { exchange: newkeys.exchange,
                                            kex:newkeys.kex,
                                            key:newkeys.key,
                                            cipher:newkeys.cipher,
                                            mac:newkeys.mac,
                                            session_id: newkeys.session_id,
                                }
                            )
                        );

                        self.read_buffer.clear();
                        self.read_len = 0;

                        Ok(true)
                    } else {
                        Err(Error::NewKeys)
                    }
                } else {
                    // Not enough bytes
                    self.state = Some(ServerState::NewKeys(newkeys));
                    Ok(false)
                }
            },
            Some(ServerState::Encrypted(mut enc)) => {
                println!("read: encrypted");

                let mut read_packet = false;

                if let Some(buf) = try!(enc.cipher.read_client_packet(self.recv_seqn, stream,
                                                                      &mut self.read_len,
                                                                      &mut self.read_buffer)) {

                    if buf[0] == msg::SERVICE_REQUEST {
                        let len = BigEndian::read_u32(&buf[1..]) as usize;
                        println!("service request : {:?}", std::str::from_utf8(&buf[5..(5+len)]));
                    }
                    read_packet = true;
                    println!("decrypted {:?}", buf);
                } else {
                    // More bytes needed
                    println!("more bytes needed");
                }

                if read_packet {
                    self.recv_seqn += 1;
                    self.read_buffer.clear();
                    self.read_len = 0;
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(read_packet)
            },
            _ => {
                println!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    fn write_all<W:Write>(&mut self, stream:&mut W) -> Result<bool, Error> {
        println!("write_all");
        while self.write_position < self.write_buffer.len() {
            match self.write_buffer.write_all_from(self.write_position, stream) {
                Ok(s) => {
                    self.write_position += s;
                    try!(stream.flush());
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(false) // need more bytes
                    } else {
                        return Err(Error::IO(e))
                    }
                }
            }
        }
        println!("flushed");
        Ok(true)
    }
    
    pub fn write<W:Write>(&mut self, stream:&mut W, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> Result<(), Error> {

        println!("writing");
        // Finish pending writes, if any.
        if ! try!(self.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(())
        }
        self.write_buffer.clear();
        self.write_position = 0;

        let state = std::mem::replace(&mut self.state, None);

        match state {
            Some(ServerState::VersionOk(mut exchange)) => {

                self.write_buffer.extend(self.server_id.as_bytes());
                self.write_buffer.push(b'\r');
                self.write_buffer.push(b'\n');
                try!(self.write_all(stream));

                exchange.server_id = Some(self.server_id.as_bytes().to_vec());

                self.state = Some(
                    ServerState::KexInit(KexInit {
                        exchange:exchange,
                        algo:None, sent:false,
                        session_id: None
                    }
                ));
                Ok(())
            },
            Some(ServerState::KexInit(mut kexinit)) => {

                if !kexinit.sent {
                    println!("kexinit");
                    self.write_buffer.extend(b"\0\0\0\0\0");
                    write_kex(&self.keys, &mut self.write_buffer);

                    kexinit.exchange.server_kex_init = {

                        let buf = self.write_buffer.as_slice();
                        Some((&buf [5..]).to_vec())

                    };

                    complete_packet(&mut self.write_buffer, 0);
                    try!(self.write_all(stream));
                    try!(stream.flush());
                    kexinit.sent = true;
                    self.sent_seqn += 1
                }
                if let Some((kex,key,cipher,mac,follows)) = kexinit.algo {

                    self.state = Some(
                        ServerState::KexDh(KexDh {
                            exchange:kexinit.exchange,
                            kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                            session_id: kexinit.session_id
                        }));
                    Ok(())
                } else {
                    println!("write kexinit: packet not yet received");
                    self.state = Some(ServerState::KexInit(kexinit));
                    Ok(())
                }
            },
            Some(ServerState::KexDhDone(mut kexdhdone)) => {
                
                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key, &kexdhdone.exchange, buffer));

                if let Some(ref server_ephemeral) = kexdhdone.exchange.server_ephemeral {
                    println!("doing ECDH");
                    // ECDH Key exchange.
                    // http://tools.ietf.org/html/rfc5656#section-4
                    self.write_buffer.extend(b"\0\0\0\0\0");
                    self.write_buffer.push(msg::KEX_ECDH_REPLY);
                    kexdhdone.key.write_pubkey(&mut self.write_buffer);
                    // Server ephemeral
                    self.write_buffer.extend_ssh_string(server_ephemeral);
                    // Hash signature
                    kexdhdone.key.add_signature(&mut self.write_buffer, hash.as_bytes());
                    //
                    complete_packet(&mut self.write_buffer, 0);
                    self.sent_seqn += 1

                } else {

                    return Err(Error::DH)

                }
                // Sending the NEWKEYS packet.
                // https://tools.ietf.org/html/rfc4253#section-7.3
                // buffer.clear();
                let pos = self.write_buffer.len();
                self.write_buffer.extend(b"\0\0\0\0\0");
                self.write_buffer.push(msg::NEWKEYS);
                complete_packet(&mut self.write_buffer, pos);
                self.sent_seqn += 1;

                try!(self.write_all(stream));

                let session_id = if let Some(session_id) = kexdhdone.session_id {
                    session_id
                } else {
                    hash.clone()
                };
                // Now computing keys.
                let c = kexdhdone.kex.compute_keys(&session_id, &hash, buffer, buffer2, &mut kexdhdone.cipher);
                // keys.dump(); //println!("keys: {:?}", keys);
                //
                self.state = Some(ServerState::NewKeys(
                    Encrypted {
                        exchange: kexdhdone.exchange,
                        kex:kexdhdone.kex, key:kexdhdone.key,
                        cipher: c,
                        mac:kexdhdone.mac,
                        session_id: session_id,
                    }
                ));
                Ok(())
            },
            Some(ServerState::Encrypted(enc)) => {
                /*match enc {
                Some(ServerState::Encrypted { ref mut cipher, .. }) => {


                // cipher.write_server_packet(self.sent_seqn, &buffer, &mut self.write_buffer);
                // self.sent_seqn += 1;
                // try!(self.write_all(stream));
                
            },
                _ => unreachable!()
                }*/
                self.state = Some(ServerState::Encrypted(enc));
                Ok(())
            },
            session => {
                // println!("write: unhandled {:?}", session);
                self.state = session;
                Ok(())
            }
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
