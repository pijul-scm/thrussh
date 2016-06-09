extern crate libc;
extern crate sodiumoxide;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate regex;
extern crate rustc_serialize;

// use rustc_serialize::hex::ToHex;

use byteorder::{ByteOrder,BigEndian, ReadBytesExt, WriteBytesExt};

use std::io::{ Read, Write, BufRead };

use std::sync::{Once, ONCE_INIT};

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
    IO(std::io::Error)
}

impl From<std::io::Error> for Error {
    fn from(e:std::io::Error) -> Error {
        Error::IO(e)
    }
}

mod msg;
mod kex;

pub mod key;
mod cipher;

mod mac;
use mac::*;

mod negociation;
use negociation::*;

mod compression;


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


#[derive(Debug)]
pub struct ServerSession<'a> {
    keys:&'a[key::Algorithm],
    server_id: &'a str,
    recv_seqn: usize,
    sent_seqn: usize,

    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    write_position: usize,

    state: Option<ServerState>
}

#[derive(Debug)]
pub enum ServerState {
    VersionOk(Exchange), // Version number received.
    KexInit { // Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively.
        algo: Option<Names>,
        exchange: Exchange,
        session_id: Option<kex::Digest>,
        sent: bool
    },
    KexDh { // Algorithms have been determined, the DH algorithm should run.
        exchange: Exchange,
        kex: kex::Name,
        key: key::Algorithm,
        cipher: cipher::Name,
        mac: Mac,
        session_id: Option<kex::Digest>,
        follows: bool
    },
    KexDhDone { // The kex has run.
        exchange: Exchange,
        kex: kex::Algorithm,
        key: key::Algorithm,
        cipher: cipher::Name,
        mac: Mac,
        session_id: Option<kex::Digest>,
        follows: bool
    },
    NewKeys { // The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side.
        exchange: Exchange,
        kex: kex::Algorithm,
        key: key::Algorithm,
        cipher: cipher::Cipher,
        mac: Mac,
        session_id: kex::Digest,
    },
    Encrypted { // Session is now encrypted.
        exchange: Exchange,
        kex: kex::Algorithm,
        key: key::Algorithm,
        cipher: cipher::Cipher,
        mac: Mac,
        session_id: kex::Digest,
    },
}


trait Named:Sized {
    fn from_name(&[u8]) -> Option<Self>;
}

trait Preferred:Sized {
    fn preferred() -> &'static [&'static str];
}


fn complete_packet(buf:&mut Vec<u8>, off:usize) {

    let block_size = 8; // no MAC yet.
    let padding_len = {
        (block_size - ((buf.len() - off) % block_size))
    };
    let padding_len = if padding_len < 4 { padding_len + block_size } else { padding_len };
    let mac_len = 0;

    let packet_len = buf.len() - off - 4 + padding_len + mac_len;
    BigEndian::write_u32(&mut buf[off..], packet_len as u32);

    buf[off + 4] = padding_len as u8;

    let mut padding = [0;256];
    sodiumoxide::randombytes::randombytes_into(&mut padding[0..padding_len]);

    buf.extend(&padding[0..padding_len]);

}

trait SSHString:Write {
    fn write_ssh_string(&mut self, s:&[u8]) -> Result<(), std::io::Error> {
        try!(self.write_u32::<BigEndian>(s.len() as u32));
        try!(self.write(s));
        Ok(())
    }
    fn write_ssh_mpint(&mut self, s:&[u8]) -> Result<(), std::io::Error> {
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i+=1
        }
        if s[i] & 0x80 != 0 {
            try!(self.write_u32::<BigEndian>((s.len() - i + 1) as u32));
            try!(self.write_u8(0));
        } else {
            try!(self.write_u32::<BigEndian>((s.len() - i) as u32));
        }
        try!(self.write(&s[i..]));
        Ok(())
    }
}
impl<T:Write> SSHString for T {}




pub fn hexdump(x:&[u8]) {
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


impl<'a> ServerSession<'a> {

    pub fn new(server_id:&'a str, keys: &'a [key::Algorithm]) -> Self {
        SODIUM_INIT.call_once(|| { sodiumoxide::init(); });
        ServerSession {
            keys:keys,
            server_id: server_id,
            recv_seqn: 0,
            sent_seqn: 0,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            write_position: 0,
            state: None
        }
    }

    fn read_clear_packet<R:BufRead>(&mut self, stream:&mut R) -> Result<bool,Error> {
        println!("read_buffer :{:?}", self.read_buffer);
        if self.read_buffer.len() == 0 {
            // Packet lengths are always multiples of 8, so is a StreamBuf.
            // Therefore, this can never block.
            self.read_buffer.resize(4,0);
            try!(stream.read_exact(&mut self.read_buffer[0..4]));
        }
        let packet_len = BigEndian::read_u32(&self.read_buffer) as usize;

        // This loop consumes something or returns, it cannot loop forever.
        loop {
            println!("loop spinning {:?}/{:?}", self.read_buffer.len(), packet_len);
            let initial_position = self.read_buffer.len();
            let consumed_len = match stream.fill_buf() {
                Ok(buf) => {
                    if self.read_buffer.len() + buf.len() < packet_len + 4 {

                        self.read_buffer.extend(buf);
                        buf.len()

                    } else {
                        let consumed_len = packet_len + 4 - self.read_buffer.len();
                        self.read_buffer.extend(&buf[0..consumed_len]);
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
            if self.read_buffer.len() >= packet_len {
                // Done
                self.recv_seqn += 1;
                return Ok(true)
            }
        }

    }
    fn get_current_payload<'b>(&'b mut self) -> &'b[u8] {
        let packet_length = BigEndian::read_u32(&self.read_buffer) as usize;
        let padding_length = self.read_buffer[4] as usize;

        let payload = &self.read_buffer[ 5 .. (4 + packet_length - padding_length) ];
        println!("payload : {:?} {:?} {:?}", payload.len(), padding_length, packet_length);
        payload
    }

    fn read_packet<R:Read>(&mut self, stream:&mut R, buf:&mut Vec<u8>) -> Result<usize,Error> {

        println!("read_packet should be replaced");

        let packet_length = try!(stream.read_u32::<BigEndian>()) as usize;
        let padding_length = try!(stream.read_u8()) as usize;

        println!("packet_length {:?}", packet_length);
        buf.resize(packet_length - 1, 0);
        try!(stream.read_exact(&mut buf[0..(packet_length - 1)]));

        self.recv_seqn += 1;
        // return the read length without padding.
        Ok(packet_length - 1 - padding_length)
    }

    
    pub fn read<R:BufRead>(&mut self, stream:&mut R, buffer:&mut Vec<u8>, buffer2:&mut Vec<u8>) -> Result<(), Error> {
        let state = std::mem::replace(&mut self.state, None);
        // println!("state: {:?}", state);
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
                        return Ok(())
                    }

                    (buf.len(),
                     if &buf[0..8] == b"SSH-2.0-" {

                         let mut exchange = Exchange::new();
                         exchange.client_id = Some((&buf[ 0 .. i ]).to_vec());
                         println!("{:?}", std::str::from_utf8(&buf[ 0 .. i ]));
                         self.state = Some(ServerState::VersionOk(exchange));
                         Ok(())
                     } else {
                         Err(Error::Version)
                     })
                };
                stream.consume(len);
                result

            },
            Some(ServerState::KexInit { mut exchange, algo, sent, session_id }) => {

                let algo = if algo.is_none() {
                    
                    if try!(self.read_clear_packet(stream)) {
                        
                        // let read = self.read_packet(stream, &mut kex_init).unwrap();
                        // kex_init.truncate(read);
                        let kex = {
                            let payload = self.get_current_payload();
                            exchange.client_kex_init = Some(payload.to_vec());
                            read_kex(payload, self.keys).unwrap()
                        };
                        self.read_buffer.clear();
                        
                        Some(kex)

                    } else {
                        // A complete packet could not be read, we need to read more.
                        println!("need more bytes");
                        self.state = Some(ServerState::KexInit {
                            exchange: exchange,
                            algo:algo,
                            sent:sent,
                            session_id: session_id
                        });
                        return Ok(())
                    }
                } else {
                    algo
                };

                if !sent {
                    self.state = Some(ServerState::KexInit {
                        exchange: exchange,
                        algo:algo,
                        sent:sent,
                        session_id: session_id
                    });
                    Ok(())
                } else {
                    if let Some((kex,key,cipher,mac,follows)) = algo {
                        self.state = Some(
                            ServerState::KexDh {
                                exchange:exchange,
                                kex:kex, key:key,
                                cipher:cipher, mac:mac, follows:follows,
                                session_id: session_id
                            });
                        Ok(())
                    } else {
                        Err(Error::Kex)
                    }
                }
            },
            Some(ServerState::KexDh { mut exchange, mut kex, key, cipher, mac, follows, session_id }) => {


                if try!(self.read_clear_packet(stream)) {

                    let kex = {
                        let payload = self.get_current_payload();
                        assert!(payload[0] == msg::KEX_ECDH_INIT);
                        exchange.client_ephemeral = Some((&payload[5..]).to_vec());
                        try!(kex.dh(&mut exchange, payload))
                    };
                    self.state = Some(
                        ServerState::KexDhDone {
                            exchange:exchange,
                            kex:kex,
                            key:key,
                            cipher:cipher, mac:mac, follows:follows,
                            session_id: session_id
                        });

                    self.read_buffer.clear();
                    
                    Ok(())

                } else {
                    // not enough bytes.
                    self.state = Some(
                        ServerState::KexDh {
                            exchange:exchange,
                            kex:kex,
                            key:key,
                            cipher:cipher, mac:mac, follows:follows,
                            session_id: session_id
                        });
                    Ok(())
                }
            },
            Some(ServerState::NewKeys { exchange, kex, key, cipher, mac, session_id }) => {

                // We are waiting for the NEWKEYS packet.
                if try!(self.read_clear_packet(stream)) {

                    let payload_is_newkeys = self.get_current_payload()[0] == msg::NEWKEYS;
                    if payload_is_newkeys {
                        self.state = Some(
                            ServerState::Encrypted { exchange: exchange, kex:kex, key:key,
                                                     cipher:cipher, mac:mac,
                                                     session_id: session_id,
                            }
                        );
                        Ok(())
                    } else {
                        Err(Error::NewKeys)
                    }
                } else {
                    // Not enough bytes
                    self.state = Some(
                        ServerState::Encrypted { exchange: exchange, kex:kex, key:key,
                                                 cipher:cipher, mac:mac,
                                                 session_id: session_id,
                        }
                    );
                    Ok(())
                }
            },
            mut state @ Some(ServerState::Encrypted { .. }) => {
                println!("read: encrypted");
                match state {
                    Some(ServerState::Encrypted { ref mut cipher, .. }) => {

                        let buf = try!(cipher.read_client_packet(&mut self.recv_seqn, stream, buffer));
                        println!("decrypted {:?}", buf);
                    },
                    _ => unreachable!()
                }
                self.state = state;
                Ok(())
            },
            _ => {
                println!("read: unhandled");
                Ok(())
            }
        }
    }

    fn write_all<W:Write>(&mut self, stream:&mut W) -> Result<bool, Error> {
        while self.write_position < self.write_buffer.len() {
            match stream.write(&self.write_buffer) {
                Ok(s) => self.write_position += s,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(false) // need more bytes
                    } else {
                        return Err(Error::IO(e))
                    }
                }
            }
        }
        try!(stream.flush());
        Ok(true)
    }
    
    pub fn write<W:Write>(&mut self, stream:&mut W, buffer:&mut Vec<u8>, buffer2:&mut Vec<u8>) -> Result<(), Error> {


        // Finish pending writes, if any.
        if ! try!(self.write_all(stream)) {
            // If we need more bytes
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
                    ServerState::KexInit {
                        exchange:exchange,
                        algo:None, sent:false,
                        session_id: None
                    }
                );
                Ok(())
            },
            Some(ServerState::KexInit { mut exchange, algo, sent, session_id }) => {
                if !sent {

                    self.write_buffer.extend(b"\0\0\0\0\0");
                    write_kex(&self.keys, &mut self.write_buffer);
                    exchange.server_kex_init = Some((&self.write_buffer [5..]).to_vec());
                    complete_packet(&mut self.write_buffer, 0);
                    try!(self.write_all(stream));

                }
                if let Some((kex,key,cipher,mac,follows)) = algo {

                    self.state = Some(
                        ServerState::KexDh {
                            exchange:exchange,
                            kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                            session_id: session_id
                    });
                    Ok(())
                } else {
                    self.state = Some(
                        ServerState::KexInit {
                            exchange:exchange,
                            algo:algo, sent:true,
                            session_id: session_id
                        }
                    );
                    Ok(())
                }
            },
            Some(ServerState::KexDhDone { exchange, kex, key, mut cipher, mac, follows, session_id }) => {

                let hash = try!(kex.compute_exchange_hash(&key, &exchange, buffer));

                if let Some(ref server_ephemeral) = exchange.server_ephemeral {

                    // ECDH Key exchange.
                    // http://tools.ietf.org/html/rfc5656#section-4
                    self.write_buffer.extend(b"\0\0\0\0\0");
                    self.write_buffer.push(msg::KEX_ECDH_REPLY);
                    try!(key.write_pubkey(&mut self.write_buffer));
                    // Server ephemeral
                    try!(self.write_buffer.write_ssh_string(server_ephemeral));
                    // Hash signature
                    try!(key.add_signature(&mut self.write_buffer, hash.as_slice()));
                    //
                    complete_packet(&mut self.write_buffer, 0);

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
                try!(self.write_all(stream));

                let session_id = if let Some(session_id) = session_id {
                    session_id
                } else {
                    hash.clone()
                };
                // Now computing keys.
                let c = kex.compute_keys(&session_id, &hash, buffer, buffer2, &mut cipher);
                // keys.dump(); //println!("keys: {:?}", keys);
                //
                self.state = Some(
                    ServerState::NewKeys {
                        exchange: exchange,
                        kex:kex, key:key,
                        cipher: c,
                        mac:mac,
                        session_id: session_id,
                    }
                );
                Ok(())
            },
            mut enc @ Some(ServerState::Encrypted { .. }) => {
                match enc {
                    Some(ServerState::Encrypted { ref mut cipher, .. }) => {
                        // unimplemented!()
                    },
                    _ => unreachable!()
                }
                self.state = enc;
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
