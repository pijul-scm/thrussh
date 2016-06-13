extern crate libc;
extern crate libsodium_sys;
extern crate rand;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate log;
extern crate byteorder;

extern crate rustc_serialize; // config: read base 64.
extern crate regex; // for config.
extern crate time;

use byteorder::{ByteOrder,BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{ Read, Write, BufRead };
use std::sync::{Once, ONCE_INIT};
use std::collections::{ HashSet, HashMap };
use rand::Rng;

pub mod sodium;
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
pub mod auth;
use auth::AuthRequest;

mod encoding;

use std::marker::PhantomData;

pub struct ServerSession<T,S> {
    recv_seqn: usize,
    sent_seqn: usize,

    read_buffer: CryptoBuf,
    read_len: usize, // next packet length.
    write_buffer: CryptoBuf,
    write_position: usize, // first position of non-written suffix.

    read_bytes:usize,
    written_bytes:usize,
    last_kex_time:u64,
    
    state: Option<ServerState<S>>,
    marker: PhantomData<T>
}

pub enum ServerState<T> {
    VersionOk(Exchange), // Version number received.
    KexInit(kex::KexInit), // Version number sent. `algo` and `sent` tell wether kexinit has been received, and sent, respectively.
    KexDh(KexDh), // Algorithms have been determined, the DH algorithm should run.
    KexDhDone(KexDhDone), // The kex has run.
    NewKeys(NewKeys), // The DH is over, we've sent the NEWKEYS packet, and are waiting the NEWKEYS from the other side.
    Encrypted(Encrypted<T>) // Session is now encrypted.
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

impl KexDhDone {
    fn compute_keys(mut self, hash:kex::Digest, buffer:&mut CryptoBuf, buffer2:&mut CryptoBuf) -> NewKeys {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = self.kex.compute_keys(&session_id, &hash, buffer, buffer2, &mut self.cipher);
        NewKeys {
            exchange: self.exchange,
            kex:self.kex,
            key:self.key,
            cipher: c,
            mac:self.mac,
            session_id: session_id,
        }
    }
}

#[derive(Debug)]
pub struct NewKeys {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
}

impl NewKeys {
    fn encrypted<T>(self) -> Encrypted<T> {
        Encrypted {
            exchange: self.exchange,
            kex:self.kex,
            key:self.key,
            cipher:self.cipher,
            mac:self.mac,
            session_id: self.session_id,
            state: Some(EncryptedState::WaitingServiceRequest),
            channels: HashMap::new()
        }
    }
}


pub struct Encrypted<T> {
    exchange: Exchange,
    kex: kex::Algorithm,
    key: key::Algorithm,
    cipher: cipher::Cipher,
    mac: Mac,
    session_id: kex::Digest,
    state: Option<EncryptedState>,
    channels: HashMap<u32, Channel<T>>
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingServiceRequest,
    ServiceRequest,
    WaitingAuthRequest(AuthRequest),
    RejectAuthRequest(AuthRequest),
    WaitingSignature(AuthRequest),
    AuthRequestSuccess,
    WaitingChannelOpen,
    ChannelOpenConfirmation(ChannelParameters),
    ChannelOpened(HashSet<u32>)
}


#[derive(Debug)]
pub struct ChannelParameters {
    pub recipient_channel:u32,
    pub sender_channel:u32,
    pub initial_window_size:u32,
    pub maximum_packet_size:u32
}

pub struct Channel<S> {
    pub parameters: ChannelParameters,
    pub stdout: CryptoBuf,
    pub stderr: CryptoBuf,
    pub server: S
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


pub use auth::Authenticate;
pub trait Serve<S> {
    fn init(&S, channel:&ChannelParameters) -> Self;
    fn data(&mut self, _:&[u8], _:&mut CryptoBuf, _:&mut CryptoBuf) -> Result<(),Error> {
        Ok(())
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
                // println!("read {:?}", buf);
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
                // println!("error :{:?}", e);
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // println!("would block");
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


impl<T,S:Serve<T>> ServerSession<T,S> {

    pub fn new() -> Self {
        SODIUM_INIT.call_once(|| { sodium::init(); });
        ServerSession {

            recv_seqn: 0,
            sent_seqn: 0,
            read_len: 0,
            read_buffer: CryptoBuf::new(),
            write_buffer: CryptoBuf::new(),

            read_bytes: 0,
            written_bytes: 0,
            last_kex_time: time::precise_time_ns(),
            
            write_position: 0,
            state: None,
            marker: PhantomData
        }
    }

    fn set_clear_len<R:BufRead>(&mut self, stream:&mut R) -> Result<(),Error> {
        debug_assert!(self.read_len == 0);
        // Packet lengths are always multiples of 8, so is a StreamBuf.
        // Therefore, this can never block.
        self.read_buffer.clear();
        try!(self.read_buffer.read(4, stream));

        self.read_len = self.read_buffer.read_u32_be(0) as usize;
        // println!("clear_len: {:?}", self.read_len);
        Ok(())
    }
    
    fn get_current_payload<'b>(&'b mut self) -> &'b[u8] {
        let packet_length = self.read_buffer.read_u32_be(0) as usize;
        let padding_length = self.read_buffer[4] as usize;

        let buf = self.read_buffer.as_slice();
        let payload = {
            &buf[ 5 .. (4 + packet_length - padding_length) ]
        };
        // println!("payload : {:?} {:?} {:?}", payload.len(), padding_length, packet_length);
        payload
    }

    // returns whether a complete packet has been read.
    pub fn read<R:BufRead, A:Authenticate>(

        &mut self, config:&config::Config<A>,
        stream:&mut R, buffer:&mut CryptoBuf

    ) -> Result<bool, Error> {

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
                        return Ok(false)
                    }
                    (buf.len(),
                     if &buf[0..8] == b"SSH-2.0-" {
                         let mut exchange = Exchange::new();
                         exchange.client_id = Some((&buf[ 0 .. i ]).to_vec());
                         // println!("{:?}", std::str::from_utf8(&buf[ 0 .. i ]));
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

                if kexinit.algo.is_none() {
                    // read algo from packet.
                    if self.read_len == 0 {
                        try!(self.set_clear_len(stream));
                    }
                    if try!(read(stream, &mut self.read_buffer, self.read_len)) {
                        {
                            let payload = self.get_current_payload();
                            kexinit.algo = Some(try!(read_kex(payload, &config.keys)));
                            kexinit.exchange.client_kex_init = Some(payload.to_vec());
                        }
                        self.recv_seqn += 1;
                        self.read_buffer.clear();
                        self.read_len = 0;
                    } else {
                        // A complete packet could not be read, we need to read more.
                        self.state = Some(ServerState::KexInit(kexinit));
                        return Ok(false)
                    }
                }
                self.state = Some(try!(kexinit.kexinit()));
                Ok(true)
            },
            Some(ServerState::KexDh(mut kexdh)) => {


                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }

                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    let kex = {
                        let payload = self.get_current_payload();
                        println!("payload = {:?}", payload);
                        assert!(payload[0] == msg::KEX_ECDH_INIT);
                        kexdh.exchange.client_ephemeral = Some((&payload[5..]).to_vec());
                        try!(kexdh.kex.dh(&mut kexdh.exchange, payload))
                    };
                    self.recv_seqn += 1;
                    self.read_buffer.clear();
                    self.read_len = 0;
                    self.state = Some(
                        ServerState::KexDhDone(KexDhDone {
                            exchange:kexdh.exchange,
                            kex:kex,
                            key:kexdh.key,
                            cipher:kexdh.cipher, mac:kexdh.mac, follows:kexdh.follows,
                            session_id: kexdh.session_id
                        }));

                    Ok(true)

                } else {
                    // not enough bytes.
                    self.state = Some(ServerState::KexDh(kexdh));
                    Ok(false)
                }
            },
            Some(ServerState::NewKeys(newkeys)) => {

                // We are waiting for the NEWKEYS packet. Is it this one?
                if self.read_len == 0 {
                    try!(self.set_clear_len(stream));
                }
                if try!(read(stream, &mut self.read_buffer, self.read_len)) {

                    let payload_is_newkeys = self.get_current_payload()[0] == msg::NEWKEYS;
                    if payload_is_newkeys {
                        // Ok, NEWKEYS received, now encrypted.
                        self.state = Some(ServerState::Encrypted(newkeys.encrypted()));
                        self.recv_seqn += 1;
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
                debug!("read: encrypted {:?}", enc.state);

                let mut read_packet = false;

                if let Some(buf) = try!(enc.cipher.read_client_packet(self.recv_seqn, stream,
                                                                      &mut self.read_len,
                                                                      &mut self.read_buffer)) {
                    

                    let state = std::mem::replace(&mut enc.state, None);
                    match state {
                        Some(EncryptedState::WaitingServiceRequest) if buf[0] == msg::SERVICE_REQUEST => {

                            let len = BigEndian::read_u32(&buf[1..]) as usize;
                            let request = &buf[5..(5+len)];
                            debug!("request: {:?}", std::str::from_utf8(request));
                            if request == b"ssh-userauth" {
                                enc.state = Some(EncryptedState::ServiceRequest)
                            } else {
                                enc.state = Some(EncryptedState::WaitingServiceRequest)
                            }
                            read_packet = true;
                            debug!("decrypted {:?}", buf);
                        },
                        Some(EncryptedState::WaitingAuthRequest(auth_request)) => {
                            if buf[0] == msg::USERAUTH_REQUEST {

                                enc.state = Some(auth_request.auth_request(config, buf));
                                read_packet = true;

                            } else {
                                // Wrong request
                                enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                                read_packet = true;
                            }
                        },

                        Some(EncryptedState::WaitingSignature(auth_request)) => {
                            debug!("receiving signature, {:?}", buf);
                            if buf[0] == msg::USERAUTH_REQUEST {

                                enc.state = Some(auth_request.waiting_signature(
                                    buf,
                                    enc.session_id.as_bytes(),
                                    buffer
                                ));
                                read_packet = true

                            } else {
                                enc.state = Some(EncryptedState::RejectAuthRequest(auth_request));
                            }
                        },
                        Some(EncryptedState::WaitingChannelOpen) if buf[0] == msg::CHANNEL_OPEN => {
                            debug!("auth! received packet: {:?}", buf);

                            let typ_len = BigEndian::read_u32(&buf[1 ..]) as usize;
                            let typ = &buf[5 .. 5+typ_len];
                            let sender = BigEndian::read_u32(&buf[5+typ_len ..]);
                            let window = BigEndian::read_u32(&buf[9+typ_len ..]);
                            let maxpacket = BigEndian::read_u32(&buf[13+typ_len ..]);


                            debug!("typ = {:?} {:?} {:?} {:?}",
                                     std::str::from_utf8(typ), sender, window, maxpacket);

                            let mut sender_channel:u32 = 1;
                            while enc.channels.contains_key(&sender_channel) || sender_channel == 0 {
                                sender_channel = rand::thread_rng().gen()
                            }
                            
                            enc.state = Some(EncryptedState::ChannelOpenConfirmation (ChannelParameters {

                                recipient_channel: sender,
                                sender_channel: sender_channel,
                                initial_window_size: window,
                                maximum_packet_size: maxpacket
                            }));
                            
                            read_packet = true;
                        },
                        Some(EncryptedState::ChannelOpened(mut channels)) => {
                            if buf[0] == msg::CHANNEL_DATA {
                                debug!("buf: {:?}", buf);

                                let channel_num = BigEndian::read_u32(&buf[1..]);
                                if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {

                                    let len = BigEndian::read_u32(&buf[5..]) as usize;
                                    let data = &buf[9 .. 9+len];
                                    buffer.clear();
                                    if let Ok(()) = channel.server.data(&data, &mut channel.stdout, &mut channel.stderr) {
                                        if channel.stdout.len() > 0 || channel.stderr.len() > 0 {
                                            channels.insert(channel_num);
                                        }
                                    } else {
                                        unimplemented!()
                                    }
                                }
                            }
                            enc.state = Some(EncryptedState::ChannelOpened(channels));
                            read_packet = true;
                        },
                        state => {
                            debug!("buf: {:?}", buf);
                            debug!("replacing state: {:?}", state);
                            enc.state = state;
                            read_packet = true;
                        }
                    }

                } else {
                    // More bytes needed
                    // println!("more bytes needed");
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
                // println!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    fn write_all<W:Write>(&mut self, stream:&mut W) -> Result<bool, Error> {
        // println!("write_all");
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
        // println!("flushed");
        Ok(true)
    }


    // Returns whether the connexion is still alive.

    pub fn write<W:Write, A:Authenticate>(
        &mut self,
        config:&config::Config<A>,
        server:&T,
        stream:&mut W,
        buffer:&mut CryptoBuf,
        buffer2:&mut CryptoBuf
    ) -> Result<bool, Error> {

        // println!("writing");
        // Finish pending writes, if any.
        if ! try!(self.write_all(stream)) {
            // If there are still bytes to write.
            return Ok(true)
        }
        self.write_buffer.clear();
        self.write_position = 0;

        let state = std::mem::replace(&mut self.state, None);

        match state {
            Some(ServerState::VersionOk(mut exchange)) => {

                self.write_buffer.extend(config.server_id.as_bytes());
                self.write_buffer.push(b'\r');
                self.write_buffer.push(b'\n');
                try!(self.write_all(stream));

                exchange.server_id = Some(config.server_id.as_bytes().to_vec());

                self.state = Some(
                    ServerState::KexInit(kex::KexInit {
                        exchange:exchange,
                        algo:None, sent:false,
                        session_id: None
                    }
                ));
                Ok(true)
            },
            Some(ServerState::KexInit(kexinit)) => {

                self.state = Some(try!(self.cleartext_write_kex_init(&config.keys, kexinit, stream)));
                Ok(true)
            },
            Some(ServerState::KexDhDone(kexdhdone)) => {
                
                let hash = try!(kexdhdone.kex.compute_exchange_hash(&kexdhdone.key, &kexdhdone.exchange, buffer));
                try!(self.cleartext_kex_ecdh_reply(&kexdhdone, &hash));
                self.cleartext_send_newkeys();
                try!(self.write_all(stream));

                self.state = Some(ServerState::NewKeys(kexdhdone.compute_keys(hash, buffer, buffer2)));
                Ok(true)
            },
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?}", enc.state);
                let state = std::mem::replace(&mut enc.state, None);
                match state {

                    Some(EncryptedState::ServiceRequest) => {
                        let auth_request = self.accept_service(config.auth_banner, config.methods, &mut enc, buffer);
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        try!(self.write_all(stream));
                    },

                    Some(EncryptedState::RejectAuthRequest(auth_request)) => {

                        self.reject_auth_request(&mut enc, buffer, &auth_request);
                        enc.state = Some(EncryptedState::WaitingAuthRequest(auth_request));
                        try!(self.write_all(stream));
                    },

                    Some(EncryptedState::WaitingSignature(mut auth_request)) => {

                        self.send_pk_ok(&mut enc, buffer, &mut auth_request);
                        enc.state = Some(EncryptedState::WaitingSignature(auth_request));
                        try!(self.write_all(stream));
                    },

                    Some(EncryptedState::AuthRequestSuccess) => {
                        buffer.clear();
                        buffer.push(msg::USERAUTH_SUCCESS);
                        enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);
                        self.sent_seqn += 1;
                        enc.state = Some(EncryptedState::WaitingChannelOpen);
                        try!(self.write_all(stream));
                    },

                    Some(EncryptedState::ChannelOpenConfirmation(channel)) => {

                        let server = S::init(server, &channel);
                        self.confirm_channel_open(&mut enc, buffer, channel, server);
                        enc.state = Some(EncryptedState::ChannelOpened(HashSet::new()));
                        try!(self.write_all(stream));
                    },
                    Some(EncryptedState::ChannelOpened(mut channels)) => {

                        self.flush_channels(&mut enc, &mut channels, buffer);
                        try!(self.write_all(stream));
                        enc.state = Some(EncryptedState::ChannelOpened(channels))
                    },
                    state => {
                        enc.state = state
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(true)
            },
            session => {
                // println!("write: unhandled {:?}", session);
                self.state = session;
                Ok(true)
            }
        }
    }

    fn cleartext_write_kex_init<W:Write>(&mut self, keys:&[key::Algorithm],
                                         mut kexinit:kex::KexInit, stream:&mut W) -> Result<ServerState<S>, Error> {
        if !kexinit.sent {
            // println!("kexinit");
            self.write_buffer.extend(b"\0\0\0\0\0");
            write_kex(&keys, &mut self.write_buffer);

            kexinit.exchange.server_kex_init = {

                let buf = self.write_buffer.as_slice();
                Some((&buf [5..]).to_vec())

            };

            complete_packet(&mut self.write_buffer, 0);
            self.sent_seqn += 1;
            try!(self.write_all(stream));
            kexinit.sent = true;
        }
        if let Some((kex,key,cipher,mac,follows)) = kexinit.algo {
            Ok(ServerState::KexDh(KexDh {
                exchange:kexinit.exchange,
                kex:kex, key:key, cipher:cipher, mac:mac, follows:follows,
                session_id: kexinit.session_id
            }))
        } else {
            Ok(ServerState::KexInit(kexinit))
        }

    }
    fn cleartext_kex_ecdh_reply(&mut self, kexdhdone:&KexDhDone, hash:&kex::Digest) -> Result<(),Error> {
        if let Some(ref server_ephemeral) = kexdhdone.exchange.server_ephemeral {
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
            self.sent_seqn += 1;
            Ok(())
        } else {
            Err(Error::DH)
        }
    }
    fn cleartext_send_newkeys(&mut self) {
        // Sending the NEWKEYS packet.
        // https://tools.ietf.org/html/rfc4253#section-7.3
        // buffer.clear();
        let pos = self.write_buffer.len();
        self.write_buffer.extend(b"\0\0\0\0\0");
        self.write_buffer.push(msg::NEWKEYS);
        complete_packet(&mut self.write_buffer, pos);
        self.sent_seqn += 1;
    }

    fn accept_service(&mut self, banner:Option<&str>, methods:auth::Methods,
                      enc:&mut Encrypted<S>, buffer:&mut CryptoBuf) -> AuthRequest {
        buffer.clear();
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
        enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);
        self.sent_seqn += 1;

        if let Some(ref banner) = banner {

            buffer.clear();
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");

            enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);
            self.sent_seqn += 1;
        }

        AuthRequest {
            methods: methods,
            partial_success: false, // not used immediately anway.
            public_key: CryptoBuf::new(),
            public_key_algorithm: CryptoBuf::new(),
            sent_pk_ok: false
        }
    }

    fn reject_auth_request(&mut self, enc:&mut Encrypted<S>, buffer:&mut CryptoBuf, auth_request:&AuthRequest) {
        buffer.clear();
        buffer.push(msg::USERAUTH_FAILURE);

        buffer.extend_list(auth_request.methods);
        buffer.push(if auth_request.partial_success { 1 } else { 0 });

        enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);

        self.sent_seqn += 1;
    }

    fn confirm_channel_open(&mut self, enc:&mut Encrypted<S>, buffer:&mut CryptoBuf, channel:ChannelParameters, server:S) {
        buffer.clear();
        buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
        buffer.push_u32_be(channel.recipient_channel);
        buffer.push_u32_be(channel.sender_channel);
        buffer.push_u32_be(channel.initial_window_size);
        buffer.push_u32_be(channel.maximum_packet_size);
        enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);

        self.sent_seqn += 1;
        let buf_stdout = CryptoBuf::new();
        let buf_stderr = CryptoBuf::new();
        enc.channels.insert(channel.sender_channel,
                            Channel {
                                parameters: channel,
                                stdout: buf_stdout,
                                stderr: buf_stderr,
                                server: server
                            });
    }

    fn send_pk_ok(&mut self, enc:&mut Encrypted<S>, buffer:&mut CryptoBuf, auth_request:&mut AuthRequest) {
        if !auth_request.sent_pk_ok {
            buffer.clear();
            buffer.push(msg::USERAUTH_PK_OK);
            buffer.extend_ssh_string(auth_request.public_key_algorithm.as_slice());
            buffer.extend_ssh_string(auth_request.public_key.as_slice());
            enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);
            self.sent_seqn += 1;
            auth_request.sent_pk_ok = true;
        }
    }

    fn flush_channels(&mut self, enc:&mut Encrypted<S>, channel_nums:&mut HashSet<u32>, buffer:&mut CryptoBuf) {

        for recip_channel in channel_nums.drain() {
            
            if let Some(ref mut channel) = enc.channels.get_mut(&recip_channel) {

                if channel.stdout.len() > 0 {
                    buffer.clear();
                    buffer.push(msg::CHANNEL_DATA);
                    buffer.push_u32_be(channel.parameters.recipient_channel);
                    buffer.extend_ssh_string(channel.stdout.as_slice());
                    channel.stdout.clear();

                    enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);

                    self.sent_seqn += 1;
                }
                if channel.stderr.len() > 0 {
                    buffer.clear();
                    buffer.push(msg::CHANNEL_EXTENDED_DATA);
                    buffer.push_u32_be(channel.parameters.recipient_channel);
                    buffer.push_u32_be(SSH_EXTENDED_DATA_STDERR);
                    buffer.extend_ssh_string(channel.stderr.as_slice());
                    channel.stderr.clear();

                    enc.cipher.write_server_packet(self.sent_seqn, buffer.as_slice(), &mut self.write_buffer);

                    self.sent_seqn += 1;
                }
            }
        }

    }

}
const SSH_EXTENDED_DATA_STDERR: u32 = 1;
