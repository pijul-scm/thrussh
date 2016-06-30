use std::io::{Write, BufRead};
use time;
use std;

use super::*;
pub use super::auth::*;
use super::msg;
use super::cipher::CipherT;

#[derive(Debug)]
pub struct Config<Auth> {
    pub server_id: String,
    pub methods: auth::Methods,
    pub auth_banner: Option<&'static str>,
    pub keys: Vec<key::Algorithm>,
    pub auth: Auth,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64,
    pub window_size: u32,
    pub maximum_packet_size: u32
}

impl<A> Config<A> {
    pub fn default(a:A, keys:Vec<key::Algorithm>) -> Config<A> {
        Config {
            // Must begin with "SSH-2.0-".
            server_id: "SSH-2.0-SSH.rs_0.1".to_string(),
            methods: auth::Methods::all(),
            auth_banner: Some("SSH Authentication\r\n"), // CRLF separated lines.
            keys: keys.to_vec(),
            auth: a,
            window_size: 100,
            maximum_packet_size: 100,
            // Following the recommendations of https://tools.ietf.org/html/rfc4253#section-9
            rekey_write_limit: 1<<30, // 1 Gb
            rekey_read_limit: 1<<30, // 1Gb
            rekey_time_limit_s: 3600.0,
        }
    }
}

pub struct ServerSession {
    buffers: super::SSHBuffers,
    state: Option<ServerState>,
}

mod read;
mod write;

impl ServerSession {
    pub fn new() -> Self {
        super::SODIUM_INIT.call_once(|| {
            super::sodium::init();
        });
        ServerSession {
            buffers: super::SSHBuffers::new(),
            state: None,
        }
    }

    // returns whether a complete packet has been read.
    pub fn read<R: BufRead, A: auth::Authenticate,S:Server>(
        &mut self,
        server:&mut S,
        config: &Config<A>,
        stream: &mut R,
        buffer: &mut CryptoBuf,
        buffer2: &mut CryptoBuf)
        -> Result<ReturnCode, Error> {

        let state = std::mem::replace(&mut self.state, None);
        println!("state: {:?}", state);
        match state {
            None => {
                let mut exchange;
                {
                    let client_id = try!(self.buffers.read.read_ssh_id(stream));
                    if let Some(client_id) = client_id {
                        exchange = Exchange::new();
                        exchange.client_id.extend(client_id);
                        debug!("client id, exchange = {:?}", exchange);
                    } else {
                        return Ok(ReturnCode::WrongPacket)
                    }
                }
                // Preparing the response
                self.buffers.write.send_ssh_id(config.server_id.as_bytes());
                exchange.server_id.extend(config.server_id.as_bytes());
                self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                })));
                Ok(ReturnCode::Ok)
            },

            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {
                    {
                        let payload = self.buffers.get_current_payload();
                        transport!(payload);
                        if kexinit.algo.is_none() {
                            // read algo from packet.
                            kexinit.algo = Some(try!(super::negociation::read_kex(payload, &config.keys)));
                            kexinit.exchange.client_kex_init.extend(payload);
                        }
                    }
                    self.state = Some(self.buffers.cleartext_write_kex_init(&config.keys, true, kexinit));
                    Ok(ReturnCode::Ok)
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            },

            Some(ServerState::Kex(Kex::KexDh(kexdh))) => {
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {
                    self.server_read_cleartext_kexdh(kexdh, buffer, buffer2)
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexDh(kexdh)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            },

            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => {
                try!(self.buffers.set_clear_len(stream));
                if try!(self.buffers.read(stream)) {
                    self.server_read_cleartext_newkeys(newkeys)
                } else {
                    self.state = Some(ServerState::Kex(Kex::NewKeys(newkeys)));
                    Ok(ReturnCode::NotEnoughBytes)
                }
            },
            
            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?} {:?}", enc.state, enc.rekey);
                let (ret_code, rekeying_done) =
                    if let Some(buf) = try!(enc.cipher.read(stream, &mut self.buffers.read)) {
                        debug!("read buf {:?}", buf);

                        transport!(buf); // return in case of a transport layer packet.
                        
                        let rek = try!(enc.server_read_rekey(buf, &config.keys, buffer, buffer2, &mut self.buffers.write));
                        if rek && enc.rekey.is_none() && buf[0] == msg::NEWKEYS {
                            // rekeying is finished.
                            (ReturnCode::Ok, true)
                        } else {
                            debug!("calling read_encrypted");
                            try!(enc.server_read_encrypted(config, server, buf, buffer, &mut self.buffers.write));
                            (ReturnCode::Ok, false)
                        }
                    } else {
                        (ReturnCode::NotEnoughBytes, false)
                    };
                
                match ret_code {
                    ReturnCode::Ok => {
                        if rekeying_done {
                            self.buffers.read.bytes = 0;
                            self.buffers.write.bytes = 0;
                            self.buffers.last_rekey_s = time::precise_time_s();
                        }
                        if enc.rekey.is_none() &&
                            (self.buffers.read.bytes >= config.rekey_read_limit
                             || self.buffers.write.bytes >= config.rekey_write_limit
                             || time::precise_time_s() >= self.buffers.last_rekey_s + config.rekey_time_limit_s) {

                                if let Some(exchange) = std::mem::replace(&mut enc.exchange, None) {
                                    
                                    let mut kexinit = KexInit {
                                        exchange: exchange,
                                        algo: None,
                                        sent: true,
                                        session_id: Some(enc.session_id.clone()),
                                    };
                                    kexinit.exchange.client_kex_init.clear();
                                    kexinit.exchange.server_kex_init.clear();
                                    kexinit.exchange.client_ephemeral.clear();
                                    kexinit.exchange.server_ephemeral.clear();

                                    debug!("sending kexinit");
                                    enc.write_kexinit(&config.keys, &mut kexinit, buffer, &mut self.buffers.write);
                                    enc.rekey = Some(Kex::KexInit(kexinit))
                                }
                            }
                        self.buffers.read.buffer.clear();
                        self.buffers.read.len = 0;
                    },
                    _ => {
                        debug!("not read buf, {:?}", self.buffers.read);
                    }
                }
                self.state = Some(ServerState::Encrypted(enc));
                Ok(ret_code)
            }
            _ => {
                debug!("read: unhandled");
                Err(Error::Inconsistent)
            }
        }
    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(
        &mut self,
        stream: &mut W)
        -> Result<(), Error> {

        // Finish pending writes, if any.
        try!(self.buffers.write_all(stream));
        Ok(())
    }
}
