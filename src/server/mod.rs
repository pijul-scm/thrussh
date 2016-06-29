use std::io::{Write, BufRead};
use time;
use std;

use super::*;
pub use super::auth::*;
use super::msg;

#[derive(Debug)]
pub struct Config<Auth> {
    pub server_id: String,
    pub methods: auth::Methods,
    pub auth_banner: Option<&'static str>,
    pub keys: Vec<key::Algorithm>,
    pub auth: Auth,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64
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
            // Following the recommendations of https://tools.ietf.org/html/rfc4253#section-9
            rekey_write_limit: 1<<30, // 1 Gb
            rekey_read_limit: 1<<30, // 1Gb
            rekey_time_limit_s: 3600.0
        }
    }
}

pub struct ServerSession {
    buffers: super::SSHBuffers,
    state: Option<ServerState>,
}


const SSH_EXTENDED_DATA_STDERR: u32 = 1;

pub struct SignalName<'a> {
    name:&'a str
}
pub const SIGABRT:SignalName<'static> = SignalName { name:"ABRT" };
pub const SIGALRM:SignalName<'static> = SignalName { name:"ALRM" };
pub const SIGFPE:SignalName<'static> = SignalName { name:"FPE" };
pub const SIGHUP:SignalName<'static> = SignalName { name:"HUP" };
pub const SIGILL:SignalName<'static> = SignalName { name:"ILL" };
pub const SIGINT:SignalName<'static> = SignalName { name:"INT" };
pub const SIGKILL:SignalName<'static> = SignalName { name:"KILL" };
pub const SIGPIPE:SignalName<'static> = SignalName { name:"PIPE" };
pub const SIGQUIT:SignalName<'static> = SignalName { name:"QUIT" };
pub const SIGSEGV:SignalName<'static> = SignalName { name:"SEGV" };
pub const SIGTERM:SignalName<'static> = SignalName { name:"TERM" };
pub const SIGUSR1:SignalName<'static> = SignalName { name:"USR1" };

impl<'a> SignalName<'a> {
    pub fn other(name:&'a str) -> SignalName<'a> {
        SignalName { name:name }
    }
}

impl<'a> ChannelBuf<'a> {
    pub fn stdout(&mut self, stdout:&[u8]) {
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_DATA);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.extend_ssh_string(stdout);

        self.cipher.write_server_packet(self.write_buffer.seqn,
                                        self.buffer.as_slice(),
                                        &mut self.write_buffer.buffer);
                        
        self.write_buffer.seqn += 1;
    }
    pub fn stderr(&mut self, stderr:&[u8]) {
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_EXTENDED_DATA);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.push_u32_be(SSH_EXTENDED_DATA_STDERR);
        self.buffer.extend_ssh_string(stderr);
        self.cipher.write_server_packet(self.write_buffer.seqn,
                                        self.buffer.as_slice(),
                                        &mut self.write_buffer.buffer);
                        
        self.write_buffer.seqn += 1;
    }

    fn reply(&mut self, msg:u8) {
        self.buffer.clear();
        self.buffer.push(msg);
        self.buffer.push_u32_be(self.recipient_channel);
        println!("reply {:?}", self.buffer.as_slice());
        self.cipher.write_server_packet(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }
    pub fn success(&mut self) {
        if self.wants_reply {
            self.reply(msg::CHANNEL_SUCCESS);
            self.wants_reply = false
        }
    }
    pub fn failure(&mut self) {
        if self.wants_reply {
            self.reply(msg::CHANNEL_FAILURE);
            self.wants_reply = false
        }
    }
    pub fn eof(&mut self) {
        self.reply(msg::CHANNEL_EOF);
    }
    pub fn close(mut self) {
        self.reply(msg::CHANNEL_CLOSE);
    }
    
    pub fn exit_status(&mut self, exit_status: u32) {
        // https://tools.ietf.org/html/rfc4254#section-6.10
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_REQUEST);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.extend_ssh_string(b"exit-status");
        self.buffer.push(0);
        self.buffer.push_u32_be(exit_status);
        self.cipher.write_server_packet(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }

    pub fn exit_signal(&mut self, signal_name:SignalName, core_dumped: bool, error_message:&str, language_tag: &str) {
        // https://tools.ietf.org/html/rfc4254#section-6.10
        // Windows compatibility: we can't use Unix signal names here.
        self.buffer.clear();
        self.buffer.push(msg::CHANNEL_REQUEST);
        self.buffer.push_u32_be(self.recipient_channel);
        self.buffer.extend_ssh_string(b"exit-signal");
        self.buffer.push(0);

        self.buffer.extend_ssh_string(signal_name.name.as_bytes());
        self.buffer.push(if core_dumped { 1 } else { 0 });
        self.buffer.extend_ssh_string(error_message.as_bytes());
        self.buffer.extend_ssh_string(language_tag.as_bytes());

        self.cipher.write_server_packet(self.write_buffer.seqn, self.buffer.as_slice(), &mut self.write_buffer.buffer);
        self.write_buffer.seqn+=1
    }
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
        -> Result<bool, Error> {

        let state = std::mem::replace(&mut self.state, None);
        // println!("state: {:?}", state);
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
                        return Ok(false)
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
                Ok(true)
            },

            Some(ServerState::Kex(Kex::KexInit(mut kexinit))) => {
                let result = try!(self.server_read_cleartext_kexinit(stream, &mut kexinit, &config.keys));
                if result {
                    self.state = Some(self.buffers.cleartext_write_kex_init(&config.keys,
                                                                            true, // is_server
                                                                            kexinit));
                } else {
                    self.state = Some(ServerState::Kex(Kex::KexInit(kexinit)))
                }
                Ok(result)
            },

            Some(ServerState::Kex(Kex::KexDh(kexdh))) => self.server_read_cleartext_kexdh(stream, kexdh, buffer, buffer2),

            Some(ServerState::Kex(Kex::NewKeys(newkeys))) => self.server_read_cleartext_newkeys(stream, newkeys),

            Some(ServerState::Encrypted(mut enc)) => {
                debug!("read: encrypted {:?} {:?}", enc.state, enc.rekey);
                let (buf_is_some, rekeying_done) =
                    if let Some(buf) = try!(enc.cipher.read_client_packet(stream, &mut self.buffers.read)) {

                        let rek = try!(enc.server_read_rekey(buf, &config.keys, buffer, buffer2, &mut self.buffers.write));
                        if rek && enc.rekey.is_none() && buf[0] == msg::NEWKEYS {
                            // rekeying is finished.
                            (true, true)
                        } else {
                            debug!("calling read_encrypted");
                            try!(enc.server_read_encrypted(config, server, buf, buffer, &mut self.buffers.write));
                            (true, false)
                        }
                    } else {
                        (false, false)
                    };

                if buf_is_some {
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
                    self.buffers.read.seqn += 1;
                    self.buffers.read.buffer.clear();
                    self.buffers.read.len = 0;
                }

                self.state = Some(ServerState::Encrypted(enc));
                Ok(buf_is_some)
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
