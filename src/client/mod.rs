use super::{CryptoBuf, Exchange, Error};
use super::key;
use std::io::{Write,BufRead};
use std;

#[derive(Debug)]
pub struct Config {
    pub client_id: String,
    pub keys: Vec<key::Algorithm>,
    pub rekey_write_limit: usize,
    pub rekey_read_limit: usize,
    pub rekey_time_limit_s: f64
}

#[derive(Debug)]
pub struct ClientSession {
    buffers: super::SSHBuffers,
    state: Option<ClientState>
}

#[derive(Debug)]
pub enum ClientState {
    Init
}


impl ClientSession {
    pub fn new() -> Self {
        ClientSession {
            buffers: super::SSHBuffers::new(),
            state: None

        }
    }
    // returns whether a complete packet has been read.
    pub fn read<R: BufRead>(&mut self,
                            config: &Config,
                            stream: &mut R,
                            buffer: &mut CryptoBuf)
                            -> Result<bool, Error> {
        unimplemented!()
    }

    // Returns whether the connexion is still alive.
    pub fn write<W: Write>(&mut self,
                           config: &Config,
                           stream: &mut W,
                           buffer: &mut CryptoBuf,
                           buffer2: &mut CryptoBuf)
                           -> Result<bool, Error> {

        let state = std::mem::replace(&mut self.state, None);
        match state {
            None => {

                self.buffers.write_buffer.extend(config.client_id.as_bytes());
                self.buffers.write_buffer.push(b'\r');
                self.buffers.write_buffer.push(b'\n');
                try!(self.buffers.write_all(stream));
                /*
                exchange.server_id.extend(config.server_id.as_bytes());

                self.state = Some(ServerState::Kex(Kex::KexInit(KexInit {
                    exchange: exchange,
                    algo: None,
                    sent: false,
                    session_id: None,
                })));
                 */
                Ok(true)
            },
            _ => unimplemented!()
        }
        
    }
}
