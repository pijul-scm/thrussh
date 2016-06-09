extern crate mio;
extern crate ssh;
use mio::*;
use mio::tcp::{TcpListener, TcpStream};
extern crate bufstream;
use bufstream::BufStream;
extern crate rand;
use rand::{Rng};
#[macro_use]
extern crate log;
extern crate env_logger;


use std::io::{ Read, Write };
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use ssh::*;

struct Server<'a> { list:TcpListener,
                    server_config: &'a config::Config,
                    buffer0:Vec<u8>,
                    buffer1:Vec<u8>,
                    sessions:HashMap<usize, (BufStream<TcpStream>, std::net::SocketAddr, ssh::ServerSession<'a>)> }

const SERVER: Token = Token(0);
impl<'a> Handler for Server<'a> {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Server>, token: Token, events: EventSet) {
        match token {
            SERVER => {
                println!("server token");
                let socket = self.list.accept().unwrap();
                if let Some((socket, addr)) = socket {
                    println!("socket!");
                    let mut id = 0;
                    while self.sessions.contains_key(&id) || id == 0 {
                        id = rand::thread_rng().gen()
                    }
                   
                    event_loop.register(&socket, Token(id), EventSet::all(), PollOpt::edge()).unwrap();

                    self.sessions.insert(id, (BufStream::new(socket), addr,
                                              ServerSession::new(
                                                  &self.server_config.server_id,
                                                  &self.server_config.keys,
                                              )));
                }
            },
            Token(id) => {
                println!("registered {:?}, events={:?}", id, events);
                if events.is_error() || events.is_hup() {

                    match self.sessions.entry(id) {
                        Entry::Occupied(e) => {
                            let (stream,_,_) = e.remove();
                            event_loop.deregister(stream.get_ref()).unwrap();
                        },
                        _ => {}
                    };

                } else {
                    if events.is_readable() {
                        println!("readable");
                        match self.sessions.entry(id) {
                            Entry::Occupied(mut e) => {

                                let result = {
                                    let &mut (ref mut stream, _, ref mut session) = e.get_mut();
                                    session.read(stream, &mut self.buffer0)
                                };
                                if result.is_err() {
                                    let (stream,_,_) = e.remove();
                                    event_loop.deregister(stream.get_ref()).unwrap();                            
                                }
                            },
                            _ => unreachable!()
                        };
                    }
                    if events.is_writable() {
                        println!("writable");
                        match self.sessions.entry(id) {
                            Entry::Occupied(mut e) => {

                                let result = {
                                    let &mut (ref mut stream, _, ref mut session) = e.get_mut();
                                    session.write(stream, &mut self.buffer0, &mut self.buffer1)
                                };
                                if result.is_err() {
                                    let (stream,_,_) = e.remove();
                                    event_loop.deregister(stream.get_ref()).unwrap();                            
                                }

                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

fn main () {
    // Setup some tokens to allow us to identify which event is
    // for which socket.
    env_logger::init().unwrap();

    let config = ssh::config::Config {
        // Must begin with "SSH-2.0-".
        server_id: "SSH-2.0-SSH.rs_0.1".to_string(),
        keys:vec!(
            key::Algorithm::Ed25519 {
                public_host_key: ssh::config::read_public_key("ssh_host_ed25519_key.pub").unwrap(),
                secret_host_key: ssh::config::read_secret_key("ssh_host_ed25519_key").unwrap(),
            }
        )
    };
    let addr = "127.0.0.1:13265".parse().unwrap();

    // Setup the server socket
    let server = TcpListener::bind(&addr).unwrap();

    // Create an event loop
    let mut event_loop = EventLoop::new().unwrap();

    // Start listening for incoming connections
    event_loop.register(&server, SERVER, EventSet::readable(), PollOpt::edge()).unwrap();

    /*const CLIENT: Token = Token(1);
    // Setup the client socket
    let sock = TcpStream::connect(&addr).unwrap();

    // Register the socket
    event_loop.register(&sock, CLIENT, EventSet::readable(),
    PollOpt::edge()).unwrap();
     */

    // Define a handler to process the events


    // Start handling events;
    let mut server = Server {
        list: server,
        server_config: &config,
        buffer0: Vec::new(),
        buffer1: Vec::new(),
        sessions:HashMap::new()
    };
    event_loop.run(&mut server).unwrap();
}
