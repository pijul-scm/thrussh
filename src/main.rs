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
use std::path::Path;
use std::fs::File;

use ssh::*;


struct Server { list:TcpListener,
                server_pubkey:Option<Vec<u8>>,
                sessions:HashMap<usize, (BufStream<TcpStream>, std::net::SocketAddr, Vec<u8>, Session)> }

const SERVER: Token = Token(0);
impl Handler for Server {
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

                    let buf = Vec::new();
                    self.sessions.insert(id, (BufStream::new(socket), addr, buf,
                                              Session::new(self.server_pubkey.as_ref())));
                }
            },
            Token(id) => {
                println!("registered {:?}, events={:?}", id, events);
                if events.is_error() || events.is_hup() {

                    match self.sessions.entry(id) {
                        Entry::Occupied(e) => {
                            let (stream,_,_,_) = e.remove();
                            event_loop.deregister(stream.get_ref()).unwrap();
                        },
                        _ => {}
                    };

                } else {
                    if events.is_readable() {
                        println!("readable");
                        let session = match self.sessions.entry(id) {
                            Entry::Occupied(e) => e.remove(),
                            _ => unreachable!()
                        };
                        let (mut stream, addr, mut buf, session) = session;
                        if let Ok(next_session) = session.read(&mut stream, &mut buf) {
                            self.sessions.insert(id, (stream, addr, buf, next_session));
                        } else {
                            event_loop.deregister(stream.get_ref()).unwrap();                            
                        }
                    }
                    if events.is_writable() {
                        println!("writable");
                        let session = match self.sessions.entry(id) {
                            Entry::Occupied(e) => Some(e.remove()),
                            _ => None
                        };
                        if let Some((mut stream, addr, mut buf, session)) = session {
                            if let Ok(next_session) = session.write(&mut stream, &mut buf) {
                                self.sessions.insert(id, (stream, addr, buf, next_session));
                            } else {
                                event_loop.deregister(stream.get_ref()).unwrap();
                            }
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
        server_pubkey: Some(ssh::key::read_key("ssh_host_ed25519_key.pub").unwrap()),
        sessions:HashMap::new()
    };
    event_loop.run(&mut server).unwrap();
}
