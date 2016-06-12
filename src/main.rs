extern crate mio;
extern crate russht;
use mio::*;
use mio::tcp::{TcpListener, TcpStream};
//extern crate bufstream;
//use bufstream::BufStream;
extern crate rand;
use rand::{Rng};
#[macro_use]
extern crate log;
extern crate env_logger;


use std::io::{ Read, Write, BufReader, BufRead };
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use russht::*;
struct Auth;

impl auth::Authenticate for Auth {
    fn auth<'a>(&self, methods:auth::Methods, method:&auth::Method) -> auth::AuthResult {
        println!("methods {:?}, method {:?}", methods, method);
        match method {
            &auth::Method::Pubkey { user, algo, ref pubkey, is_probe } if is_probe && user == "pe" && algo == "ssh-ed25519" => {

                let pe_pubkey = key::PublicKey::Ed25519(
                    sodium::ed25519::PublicKey::copy_from_slice(
                        &[182, 160, 56, 145, 96, 193, 163, 13, 132, 21, 144, 32, 216, 167,
                          40, 229, 230, 169, 46, 6, 135, 147, 96, 198, 10, 226, 95, 7, 78, 160, 131, 73])
                );

                if *pubkey == pe_pubkey {
                    return auth::AuthResult::PublicKey
                }
            },
            &auth::Method::Password { user, password } if user == "pe" && password == "blabla" => {
                return auth::AuthResult::Success
            }
            _ => {}
        }
        auth::AuthResult::Reject {
            remaining_methods: methods - method,
            partial_success: false
        }

    }
}

struct Server<'a> { list:TcpListener,
                    server_config: &'a config::Config,
                    auth:&'a Auth,
                    auth_banner:Option<&'a str>,
                    methods:auth::Methods,
                    buffer0:CryptoBuf,
                    buffer1:CryptoBuf,
                    sessions:HashMap<usize, (BufReader<TcpStream>, std::net::SocketAddr, ServerSession<'a, Auth>)> }

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

                    self.sessions.insert(id, (BufReader::new(socket), addr,
                                              ServerSession::new(
                                                  &self.server_config.server_id,
                                                  &self.server_config.keys,
                                                  self.auth_banner,
                                                  self.methods,
                                                  &self.auth,
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

                                // Read as many packet as are
                                // available in the buffer.  One issue
                                // is, session.read reads at most one
                                // packet, returning true if it read
                                // one, and false if there were not
                                // enough bytes.
                                let mut result = Ok(true);
                                {
                                    let &mut (ref mut stream, _, ref mut session) = e.get_mut();
                                    while result.is_ok() && stream.fill_buf().is_ok() {
                                        let r = session.read(stream, &mut self.buffer0);
                                        if let Ok(t) = r {
                                            if !t {
                                                //not enough bytes
                                                break
                                            }
                                        } else {
                                            result = r
                                        }
                                    };
                                }
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
                                    session.write(stream.get_mut(), &mut self.buffer0, &mut self.buffer1)
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

    let auth = Auth;
    let config = config::Config {
        // Must begin with "SSH-2.0-".
        server_id: "SSH-2.0-SSH.rs_0.1".to_string(),
        keys:vec!(
            key::Algorithm::Ed25519 {
                public_host_key: config::read_public_key("ssh_host_ed25519_key.pub").unwrap(),
                secret_host_key: config::read_secret_key("ssh_host_ed25519_key").unwrap(),
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
        auth: &auth,
        methods: auth::Methods::all(),
        auth_banner: Some("You're about to authenticate\r\n"), // CRLF separated lines.
        server_config: &config,
        buffer0: CryptoBuf::new(),
        buffer1: CryptoBuf::new(),
        sessions:HashMap::new()
    };
    event_loop.run(&mut server).unwrap();
}
