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

impl Authenticate for Auth {
    fn auth<'a>(&self, methods:auth::Methods, method:&auth::Method) -> auth::Auth {
        debug!("methods {:?}, method {:?}", methods, method);
        match method {
            &auth::Method::Pubkey { user, algo, ref pubkey } if user == "pe" && algo == "ssh-ed25519" => {

                let pe_pubkey = key::PublicKey::Ed25519(
                    sodium::ed25519::PublicKey::copy_from_slice(
                        &[182, 160, 56, 145, 96, 193, 163, 13, 132, 21, 144, 32, 216, 167,
                          40, 229, 230, 169, 46, 6, 135, 147, 96, 198, 10, 226, 95, 7, 78, 160, 131, 73])
                );

                if *pubkey == pe_pubkey {
                    return auth::Auth::Success
                }
            },
            &auth::Method::Password { user, password } if user == "pe" && password == "blabla" => {
                return auth::Auth::Success
            }
            _ => {}
        }
        auth::Auth::Reject {
            remaining_methods: methods - method,
            partial_success: false
        }
    }
}

#[derive(Clone)]
struct S<'a> {
    channel: u32,
    counter: &'a std::sync::atomic::AtomicUsize
}

impl<'a> Serve for S<'a> {
    fn init(&self, c:&Channel) -> S<'a> {
        let mut s = self.clone();
        s.channel = c.recipient_channel;
        s
    }
    fn data(&mut self, data:&[u8], reply_stdout:&mut CryptoBuf, reply_stderr:&mut CryptoBuf) -> Result<(),Error> {
        println!("data: {:?}", std::str::from_utf8(data));
        let c = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        write!(reply_stdout, "blabla blibli\r\n").unwrap();
        write!(reply_stderr, "{:?}\r\n", c).unwrap();
        Ok(())
    }
}


struct Server<A,S:Serve> {
    list:TcpListener,
    server_config: config::Config<A>,
    server: S,
    buffer0:CryptoBuf,
    buffer1:CryptoBuf,
    sessions:HashMap<usize, (BufReader<TcpStream>, std::net::SocketAddr, ServerSession<S>)>
}

const SERVER: Token = Token(0);
impl<A:Authenticate,S:Serve> Handler for Server<A, S> {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Server<A,S>>, token: Token, events: EventSet) {
        match token {
            SERVER => {
                debug!("server token");
                let socket = self.list.accept().unwrap();
                if let Some((socket, addr)) = socket {
                    debug!("socket!");
                    let mut id = 0;
                    while self.sessions.contains_key(&id) || id == 0 {
                        id = rand::thread_rng().gen()
                    }
                   
                    event_loop.register(&socket, Token(id), EventSet::all(), PollOpt::edge()).unwrap();

                    self.sessions.insert(id, (BufReader::new(socket), addr,
                                              ServerSession::new()));
                }
            },
            Token(id) => {
                debug!("registered {:?}, events={:?}", id, events);
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
                        debug!("readable");
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
                                        let r = session.read(&self.server_config, stream, &mut self.buffer0);
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
                        debug!("writable");
                        match self.sessions.entry(id) {
                            Entry::Occupied(mut e) => {

                                let result = {
                                    let &mut (ref mut stream, _, ref mut session) = e.get_mut();
                                    session.write(&self.server_config, &self.server, stream.get_mut(), &mut self.buffer0, &mut self.buffer1)
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

    let initial = std::sync::atomic::AtomicUsize::new(0);

    let config = config::Config {
        // Must begin with "SSH-2.0-".
        server_id: "SSH-2.0-SSH.rs_0.1".to_string(),
        methods: auth::Methods::all(),
        auth_banner: Some("You're about to authenticate\r\n"), // CRLF separated lines.
        keys:vec!(
            key::Algorithm::Ed25519 {
                public_host_key: config::read_public_key("ssh_host_ed25519_key.pub").unwrap(),
                secret_host_key: config::read_secret_key("ssh_host_ed25519_key").unwrap(),
            }
        ),
        auth: Auth
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
    let mut server = Server::<Auth, S> {
        list: server,
        server: S {
            channel:0,
            counter: &initial
        },
        server_config: config,
        buffer0: CryptoBuf::new(),
        buffer1: CryptoBuf::new(),
        sessions:HashMap::new()
    };
    event_loop.run(&mut server).unwrap();
}
