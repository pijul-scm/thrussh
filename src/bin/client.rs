extern crate futures;
extern crate env_logger;
extern crate tokio_core;
extern crate thrussh;
#[macro_use]
extern crate log;
use thrussh::*;
use thrussh::client::*;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use futures::stream::Stream;
use futures::{Future, Poll, Async};
use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor::{Core, Timeout, Handle};
use std::io::Write;

fn run<H: Handler + 'static>(config: Arc<Config>, addr: &str, handler: H) {

    let addr = addr.to_socket_addrs().unwrap().next().unwrap();
    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let done:futures::future::AndThen<_,Connection<TcpStream, H>,_> =
        TcpStream::connect(&addr, &handle).map_err(|err| thrussh::Error::IO(err)).and_then(|socket| {

            println!("connected");
            let mut connection = Connection::new(
                config.clone(),
                socket,
                handler,
                None
            );

            connection.set_auth_user("pe");
            connection.set_auth_public_key(thrussh::load_secret_key("/home/pe/.ssh/id_ed25519").unwrap());
            debug!("connection");
            connection
        });
    l.run(done).unwrap();
}


struct H { }

impl Handler for H {
    fn check_server_key(&mut self, server_public_key: &key::PublicKey) -> Result<bool, Error> {
        Ok(true)
    }
}

fn main() {
    env_logger::init().unwrap();
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = None; // Some(std::time::Duration::from_secs(600));

    let config = Arc::new(config);
    let sh = H {};
    run(config, "127.0.0.1:22", sh);
}
