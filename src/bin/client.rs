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
use futures::Future;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

fn run<H: Handler + 'static>(config: Arc<Config>, addr: &str, handler: H) {

    let addr = addr.to_socket_addrs().unwrap().next().unwrap();
    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let done =
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
            connection.authenticate().and_then(|connection| {

                connection.channel_open_session().and_then(|(mut connection, chan)| {

                    try!(connection.data(chan, None, b"AAAAAA"));
                    try!(connection.data(chan, None, b"BBBBBBBBBB"));
                    connection.flush().and_then(|mut connection| {

                        try!(connection.data(chan, None, b"CCCCCCCCCCCCCCCC"));
                        connection.flush().and_then(|mut connection| connection.wait()).wait()

                    }).wait()
                })
            })
        });
    l.run(done).unwrap();
}

struct H { }

impl Handler for H {
    type FutureBool = futures::Finished<bool, Error>;
    type FutureUnit = futures::Finished<(), Error>;
    fn check_server_key(&mut self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        debug!("check_server_key: {:?}", server_public_key);
        futures::finished(true)
    }
    fn data(&mut self, channel: ChannelId, ext: Option<u32>, data: &[u8], session: &mut Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        futures::finished(())
    }
}

fn main() {
    env_logger::init().unwrap();
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = H {};
    run(config, "127.0.0.1:2222", sh);
}
